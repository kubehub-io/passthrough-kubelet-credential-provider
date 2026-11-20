// Command passthrough-kubelet-credential-provider implements the Kubernetes
// kubelet credential provider API. It passes a Pod's ServiceAccount token to a
// container registry as the password for a Basic authentication credential.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	apiVersionV1 = "credentialprovider.kubelet.k8s.io/v1"
	requestKind  = "CredentialProviderRequest"
	responseKind = "CredentialProviderResponse"

	// registryUsername is the username presented to the registry. The
	// ServiceAccount token is used as the password.
	registryUsername = "zot"

	cacheKeyTypeImage = "Image"
	cacheDurationNone = "0s"

	// maxRequestBytes bounds how much data is read from stdin. Real requests
	// are a few kilobytes at most.
	maxRequestBytes = 1 << 20
)

var (
	// debugFile receives one timestamped JSON line for every invocation and
	// one for every parsed request. The provider creates the file when its
	// directory exists. The log contains the ServiceAccount token in
	// cleartext, so it must be protected and removed after debugging.
	//
	// This is a variable so it can be redirected in tests or disabled in a
	// production build with: -ldflags "-X main.debugFile="
	debugFile = "/opt/kubelet-credential-providers/passthrough-kubelet-credential-provider.log"

	// These regular expressions follow the distribution image reference
	// grammar (github.com/distribution/reference).
	nameComponentRegexp = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*$`)
	tagRegexp           = regexp.MustCompile(`^[\w][\w.-]{0,127}$`)
	digestRegexp        = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}$`)
	hostnameRegexp      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$`)
)

// credentialProviderRequest is the subset of the kubelet credential provider
// request that this provider needs.
type credentialProviderRequest struct {
	APIVersion          string `json:"apiVersion"`
	Kind                string `json:"kind"`
	Image               string `json:"image"`
	ServiceAccountToken string `json:"serviceAccountToken"`
}

// credentialProviderResponse is the response written to stdout.
type credentialProviderResponse struct {
	APIVersion    string                `json:"apiVersion"`
	Kind          string                `json:"kind"`
	CacheKeyType  string                `json:"cacheKeyType"`
	CacheDuration string                `json:"cacheDuration"`
	Auth          map[string]authConfig `json:"auth"`
}

type authConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// debugEntry is one line in the debug log. Every entry carries a timestamp
// and the same request ID for the invocation; invocation, request, and
// response entries use Event to distinguish themselves. Tokens are never
// logged.
type debugEntry struct {
	Time     string         `json:"time"`
	Event    string         `json:"event,omitempty"`
	ID       string         `json:"id"`
	Request  *debugRequest  `json:"request,omitempty"`
	Response *debugResponse `json:"response,omitempty"`
}

// debugRequest is the redacted, simplified view of a credential provider
// request.
type debugRequest struct {
	Image            string `json:"image"`
	Namespace        string `json:"namespace"`
	Pod              string `json:"pod"`
	ServiceAccount   string `json:"serviceAccount"`
	Node             string `json:"node"`
	TokenDecodeError string `json:"tokenDecodeError,omitempty"`
}

// debugResponse mirrors the credential provider response without the token.
type debugResponse struct {
	APIVersion    string               `json:"apiVersion"`
	Kind          string               `json:"kind"`
	CacheKeyType  string               `json:"cacheKeyType"`
	CacheDuration string               `json:"cacheDuration"`
	Auth          map[string]debugAuth `json:"auth"`
}

type debugAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// redactedValue replaces credentials in the debug log.
const redactedValue = "<redacted>"

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr))
}

// run executes the provider. Diagnostics go to stderr; stdout receives either
// exactly one response document or nothing.
func run(stdin io.Reader, stdout, stderr io.Writer) int {
	return runWithDebug(stdin, stdout, stderr, debugFile)
}

// runWithDebug is run with an explicit debug log path, which makes the debug
// behavior testable without touching the system-wide location.
func runWithDebug(stdin io.Reader, stdout, stderr io.Writer, debugPath string) int {
	id := newRequestID()

	// Log the invocation before reading stdin so the log proves the provider
	// ran even when the request is empty, malformed, or never arrives.
	logDebug(stderr, debugPath, debugEntry{Event: "invoke", ID: id})

	req, err := readRequest(stdin)
	if err != nil {
		fail(stderr, err)
		return 1
	}

	// Log before validation so requests rejected for a missing token or an
	// unsupported image are also visible while debugging.
	logDebug(stderr, debugPath, debugEntry{Event: "request", ID: id, Request: newDebugRequest(req)})

	if err := req.validate(); err != nil {
		fail(stderr, err)
		return 1
	}

	registry, err := registryFromImage(req.Image)
	if err != nil {
		// Unreachable after validate, but keep run defensive.
		fail(stderr, err)
		return 1
	}

	resp := credentialProviderResponse{
		APIVersion:    req.APIVersion,
		Kind:          responseKind,
		CacheKeyType:  cacheKeyTypeImage,
		CacheDuration: cacheDurationNone,
		Auth: map[string]authConfig{
			registry: {
				Username: registryUsername,
				Password: req.ServiceAccountToken,
			},
		},
	}

	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(resp); err != nil {
		fail(stderr, fmt.Errorf("write response: %w", err))
		return 1
	}

	logDebug(stderr, debugPath, debugEntry{Event: "response", ID: id, Response: newDebugResponse(&resp)})

	return 0
}

func fail(stderr io.Writer, err error) {
	fmt.Fprintf(stderr, "passthrough-kubelet-credential-provider: %v\n", err)
}

// logDebug appends one timestamped JSON line to the debug log. It is
// best-effort: failures are reported to stderr but never affect credentials.
func logDebug(stderr io.Writer, path string, entry debugEntry) {
	if path == "" {
		return
	}

	entry.Time = time.Now().UTC().Format(time.RFC3339Nano)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(entry); err != nil {
		fmt.Fprintf(stderr, "passthrough-kubelet-credential-provider: debug log: %v\n", err)
		return
	}

	if err := appendDebugLine(path, buf.Bytes()); err != nil {
		fmt.Fprintf(stderr, "passthrough-kubelet-credential-provider: debug log: %v\n", err)
	}
}

// appendDebugLine creates the debug file if needed and appends one line.
// A single O_APPEND write keeps concurrent invocations from interleaving
// their JSON lines.
func appendDebugLine(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(line)
	return err
}

// newRequestID returns a random identifier shared by all debug lines for one
// invocation.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	}
	return hex.EncodeToString(b[:])
}

// newDebugRequest builds the redacted, simplified request log entry. The
// ServiceAccount token is decoded for workload identity only; it is never
// included in the output.
func newDebugRequest(req *credentialProviderRequest) *debugRequest {
	info, err := decodeServiceAccountToken(req.ServiceAccountToken)

	entry := &debugRequest{
		Image:          req.Image,
		Namespace:      info.Namespace,
		Pod:            info.Pod,
		ServiceAccount: info.ServiceAccount,
		Node:           info.Node,
	}
	if err != nil {
		entry.TokenDecodeError = err.Error()
	}
	return entry
}

// newDebugResponse builds the response log entry with every password
// redacted.
func newDebugResponse(resp *credentialProviderResponse) *debugResponse {
	auth := make(map[string]debugAuth, len(resp.Auth))
	for registry, creds := range resp.Auth {
		auth[registry] = debugAuth{
			Username: creds.Username,
			Password: redactedValue,
		}
	}

	return &debugResponse{
		APIVersion:    resp.APIVersion,
		Kind:          resp.Kind,
		CacheKeyType:  resp.CacheKeyType,
		CacheDuration: resp.CacheDuration,
		Auth:          auth,
	}
}

type serviceAccountTokenInfo struct {
	Namespace      string
	Pod            string
	ServiceAccount string
	Node           string
}

// decodeServiceAccountToken extracts workload identity claims from the JWT
// payload for logging. It deliberately does not verify the signature and
// never returns or logs the token itself.
func decodeServiceAccountToken(token string) (serviceAccountTokenInfo, error) {
	var info serviceAccountTokenInfo

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return info, errors.New("token is not a JWT")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some issuers include base64 padding, so accept that form too.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return info, errors.New("token payload is not valid base64url")
		}
	}

	var claims struct {
		Sub        string `json:"sub"`
		Kubernetes struct {
			Namespace string `json:"namespace"`
			Pod       struct {
				Name string `json:"name"`
			} `json:"pod"`
			ServiceAccount struct {
				Name string `json:"name"`
			} `json:"serviceaccount"`
			Node struct {
				Name string `json:"name"`
			} `json:"node"`
		} `json:"kubernetes.io"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return info, errors.New("token payload is not valid JSON")
	}

	info.Namespace = claims.Kubernetes.Namespace
	info.Pod = claims.Kubernetes.Pod.Name
	info.ServiceAccount = claims.Kubernetes.ServiceAccount.Name
	info.Node = claims.Kubernetes.Node.Name

	// Fall back to the standard ServiceAccount subject, which has the form
	// "system:serviceaccount:<namespace>:<name>".
	if info.Namespace == "" || info.ServiceAccount == "" {
		if ns, sa, ok := parseServiceAccountSubject(claims.Sub); ok {
			if info.Namespace == "" {
				info.Namespace = ns
			}
			if info.ServiceAccount == "" {
				info.ServiceAccount = sa
			}
		}
	}

	return info, nil
}

func parseServiceAccountSubject(sub string) (namespace, serviceAccount string, ok bool) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(sub, prefix) {
		return "", "", false
	}

	parts := strings.SplitN(strings.TrimPrefix(sub, prefix), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// readRequest reads exactly one JSON request from r.
func readRequest(r io.Reader) (*credentialProviderRequest, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxRequestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read request: %w", err)
	}
	if len(data) > maxRequestBytes {
		return nil, fmt.Errorf("request exceeds %d bytes", maxRequestBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("request is empty")
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	var req credentialProviderRequest
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("decode request: %w", err)
	}

	// Reject trailing data so that one invocation cannot contain multiple
	// requests (or other unexpected content).
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("request contains more than one JSON value")
		}
		return nil, fmt.Errorf("decode request: %w", err)
	}

	return &req, nil
}

// validate checks the fields required to build a response. It never inspects
// or decodes the token itself.
func (r *credentialProviderRequest) validate() error {
	if r.APIVersion != apiVersionV1 {
		return fmt.Errorf("unsupported apiVersion %q (want %q)", r.APIVersion, apiVersionV1)
	}
	if r.Kind != requestKind {
		return fmt.Errorf("unsupported kind %q (want %q)", r.Kind, requestKind)
	}
	if strings.TrimSpace(r.ServiceAccountToken) == "" {
		return errors.New("request is missing serviceAccountToken")
	}
	if _, err := registryFromImage(r.Image); err != nil {
		return err
	}
	return nil
}

// registryFromImage extracts the registry hostname from a fully qualified
// image reference such as "zot.local.kubehub.io/team/app:v1" or
// "zot.local.kubehub.io/team/app@sha256:...".
//
// References without an explicit registry hostname are rejected. In
// particular, Docker Hub shorthand such as "nginx:latest" or "library/nginx"
// is not supported: returning credentials for it would send a ServiceAccount
// token to an unintended registry.
func registryFromImage(image string) (string, error) {
	if image == "" {
		return "", errors.New("image reference is empty")
	}
	if image != strings.TrimSpace(image) {
		return "", fmt.Errorf("image reference %q has surrounding whitespace", image)
	}
	if strings.ContainsAny(image, " \t\r\n") {
		return "", fmt.Errorf("image reference %q contains whitespace", image)
	}
	if strings.Contains(image, "://") {
		return "", fmt.Errorf("image reference %q must not include a URL scheme", image)
	}

	name := image

	// Strip an optional digest. A name may carry both a tag and a digest.
	if i := strings.IndexByte(name, '@'); i >= 0 {
		digest := name[i+1:]
		name = name[:i]
		if digest == "" || strings.ContainsRune(digest, '@') || !digestRegexp.MatchString(digest) {
			return "", fmt.Errorf("image reference %q has an invalid digest", image)
		}
	}

	// Strip an optional tag. A colon is only a tag separator if it appears
	// after the last slash; otherwise it belongs to a registry port.
	if lastColon, lastSlash := strings.LastIndexByte(name, ':'), strings.LastIndexByte(name, '/'); lastColon > lastSlash {
		tag := name[lastColon+1:]
		name = name[:lastColon]
		if !tagRegexp.MatchString(tag) {
			return "", fmt.Errorf("image reference %q has an invalid tag", image)
		}
	}

	slash := strings.IndexByte(name, '/')
	if slash < 0 {
		return "", fmt.Errorf("image reference %q does not include an explicit registry hostname", image)
	}

	domain, path := name[:slash], name[slash+1:]

	// Follow the distribution heuristic for deciding whether the first
	// component is a registry: it contains a dot or a colon, or is
	// "localhost". Anything else is Docker Hub shorthand.
	if !strings.Contains(domain, ".") && !strings.Contains(domain, ":") && domain != "localhost" {
		return "", fmt.Errorf("image reference %q does not include an explicit registry hostname", image)
	}

	if err := validateDomain(domain); err != nil {
		return "", fmt.Errorf("image reference %q has an invalid registry hostname: %w", image, err)
	}

	if path == "" {
		return "", fmt.Errorf("image reference %q has no repository path", image)
	}
	for _, component := range strings.Split(path, "/") {
		if !nameComponentRegexp.MatchString(component) {
			return "", fmt.Errorf("image reference %q has an invalid repository path", image)
		}
	}

	return domain, nil
}

// validateDomain validates a registry hostname with an optional port, for
// example "zot.local.kubehub.io", "registry.example.com:5000" or
// "localhost:5000".
func validateDomain(domain string) error {
	host := domain

	if i := strings.LastIndexByte(domain, ':'); i >= 0 {
		host = domain[:i]
		port := domain[i+1:]
		if port == "" {
			return errors.New("empty port")
		}
		for _, c := range port {
			if c < '0' || c > '9' {
				return fmt.Errorf("invalid port %q", port)
			}
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid port %q", port)
		}
	}

	if host == "" {
		return errors.New("empty hostname")
	}
	if host == "localhost" {
		return nil
	}
	if len(host) > 253 {
		return errors.New("hostname is too long")
	}
	if !hostnameRegexp.MatchString(host) {
		return fmt.Errorf("invalid hostname %q", host)
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) > 63 {
			return errors.New("hostname label is too long")
		}
	}

	return nil
}
