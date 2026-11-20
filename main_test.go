package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testImage = "zot.local.kubehub.io/team/app:v1"

	// A ServiceAccount JWT with the same claims Kubernetes puts in a
	// short-lived Pod token. The signature is not verified by the provider.
	testJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0." +
		"eyJhdWQiOlsiem90Il0sImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbCIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoidGVhbSIsIm5vZGUiOnsibmFtZSI6Indvcmtlci0xIiwidWlkIjoibm9kZS11aWQifSwicG9kIjp7Im5hbWUiOiJhcHAtN2Y5YyIsInVpZCI6InBvZC11aWQifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImFwcCIsInVpZCI6InNhLXVpZCJ9fSwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnRlYW06YXBwIn0." +
		"c2lnbmF0dXJl"

	testNamespace      = "team"
	testPod            = "app-7f9c"
	testServiceAccount = "app"
	testNode           = "worker-1"

	testDigest = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func requestJSON(t *testing.T, image, token string) string {
	t.Helper()
	data, err := json.Marshal(map[string]string{
		"apiVersion":          apiVersionV1,
		"kind":                requestKind,
		"image":               image,
		"serviceAccountToken": token,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return string(data)
}

func runProvider(t *testing.T, input string) (code int, stdout, stderr string) {
	t.Helper()
	return runProviderWithDebug(t, input, filepath.Join(t.TempDir(), "debug.log"))
}

func runProviderWithDebug(t *testing.T, input, debugPath string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runWithDebug(strings.NewReader(input), &out, &errOut, debugPath)
	return code, out.String(), errOut.String()
}

func decodeResponse(t *testing.T, stdout string) credentialProviderResponse {
	t.Helper()
	var resp credentialProviderResponse
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("decode response %q: %v", stdout, err)
	}
	return resp
}

// Test 1: a valid image reference and a valid JWT produce a successful
// response.
func TestRunValidRequest(t *testing.T) {
	code, stdout, stderr := runProvider(t, requestJSON(t, testImage, testJWT))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	resp := decodeResponse(t, stdout)
	if resp.Kind != responseKind {
		t.Errorf("kind = %q, want %q", resp.Kind, responseKind)
	}
	if len(resp.Auth) != 1 {
		t.Fatalf("auth entries = %d, want 1: %#v", len(resp.Auth), resp.Auth)
	}
	creds, ok := resp.Auth["zot.local.kubehub.io"]
	if !ok {
		t.Fatalf("auth has no entry for zot.local.kubehub.io: %#v", resp.Auth)
	}
	if creds.Password != testJWT {
		t.Errorf("password = %q, want the request token", creds.Password)
	}
}

// Test 2: the JWT is returned byte-for-byte unchanged.
func TestRunReturnsTokenUnchanged(t *testing.T) {
	token := "header.with-dashes_and_underscores.and=padding=="
	code, stdout, stderr := runProvider(t, requestJSON(t, testImage, token))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}

	resp := decodeResponse(t, stdout)
	if got := resp.Auth["zot.local.kubehub.io"].Password; got != token {
		t.Errorf("password = %q, want %q", got, token)
	}
}

// Test 3: username and response API version follow the API contract.
func TestRunUsernameAndAPIVersion(t *testing.T) {
	code, stdout, stderr := runProvider(t, requestJSON(t, testImage, testJWT))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}

	resp := decodeResponse(t, stdout)
	if resp.APIVersion != apiVersionV1 {
		t.Errorf("apiVersion = %q, want %q", resp.APIVersion, apiVersionV1)
	}
	if got := resp.Auth["zot.local.kubehub.io"].Username; got != "zot" {
		t.Errorf("username = %q, want %q", got, "zot")
	}
}

// Test 4: cache settings disable caching and key the response by image.
func TestRunCacheSettings(t *testing.T) {
	code, stdout, stderr := runProvider(t, requestJSON(t, testImage, testJWT))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}

	resp := decodeResponse(t, stdout)
	if resp.CacheKeyType != "Image" {
		t.Errorf("cacheKeyType = %q, want %q", resp.CacheKeyType, "Image")
	}
	if resp.CacheDuration != "0s" {
		t.Errorf("cacheDuration = %q, want %q", resp.CacheDuration, "0s")
	}
}

// Test 5: a missing or blank ServiceAccount token is rejected.
func TestRunMissingServiceAccountToken(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "empty token",
			input: requestJSON(t, testImage, ""),
		},
		{
			name:  "whitespace token",
			input: requestJSON(t, testImage, " \t\n"),
		},
		{
			name: "absent token field",
			input: `{"apiVersion":"` + apiVersionV1 + `","kind":"` + requestKind +
				`","image":"` + testImage + `"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runProvider(t, tt.input)
			if code == 0 {
				t.Fatalf("exit code = 0, want non-zero")
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if !strings.Contains(stderr, "serviceAccountToken") {
				t.Errorf("stderr = %q, want a serviceAccountToken diagnostic", stderr)
			}
		})
	}
}

// Test 6: malformed JSON input is rejected.
func TestRunMalformedJSON(t *testing.T) {
	valid := requestJSON(t, testImage, testJWT)

	tests := []struct {
		name  string
		input string
	}{
		{name: "empty input", input: ""},
		{name: "whitespace only", input: " \n\t "},
		{name: "truncated object", input: valid[:len(valid)/2]},
		{name: "not an object", input: `["not","an","object"]`},
		{name: "null", input: `null`},
		{name: "syntax error", input: `{not json}`},
		{name: "multiple values", input: valid + valid},
		{name: "trailing garbage", input: valid + " trailing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runProvider(t, tt.input)
			if code == 0 {
				t.Fatalf("exit code = 0, want non-zero")
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if stderr == "" {
				t.Error("stderr is empty, want diagnostic")
			}
		})
	}
}

// Test 7: missing or malformed image references are rejected instead of
// producing credentials for an unintended registry.
func TestRunInvalidImageReferences(t *testing.T) {
	tests := []struct {
		name  string
		image string
	}{
		{name: "missing image", image: ""},
		{name: "surrounding whitespace", image: " " + testImage},
		{name: "URL scheme", image: "https://zot.local.kubehub.io/team/app:v1"},
		{name: "Docker Hub shorthand tag", image: "nginx:latest"},
		{name: "Docker Hub shorthand digest", image: "nginx@" + testDigest},
		{name: "Docker Hub namespace", image: "library/nginx:latest"},
		{name: "single path component", image: "team/app:v1"},
		{name: "registry without repository", image: "zot.local.kubehub.io"},
		{name: "registry with bare slash", image: "zot.local.kubehub.io/"},
		{name: "empty hostname", image: "/team/app:v1"},
		{name: "empty path component", image: "zot.local.kubehub.io/team//app:v1"},
		{name: "uppercase path", image: "zot.local.kubehub.io/Team/App:v1"},
		{name: "uppercase hostname", image: "ZOT.local.kubehub.io/team/app:v1"},
		{name: "empty tag", image: "zot.local.kubehub.io/team/app:"},
		{name: "invalid tag characters", image: "zot.local.kubehub.io/team/app:bad^tag"},
		{name: "empty digest", image: "zot.local.kubehub.io/team/app@"},
		{name: "invalid digest", image: "zot.local.kubehub.io/team/app@sha256:xyz"},
		{name: "multiple digests", image: "zot.local.kubehub.io/team/app@" + testDigest + "@" + testDigest},
		{name: "userinfo", image: "user@zot.local.kubehub.io/team/app:v1"},
		{name: "empty port", image: "zot.local.kubehub.io:/team/app:v1"},
		{name: "non-numeric port", image: "zot.local.kubehub.io:abc/team/app:v1"},
		{name: "out of range port", image: "zot.local.kubehub.io:99999/team/app:v1"},
		{name: "leading dot in hostname", image: ".example.com/team/app:v1"},
		{name: "trailing dot in hostname", image: "example.com./team/app:v1"},
		{name: "underscore in hostname", image: "zot_local.kubehub.io/team/app:v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runProvider(t, requestJSON(t, tt.image, testJWT))
			if code == 0 {
				t.Fatalf("exit code = 0, want non-zero for image %q", tt.image)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if stderr == "" {
				t.Error("stderr is empty, want diagnostic")
			}
			// Diagnostics must never expose the ServiceAccount token.
			if strings.Contains(stderr, testJWT) {
				t.Error("stderr contains the ServiceAccount token")
			}
		})
	}
}

// Test 8: the registry hostname is extracted from the image reference,
// including ports, tags, digests, and localhost.
func TestRegistryFromImage(t *testing.T) {
	tests := []struct {
		name  string
		image string
		want  string
	}{
		{name: "tag", image: "zot.local.kubehub.io/team/app:v1", want: "zot.local.kubehub.io"},
		{name: "no tag", image: "zot.local.kubehub.io/team/app", want: "zot.local.kubehub.io"},
		{name: "digest", image: "zot.local.kubehub.io/team/app@" + testDigest, want: "zot.local.kubehub.io"},
		{
			name:  "tag and digest",
			image: "zot.local.kubehub.io/team/app:v1@" + testDigest,
			want:  "zot.local.kubehub.io",
		},
		{name: "port", image: "zot.local.kubehub.io:5000/team/app:v1", want: "zot.local.kubehub.io:5000"},
		{name: "localhost", image: "localhost/team/app", want: "localhost"},
		{name: "localhost with port", image: "localhost:5000/team/app:latest", want: "localhost:5000"},
		{name: "single component path", image: "registry.example.com/app:v1", want: "registry.example.com"},
		{name: "nested path", image: "registry.example.com/team/sub/app:v1", want: "registry.example.com"},
		{name: "hyphenated host", image: "my-registry.example.com/app", want: "my-registry.example.com"},
		{name: "dot separated path segments", image: "registry.example.com/team/app.v1", want: "registry.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := registryFromImage(tt.image)
			if err != nil {
				t.Fatalf("registryFromImage(%q) error: %v", tt.image, err)
			}
			if got != tt.want {
				t.Errorf("registryFromImage(%q) = %q, want %q", tt.image, got, tt.want)
			}
		})
	}
}

// Test 9: an image from an unrelated registry receives credentials keyed only
// to that registry, never to the configured Zot hostname.
func TestRunUnrelatedRegistry(t *testing.T) {
	const image = "registry.example.com/team/app:v1"

	code, stdout, stderr := runProvider(t, requestJSON(t, image, testJWT))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}

	resp := decodeResponse(t, stdout)
	if len(resp.Auth) != 1 {
		t.Fatalf("auth entries = %d, want 1: %#v", len(resp.Auth), resp.Auth)
	}
	if _, ok := resp.Auth["registry.example.com"]; !ok {
		t.Errorf("auth is missing registry.example.com: %#v", resp.Auth)
	}
	if _, ok := resp.Auth["zot.local.kubehub.io"]; ok {
		t.Errorf("auth contains credentials for zot.local.kubehub.io: %#v", resp.Auth)
	}
}

// Additional validation: unsupported API versions and kinds are rejected.
func TestRunUnsupportedRequestMetadata(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "wrong apiVersion",
			input: `{"apiVersion":"credentialprovider.kubelet.k8s.io/v1beta1","kind":"` + requestKind + `","image":"` + testImage + `","serviceAccountToken":"` + testJWT + `"}`,
		},
		{
			name:  "missing apiVersion",
			input: `{"kind":"` + requestKind + `","image":"` + testImage + `","serviceAccountToken":"` + testJWT + `"}`,
		},
		{
			name:  "wrong kind",
			input: `{"apiVersion":"` + apiVersionV1 + `","kind":"Pod","image":"` + testImage + `","serviceAccountToken":"` + testJWT + `"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runProvider(t, tt.input)
			if code == 0 {
				t.Fatalf("exit code = 0, want non-zero")
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if stderr == "" {
				t.Error("stderr is empty, want diagnostic")
			}
		})
	}
}

// TestLogDebugAppendsTimestampedJSONLines verifies that invocation, request,
// and response entries each occupy exactly one line, carry the same request
// ID and a timestamp, and never contain the ServiceAccount token.
func TestLogDebugAppendsTimestampedJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.log")
	req := &credentialProviderRequest{
		APIVersion:          apiVersionV1,
		Kind:                requestKind,
		Image:               testImage,
		ServiceAccountToken: testJWT,
	}
	resp := &credentialProviderResponse{
		APIVersion:    apiVersionV1,
		Kind:          responseKind,
		CacheKeyType:  cacheKeyTypeImage,
		CacheDuration: cacheDurationNone,
		Auth: map[string]authConfig{
			"zot.local.kubehub.io": {Username: registryUsername, Password: testJWT},
		},
	}
	const id = "test-request-id"

	var stderr bytes.Buffer
	logDebug(&stderr, path, debugEntry{Event: "invoke", ID: id})
	logDebug(&stderr, path, debugEntry{Event: "request", ID: id, Request: newDebugRequest(req)})
	logDebug(&stderr, path, debugEntry{Event: "response", ID: id, Response: newDebugResponse(resp)})
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read debug file: %v", err)
	}
	if strings.Contains(string(data), testJWT) {
		t.Error("debug log contains the ServiceAccount token")
	}
	if !strings.Contains(string(data), `"password":"`+redactedValue+`"`) {
		t.Error("debug log does not contain the literal redacted password")
	}

	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("debug lines = %d, want 3: %q", len(lines), data)
	}

	entries := make([]debugEntry, len(lines))
	for i, line := range lines {
		if err := json.Unmarshal([]byte(line), &entries[i]); err != nil {
			t.Fatalf("line %d is not JSON: %v (%q)", i, err, line)
		}
		if _, err := time.Parse(time.RFC3339Nano, entries[i].Time); err != nil {
			t.Errorf("line %d timestamp %q is invalid: %v", i, entries[i].Time, err)
		}
		if entries[i].ID != id {
			t.Errorf("line %d id = %q, want %q", i, entries[i].ID, id)
		}
	}

	if entries[0].Event != "invoke" {
		t.Errorf("first event = %q, want %q", entries[0].Event, "invoke")
	}
	if entries[0].Request != nil || entries[0].Response != nil {
		t.Errorf("invocation entry unexpectedly contains data: %+v", entries[0])
	}

	if entries[1].Event != "request" {
		t.Errorf("second event = %q, want %q", entries[1].Event, "request")
	}
	if entries[1].Request == nil {
		t.Fatal("request entry has no request")
	}
	wantRequest := debugRequest{
		Image:          testImage,
		Namespace:      testNamespace,
		Pod:            testPod,
		ServiceAccount: testServiceAccount,
		Node:           testNode,
	}
	if *entries[1].Request != wantRequest {
		t.Errorf("logged request = %+v, want %+v", *entries[1].Request, wantRequest)
	}

	if entries[2].Event != "response" {
		t.Errorf("third event = %q, want %q", entries[2].Event, "response")
	}
	if entries[2].Response == nil {
		t.Fatal("response entry has no response")
	}
	creds, ok := entries[2].Response.Auth["zot.local.kubehub.io"]
	if !ok || creds.Username != registryUsername || creds.Password != redactedValue {
		t.Errorf("logged response = %+v, want redacted credentials", entries[2].Response)
	}
}

// TestLogDebugCreatesPrivateFile verifies that the debug file is created on
// first use and is not readable by group or others.
func TestLogDebugCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.log")

	var stderr bytes.Buffer
	logDebug(&stderr, path, debugEntry{Event: "invoke"})
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("debug file was not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("debug file mode = %04o, want no group/other access", perm)
	}
}

// TestLogDebugMissingDirectoryReportsError verifies that a missing debug
// directory is reported instead of silently dropping logs.
func TestLogDebugMissingDirectoryReportsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "debug.log")

	var stderr bytes.Buffer
	logDebug(&stderr, path, debugEntry{Event: "invoke"})
	if !strings.Contains(stderr.String(), "debug log:") {
		t.Fatalf("stderr = %q, want a debug log diagnostic", stderr.String())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("debug file exists or stat failed unexpectedly: %v", err)
	}
}

// TestRunWritesDebugLogForEveryInvocation verifies the run wiring: every
// invocation writes a timestamp line, and requests are logged even when
// validation later rejects them.
func TestRunWritesDebugLogForEveryInvocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.log")

	valid := requestJSON(t, testImage, testJWT)
	code, _, stderr := runProviderWithDebug(t, valid, path)
	if code != 0 {
		t.Fatalf("valid request exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if stderr != "" {
		t.Errorf("valid request stderr = %q, want empty", stderr)
	}

	missingToken := requestJSON(t, testImage, "")
	code, stdout, stderr := runProviderWithDebug(t, missingToken, path)
	if code == 0 {
		t.Fatal("missing-token request exit code = 0, want non-zero")
	}
	if stdout != "" {
		t.Errorf("missing-token request stdout = %q, want empty", stdout)
	}
	if stderr == "" {
		t.Error("missing-token request stderr is empty, want diagnostic")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read debug file: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	wantEvents := []string{"invoke", "request", "response", "invoke", "request"}
	if len(lines) != len(wantEvents) {
		t.Fatalf("debug lines = %d, want %d: %q", len(lines), len(wantEvents), data)
	}

	entries := make([]debugEntry, len(lines))
	for i, line := range lines {
		if err := json.Unmarshal([]byte(line), &entries[i]); err != nil {
			t.Fatalf("line %d is not JSON: %v (%q)", i, err, line)
		}
		if entries[i].Event != wantEvents[i] {
			t.Errorf("line %d event = %q, want %q", i, entries[i].Event, wantEvents[i])
		}
		if entries[i].ID == "" {
			t.Errorf("line %d has an empty request ID", i)
		}
		if _, err := time.Parse(time.RFC3339Nano, entries[i].Time); err != nil {
			t.Errorf("line %d timestamp %q is invalid: %v", i, entries[i].Time, err)
		}
	}
	if strings.Contains(string(data), testJWT) {
		t.Error("debug log contains the ServiceAccount token")
	}
	for i := 1; i < 3; i++ {
		if entries[i].ID != entries[0].ID {
			t.Errorf("line %d id = %q, want %q", i, entries[i].ID, entries[0].ID)
		}
	}
	for i := 4; i < 5; i++ {
		if entries[i].ID != entries[3].ID {
			t.Errorf("line %d id = %q, want %q", i, entries[i].ID, entries[3].ID)
		}
	}
	if entries[3].ID == entries[0].ID {
		t.Error("separate invocations share a request ID")
	}

	wantRequest := debugRequest{
		Image:          testImage,
		Namespace:      testNamespace,
		Pod:            testPod,
		ServiceAccount: testServiceAccount,
		Node:           testNode,
	}
	if entries[1].Request == nil || *entries[1].Request != wantRequest {
		t.Errorf("first logged request = %+v, want %+v", entries[1].Request, wantRequest)
	}
	if entries[2].Response == nil {
		t.Fatal("valid invocation has no logged response")
	}
	creds, ok := entries[2].Response.Auth["zot.local.kubehub.io"]
	if !ok || creds.Username != registryUsername || creds.Password != redactedValue {
		t.Errorf("logged response = %+v, want redacted credentials", entries[2].Response)
	}
	if entries[4].Request == nil || entries[4].Request.Image != testImage ||
		entries[4].Request.TokenDecodeError == "" {
		t.Errorf("second logged request = %+v, want image %q and a token decode error", entries[4].Request, testImage)
	}
}

// TestRunLogsInvocationForMalformedInput verifies that a timestamp is written
// even when stdin cannot be decoded.
func TestRunLogsInvocationForMalformedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.log")

	code, stdout, stderr := runProviderWithDebug(t, "{not json", path)
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero")
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if stderr == "" {
		t.Error("stderr is empty, want diagnostic")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read debug file: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("debug lines = %d, want 1: %q", len(lines), data)
	}

	var entry debugEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("debug line is not JSON: %v (%q)", err, lines[0])
	}
	if entry.Event != "invoke" {
		t.Errorf("event = %q, want %q", entry.Event, "invoke")
	}
	if _, err := time.Parse(time.RFC3339Nano, entry.Time); err != nil {
		t.Errorf("timestamp %q is invalid: %v", entry.Time, err)
	}
}

// TestDecodeServiceAccountToken verifies extraction of workload identity
// claims and fallback to the ServiceAccount subject.
func TestDecodeServiceAccountToken(t *testing.T) {
	fallback := makeTestToken(t, map[string]any{
		"sub": "system:serviceaccount:other:builder",
	})
	invalidJSON := "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".signature"

	tests := []struct {
		name    string
		token   string
		want    serviceAccountTokenInfo
		wantErr bool
	}{
		{
			name:  "kubernetes claims",
			token: testJWT,
			want: serviceAccountTokenInfo{
				Namespace:      testNamespace,
				Pod:            testPod,
				ServiceAccount: testServiceAccount,
				Node:           testNode,
			},
		},
		{
			name:  "subject fallback",
			token: fallback,
			want: serviceAccountTokenInfo{
				Namespace:      "other",
				ServiceAccount: "builder",
			},
		},
		{name: "not a JWT", token: "header.payload", wantErr: true},
		{name: "invalid base64", token: "header.!!!.signature", wantErr: true},
		{name: "invalid JSON", token: invalidJSON, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeServiceAccountToken(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("decodeServiceAccountToken() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeServiceAccountToken() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("decodeServiceAccountToken() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestNewDebugResponseRedactsPasswords verifies that no response credential
// reaches the debug log.
func TestNewDebugResponseRedactsPasswords(t *testing.T) {
	resp := &credentialProviderResponse{
		APIVersion:    apiVersionV1,
		Kind:          responseKind,
		CacheKeyType:  cacheKeyTypeImage,
		CacheDuration: cacheDurationNone,
		Auth: map[string]authConfig{
			"one.example.com": {Username: "zot", Password: "secret-one"},
			"two.example.com": {Username: "zot", Password: "secret-two"},
		},
	}

	debug := newDebugResponse(resp)
	if len(debug.Auth) != len(resp.Auth) {
		t.Fatalf("debug auth entries = %d, want %d", len(debug.Auth), len(resp.Auth))
	}
	for registry, creds := range debug.Auth {
		if creds.Username != "zot" {
			t.Errorf("%s username = %q, want %q", registry, creds.Username, "zot")
		}
		if creds.Password != redactedValue {
			t.Errorf("%s password = %q, want %q", registry, creds.Password, redactedValue)
		}
	}

	raw, err := json.Marshal(debug)
	if err != nil {
		t.Fatalf("marshal debug response: %v", err)
	}
	if strings.Contains(string(raw), "secret-one") || strings.Contains(string(raw), "secret-two") {
		t.Errorf("debug response contains a password: %s", raw)
	}
}

func makeTestToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

// TestExecutableIntegration pipes a sample CredentialProviderRequest through
// the compiled executable, as kubelet does.
func TestExecutableIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping executable integration test in short mode")
	}

	bin := filepath.Join(t.TempDir(), "passthrough-kubelet-credential-provider")
	debugPath := filepath.Join(t.TempDir(), "debug.log")
	build := exec.Command("go", "build", "-buildvcs=false",
		"-ldflags", "-X=main.debugFile="+debugPath, "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build provider: %v\n%s", err, out)
	}

	t.Run("valid request", func(t *testing.T) {
		req := `{
			"apiVersion": "credentialprovider.kubelet.k8s.io/v1",
			"kind": "CredentialProviderRequest",
			"image": "zot.local.kubehub.io/team/app:v1",
			"serviceAccountToken": "` + testJWT + `"
		}`

		code, stdout, stderr := runExecutable(t, bin, req)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		if stderr != "" {
			t.Errorf("stderr = %q, want empty", stderr)
		}

		resp := decodeResponse(t, stdout)
		if resp.APIVersion != apiVersionV1 {
			t.Errorf("apiVersion = %q, want %q", resp.APIVersion, apiVersionV1)
		}
		if resp.CacheKeyType != "Image" || resp.CacheDuration != "0s" {
			t.Errorf("cache settings = %q/%q, want Image/0s", resp.CacheKeyType, resp.CacheDuration)
		}
		creds, ok := resp.Auth["zot.local.kubehub.io"]
		if !ok {
			t.Fatalf("auth has no entry for zot.local.kubehub.io: %#v", resp.Auth)
		}
		if creds.Username != "zot" || creds.Password != testJWT {
			t.Errorf("credentials = %q/%q, want zot/<request token>", creds.Username, creds.Password)
		}
	})

	t.Run("missing token", func(t *testing.T) {
		req := `{
			"apiVersion": "credentialprovider.kubelet.k8s.io/v1",
			"kind": "CredentialProviderRequest",
			"image": "zot.local.kubehub.io/team/app:v1"
		}`

		code, stdout, stderr := runExecutable(t, bin, req)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty", stdout)
		}
		if !strings.Contains(stderr, "serviceAccountToken") {
			t.Errorf("stderr = %q, want a serviceAccountToken diagnostic", stderr)
		}
	})

	// The compiled executable must have logged both invocations and both
	// requests, plus the successful response, each on its own line.
	data, err := os.ReadFile(debugPath)
	if err != nil {
		t.Fatalf("read debug file: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	wantEvents := []string{"invoke", "request", "response", "invoke", "request"}
	if len(lines) != len(wantEvents) {
		t.Fatalf("debug lines = %d, want %d: %q", len(lines), len(wantEvents), data)
	}
	if strings.Contains(string(data), testJWT) {
		t.Error("debug log contains the ServiceAccount token")
	}
	entries := make([]debugEntry, len(lines))
	for i, line := range lines {
		if err := json.Unmarshal([]byte(line), &entries[i]); err != nil {
			t.Fatalf("line %d is not JSON: %v (%q)", i, err, line)
		}
		if entries[i].Event != wantEvents[i] {
			t.Errorf("line %d event = %q, want %q", i, entries[i].Event, wantEvents[i])
		}
		if entries[i].ID == "" {
			t.Errorf("line %d has an empty request ID", i)
		}
		if _, err := time.Parse(time.RFC3339Nano, entries[i].Time); err != nil {
			t.Errorf("line %d timestamp %q is invalid: %v", i, entries[i].Time, err)
		}
	}
	for i := 1; i < 3; i++ {
		if entries[i].ID != entries[0].ID {
			t.Errorf("line %d id = %q, want %q", i, entries[i].ID, entries[0].ID)
		}
	}
	wantRequest := debugRequest{
		Image:          testImage,
		Namespace:      testNamespace,
		Pod:            testPod,
		ServiceAccount: testServiceAccount,
		Node:           testNode,
	}
	if entries[1].Request == nil || *entries[1].Request != wantRequest {
		t.Errorf("logged request = %+v, want %+v", entries[1].Request, wantRequest)
	}
	if entries[2].Response == nil {
		t.Fatal("successful invocation has no logged response")
	}
	creds, ok := entries[2].Response.Auth["zot.local.kubehub.io"]
	if !ok || creds.Username != registryUsername || creds.Password != redactedValue {
		t.Errorf("logged response = %+v, want redacted credentials", entries[2].Response)
	}
}

func runExecutable(t *testing.T, bin, input string) (code int, stdout, stderr string) {
	t.Helper()

	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(input)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	err := cmd.Run()
	if err == nil {
		return 0, out.String(), errOut.String()
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), out.String(), errOut.String()
	}

	t.Fatalf("run executable: %v", err)
	return 0, "", ""
}
