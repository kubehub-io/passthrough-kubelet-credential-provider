# passthrough-kubelet-credential-provider

A minimal Kubernetes kubelet credential provider that passes a Pod's
ServiceAccount JWT directly to a container registry as Basic authentication
credentials.

It is intended for clusters that authenticate image pulls from a
container registry with short-lived Kubernetes ServiceAccount tokens, 
instead of static image pull secrets or long-lived registry passwords.

You do need to config your container registry to trust kubernetes service account Token.

This is tested with [Zot](https://zotregistry.dev/)

## How it works

Kubelet have a [feature that resolve image pull credential from credential provider](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/),
it invokes this binary for images that match the provider configuration.
The provider:

1. Reads one `CredentialProviderRequest` from stdin.
2. Extracts the registry hostname from the requested image reference.
3. Returns a `CredentialProviderResponse` on stdout containing the
   ServiceAccount token as the password, with username `zot`.

The provider does not talk to the registry, call the Kubernetes API, verify or
validate the JWT, exchange tokens, or keep any state. The registry validates
the JWT and authorizes the pull. For debug logging only, the provider decodes
the JWT payload to record workload identity; the token itself is never logged.

The response uses `cacheKeyType: Image` and `cacheDuration: 0s`, so kubelet
asks for fresh credentials for every image pull. This avoids reusing a
short-lived ServiceAccount token after it expires.

## Requirements

- Go 1.24 or later to build.
- Kubernetes 1.35 or later.
- The `KubeletServiceAccountTokenForCredentialProviders` feature gate enabled
  (enabled by default in Kubernetes 1.34 and later).

The provider has no third-party dependencies and uses only the Go standard
library.

## Build

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
  -o passthrough-kubelet-credential-provider .
```

## Install

The binary name must match the provider `name` in the kubelet configuration.
Install it into kubelet's credential provider binary directory:

```sh
sudo install -D -m 0755 passthrough-kubelet-credential-provider \
  /opt/kubelet-credential-providers/passthrough-kubelet-credential-provider
```

## Kubelet configuration

Create `/etc/kubernetes/credential-provider.yaml`:

```yaml
apiVersion: kubelet.config.k8s.io/v1
kind: CredentialProviderConfig

providers:
  - name: passthrough-kubelet-credential-provider
    matchImages:
      - "zot.local.kubehub.io"
    defaultCacheDuration: "0s"
    apiVersion: credentialprovider.kubelet.k8s.io/v1
    tokenAttributes:
      serviceAccountTokenAudience: "zot"
      cacheType: Token
      requireServiceAccount: true
```

Add these flags to the kubelet:

```text
--image-credential-provider-config=/etc/kubernetes/credential-provider.yaml
--image-credential-provider-bin-dir=/opt/kubelet-credential-providers
```

`matchImages` decides which images are sent to this provider. Narrow patterns
are strongly recommended so that the provider is only invoked for the registry
whose token audience matches the configuration. The example above matches only
`zot.local.kubehub.io`.

## Request and response

Kubelet sends a request similar to the following on stdin:

```json
{
  "apiVersion": "credentialprovider.kubelet.k8s.io/v1",
  "kind": "CredentialProviderRequest",
  "image": "zot.local.kubehub.io/team/app:v1",
  "serviceAccountToken": "<short-lived-service-account-jwt>"
}
```

The provider writes one response to stdout:

```json
{
  "apiVersion": "credentialprovider.kubelet.k8s.io/v1",
  "kind": "CredentialProviderResponse",
  "cacheKeyType": "Image",
  "cacheDuration": "0s",
  "auth": {
    "zot.local.kubehub.io": {
      "username": "zot",
      "password": "<short-lived-service-account-jwt>"
    }
  }
}
```

The token is returned unchanged. The `auth` map is keyed by the registry
hostname extracted from the request image, so the credential is scoped to that
registry only.

## Supported image references

The provider supports ordinary, fully qualified image references with an
explicit registry hostname:

```text
zot.local.kubehub.io/team/app:v1
zot.local.kubehub.io/team/app@sha256:...
zot.local.kubehub.io:5000/team/app:v1
localhost:5000/team/app:v1
```

Malformed references, URL-style references, and Docker Hub shorthand such as
`nginx:latest` or `library/nginx` are rejected. The latter is important:
Docker Hub shorthand implies the registry `docker.io`, and returning
credentials for it would send the ServiceAccount token to an unintended
registry.

The provider exits non-zero and writes a diagnostic to stderr for invalid
input, unsupported image references, or a missing ServiceAccount token.

## Debug logging

Every invocation appends timestamped JSON lines (JSON Lines) to:

```text
/opt/kubelet-credential-providers/passthrough-kubelet-credential-provider.log
```

The provider creates the file on first write, using mode `0600`. If the file
cannot be created or written, a diagnostic is written to stderr. Each line has
an RFC3339Nano `time` field and the same `id` for one invocation:

```json
{"time":"2026-11-19T12:34:56.789012345Z","event":"invoke","id":"4c1f0c2a1d7f4c8e9b3a6d5e2f8a7b1c"}
{"time":"2026-11-19T12:34:56.789123456Z","event":"request","id":"4c1f0c2a1d7f4c8e9b3a6d5e2f8a7b1c","request":{"image":"zot.local.kubehub.io/team/app:v1","namespace":"team","pod":"app-7f9c","serviceAccount":"app","node":"worker-1"}}
{"time":"2026-11-19T12:34:56.790234567Z","event":"response","id":"4c1f0c2a1d7f4c8e9b3a6d5e2f8a7b1c","response":{"apiVersion":"credentialprovider.kubelet.k8s.io/v1","kind":"CredentialProviderResponse","cacheKeyType":"Image","cacheDuration":"0s","auth":{"zot.local.kubehub.io":{"username":"zot","password":"<redacted>"}}}}
```

An `invoke` line is written before stdin is read, so it proves the provider was
called even when the input is empty or malformed. A `request` line is written
after JSON decoding but before validation, so requests rejected for a missing
token or an unsupported image are logged too. A `response` line is written
after a successful response is sent to stdout; rejected requests produce no
response line.

Request logging decodes the JWT payload without verifying its signature to
extract the namespace, Pod, ServiceAccount, and node names. If the token cannot
be decoded, the request entry includes a `tokenDecodeError` field. The token is
never written to the log, and every password in the response is replaced with
`<redacted>`.

To disable debug logging, build the production binary with an empty debug path:

```sh
CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w -X main.debugFile=" \
  -o passthrough-kubelet-credential-provider .
```

**The debug log does not contain the ServiceAccount token, and response
passwords are redacted.** It does contain decoded workload identity and image
information. Keep the file readable only by root and delete it when debugging
is finished.

## Security properties

- Diagnostics go only to stderr; stdout contains only the response document.
- The ServiceAccount token is never written to the debug log; response
  passwords are replaced with `<redacted>`. Debug logging can still be disabled
  with `-X main.debugFile=` for production builds.
- No network requests are made.
- No credentials are returned for images without an explicit registry
  hostname.

## Test

```sh
go test ./...
```

`TestExecutableIntegration` compiles the binary and pipes a sample request
through it, exercising the same stdin/stdout path kubelet uses. Skip that test
with:

```sh
go test -short ./...
```

## Non-goals

This project deliberately does not implement JWT verification, Kubernetes API
integration, token refresh or exchange, HTTP endpoints, registry-specific
behavior beyond Basic credential formatting, or long-running daemon
configuration.
