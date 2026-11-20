# passthrough-kubelet-credential-provider

## Goal

Implement a minimal Kubernetes kubelet credential provider that passes a Pod's ServiceAccount JWT directly to a container registry as Basic authentication credentials.

The primary use case is authenticating image pulls from Kubehub's Zot registry using Kubernetes ServiceAccount tokens, without static image pull secrets or long-lived registry passwords.

## 1. Architecture

A standalone Go executable implementing the Kubernetes Credential Provider API.

**No:**

- Kubernetes client-go or API access.
- HTTP server or network calls.
- Database, cache, or persistent state.
- Token exchange or JWT validation.
- External dependencies beyond the Go standard library.

**Runtime flow:**

1. Kubelet identifies an image matching the configured registry pattern.
2. Kubelet requests a short-lived ServiceAccount token for the Pod.
3. Kubelet executes `passthrough-kubelet-credential-provider`.
4. The provider reads the request from stdin.
5. The provider returns the ServiceAccount JWT as the registry password.
6. Kubelet passes the credentials to the container runtime.
7. The registry (Zot) validates the JWT and authorizes the image pull.

The provider never communicates with the registry.

## 2. Input

Read one JSON `CredentialProviderRequest` from stdin.

API version: [`credentialprovider.kubelet.k8s.io/v1`](http://credentialprovider.kubelet.k8s.io/v1)

Relevant fields:

- `apiVersion`
- `kind`
- `image`
- `serviceAccountToken`

The provider must reject requests with a missing or empty ServiceAccount token.

Do not decode, modify, or validate the JWT.

## 3. Output

Write one JSON `CredentialProviderResponse` to stdout.

Example:

```
{
  "apiVersion": "credentialprovider.kubelet.k8s.io/v1",
  "kind": "CredentialProviderResponse",
  "cacheKeyType": "Image",
  "cacheDuration": "0s",
  "auth": {
    "zot.local.kubehub.io": {
      "username": "zot",
      "password": "<original-service-account-jwt>"
    }
  }
}
```

Requirements:

- Preserve the original request API version.
- Return the original JWT unchanged as `password`.
- Use `zot` as the username.
- Return `cacheKeyType: Image`.
- Return `cacheDuration: 0s`.
- Return credentials only for the registry in the requested image.
- Do not include credentials for unrelated registries.

The registry hostname must be extracted from the image reference. Do not assume every image uses the same hostname.

For the initial implementation, support ordinary fully qualified registry image references such as:

```
zot.local.kubehub.io/team/app:v1
zot.local.kubehub.io/team/app@sha256:...
```

Reject malformed or unsupported image references rather than returning credentials for an unintended registry.

## 4. Kubelet configuration

The provider binary is installed in:

```
/opt/kubelet-credential-providers/passthrough-kubelet-credential-provider
```

Kubelet configuration:

`/etc/kubernetes/credential-provider.yaml`

```
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

Kubelet startup flags:

```
--image-credential-provider-config=/etc/kubernetes/credential-provider.yaml
--image-credential-provider-bin-dir=/opt/kubelet-credential-providers
```

The provider binary name must match the configured provider name.

The `KubeletServiceAccountTokenForCredentialProviders` feature gate must be enabled. It is enabled by default in Kubernetes 1.34 and later.

Target compatibility: Kubernetes 1.35+.

## 5. Error handling and security

- Write diagnostic errors exclusively to stderr.
- Never write logs or diagnostics to stdout.
- Never log or expose the ServiceAccount JWT.
- Never persist tokens to disk.
- Never make network requests.
- Exit non-zero on invalid input or missing credentials.
- Do not return credentials for images outside the intended registry configuration.

## 6. Tests

Implement unit tests for:

1. Valid image reference and valid JWT.
2. JWT is returned unchanged.
3. Correct username and response API version.
4. Correct cache settings.
5. Missing ServiceAccount token.
6. Malformed JSON input.
7. Missing or malformed image reference.
8. Registry hostname extraction.
9. Image belonging to an unrelated registry.

Include an integration test using a sample CredentialProviderRequest JSON piped through the compiled executable.

## 7. Deliverables

- `main.go`
- `main_test.go`
- `go.mod`
- [`README.md`](http://README.md)

README must document:

- What the provider does.
- Build instructions.
- Installation path.
- Kubelet configuration.
- A sample request and response.

## 8. Explicit non-goals

Do not implement:

- JWT verification.
- Kubernetes API integration.
- Token refresh.
- Token exchange.
- HTTP endpoints.
- Registry-specific logic beyond Basic credential formatting.
- Configuration management or a daemon.

Keep the implementation small, dependency-free, and easy to embed in Kubehub node provisioning.

**Acceptance criterion:** A Pod using a Kubernetes ServiceAccount can pull an image from an appropriately configured Zot registry without an imagePullSecret or static registry credentials.