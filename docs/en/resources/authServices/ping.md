---
title: "PingID / PingFederate"
type: docs
weight: 2
description: >
  Use PingID or PingFederate OIDC tokens for authorized tool invocations.
---

## Getting Started

PingID and PingFederate issue OIDC ID tokens that Toolbox can validate using the
issuer metadata and JWKS keys. Configure the auth service with your issuer and
client ID. You can optionally provide a `jwksUrl` to skip OIDC discovery.

## Behavior

### Authorized Invocations

Tools are authorized when a valid token is present, the signature verifies with
JWKS, and the `iss` claim matches the configured issuer.

### Authenticated Parameters

Any claim in the verified ID token can be used as an authenticated parameter.

## Example

```yaml
kind: authServices
name: my-ping-auth
type: ping
issuer: https://id.example.com
clientId: ${PING_CLIENT_ID}
# jwksUrl: https://id.example.com/.well-known/jwks.json
```

{{< notice tip >}}
Use environment variable replacement with the format ${ENV_NAME}
instead of hardcoding your secrets into the configuration file.
{{< /notice >}}

## Testing

### Unit Tests

Run the unit tests for the auth service:

```bash
go test -race ./internal/auth/ping
```

### Manual Test (Local Server)

1. Add the auth service to your `tools.yaml` and reference it from a tool that
   uses `authRequired`.

```yaml
kind: authServices
name: my-ping-auth
type: ping
issuer: https://id.example.com
clientId: ${PING_CLIENT_ID}
---
kind: tools
name: secured_tool
type: postgres-sql
source: my-pg-source
statement: SELECT NOW();
authRequired:
  - my-ping-auth
```

2. Start Toolbox with your config:

```bash
go run . --tools-file tools.yaml
```

3. Invoke the tool with a valid ID token. You can use either header format:

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${PING_ID_TOKEN}" \
  -d '{}' \
  http://127.0.0.1:5000/api/tool/secured_tool/invoke
```

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  -H "my-ping-auth_token: ${PING_ID_TOKEN}" \
  -d '{}' \
  http://127.0.0.1:5000/api/tool/secured_tool/invoke
```

4. Negative checks:

- Omit the token header to confirm a 401 response.
- Use a token with the wrong issuer to confirm a 401 response.
- Use an expired token to confirm a 401 response.

## Reference

| **field** | **type** | **required** | **description** |
|-----------|:--------:|:------------:|-----------------|
| type      |  string  |     true     | Must be "ping". |
| issuer    |  string  |     true     | OIDC issuer URL. |
| clientId  |  string  |     true     | Expected client ID claim. |
| jwksUrl   |  string  |     false    | Override JWKS URL. |
