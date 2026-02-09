# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP Toolbox for Databases is an open-source MCP (Model Context Protocol) server that enables AI agents to interact with databases. It provides connection pooling, authentication, and observability while allowing tools to be defined via YAML configuration.

## Common Commands

```bash
# Run from source (default port 5000)
go run .

# Run with custom config
go run . --tools-file tools.yaml

# Build binary
go build -o toolbox

# Run tests
go test -race -v ./...

# Run single test file/package
go test -race -v ./tests/postgres
go test -race -v ./internal/tools/postgres/postgressql

# Lint (requires golangci-lint)
golangci-lint run --fix

# Download dependencies
go get && go mod tidy
```

## Architecture

### Entry Point
- `main.go` → `cmd/root.go` - CLI entry using Cobra

### Core Components

**Sources** (`internal/sources/`): Database connection implementations
- Each database type has its own package (e.g., `postgres/`, `mysql/`, `mongodb/`)
- Implement `SourceConfig` interface with `SourceConfigKind()` and `Initialize()`
- Implement `Source` interface with `SourceKind()`
- Register via `init()` function using `sources.Register()`

**Tools** (`internal/tools/`): Database operations exposed to AI agents
- Organized by database type (e.g., `postgres/postgressql/`)
- Implement `ToolConfig` interface with `ToolConfigKind()` and `Initialize()`
- Implement `Tool` interface with `Invoke()`, `ParseParams()`, `Manifest()`, `McpManifest()`, `Authorized()`
- Register via `init()` function using `tools.Register()`

**Server** (`internal/server/`): HTTP/MCP server with chi router
- `ResourceManager` holds runtime sources, tools, toolsets, prompts
- Supports both native Toolbox endpoints and MCP protocol

**Auth** (`internal/auth/`): Authentication services
- `google/`: Google ID token validation
- `ping/`: PingID/PingFederate OIDC token validation

**Prompts** (`internal/prompts/`): LLM prompt templates

### Configuration

Tools are defined in `tools.yaml`:
```yaml
sources:
  my-pg-source:
    kind: postgres
    host: 127.0.0.1
    # ...

tools:
  search-hotels:
    kind: postgres-sql
    source: my-pg-source
    description: Search for hotels
    parameters:
      - name: name
        type: string
    statement: SELECT * FROM hotels WHERE name ILIKE $1;

toolsets:
  my_toolset:
    - search-hotels

authServices:
  # Google ID token authentication
  my-google-auth:
    kind: google
    clientId: your-client-id.apps.googleusercontent.com

  # PingID/PingFederate OIDC authentication
  my-ping-auth:
    kind: ping
    issuer: https://idpb2e.adeo.com
    clientId: 0P35e3568bf7a2e1cf27d6ef4c5ca0fdb8
    # jwksUrl: optional, defaults to {issuer}/.well-known/openid-configuration
```

### Auth Service Usage

Tools can require authentication by specifying `authRequired`:
```yaml
tools:
  protected-tool:
    kind: postgres-sql
    source: my-pg-source
    authRequired:
      - my-ping-auth  # Requires valid PingID token
    # ...
```

**Token headers**: Auth services accept tokens via:
- `Authorization: Bearer <token>` (standard OAuth2)
- `{service_name}_token` header (e.g., `my-ping-auth_token`)

### Testing

- Unit tests: `*_test.go` files alongside source
- Integration tests: `tests/` directory, organized by database type
- Integration tests require environment variables (see `.ci/integration.cloudbuild.yaml`)

### Adding New Database Support

1. Create source in `internal/sources/<db>/`
2. Create tool(s) in `internal/tools/<db>/<tool-kind>/`
3. Add integration tests in `tests/<db>/`
4. Follow naming: tool names use underscores (`list_tables`), tool kinds use hyphens (`postgres-sql`)

## Commit Message Format

Uses Conventional Commits: `<type>(<scope>): description`
- Types: `feat`, `fix`, `docs`, `test`, `ci`, `chore`, `refactor`
- Scopes: `sources/<kind>`, `tools/<kind>` (e.g., `feat(sources/postgres): add SSL support`)
