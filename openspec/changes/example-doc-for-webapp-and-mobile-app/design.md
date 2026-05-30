## Context

This OAuth 2.0 authorization server (`authserver`) supports the Authorization Code Flow with PKCE, token introspection, and standard userinfo endpoint. Developers need to understand how to integrate with it, but there are no reference implementations. The server endpoints are documented implicitly through code, but no end-to-end client examples exist.

## Goals / Non-Goals

**Goals:**
- Provide a runnable web app example using the Authorization Code Flow with PKCE
- Provide a mobile app example (shell-based reference + native integration notes)
- Document the full flow: authorize → token → userinfo → logout
- Cover PKCE parameters, redirect URI registration, and error responses

**Non-Goals:**
- Server-side configuration changes
- Adding new endpoints or modifying existing OAuth behavior
- SDK wrappers or client libraries
- Social login or federation examples

## Decisions

1. **Vanilla JS for web example** — No build tools, no frameworks. Developers can read and adapt the code without understanding React/Vue/Angular. The code runs from a static file server.

2. **Shell script for mobile reference** — Use `curl` commands that demonstrate the exact token exchange steps. Native iOS/Android developers can translate these into HTTP client calls. This avoids committing platform-specific code.

3. **Single `examples/` root directory** — All examples live under `examples/` with subdirectories `web-app/` and `mobile/`. This is standard convention and easy to discover.

4. **README-first approach** — The root `examples/README.md` explains the server endpoints first, then walks through each example. This serves as standalone integration documentation.

## Risks / Trade-offs

| Risk | Mitigation |
|------|-----------|
| Examples drift from server behavior as OAuth endpoints evolve | Add a note in README directing developers to verify against live server; document version assumptions |
| Mobile example is too abstract with just curl scripts | Include detailed comments mapping each curl step to the corresponding native SDK API call |
| PKCE explanation is technical and hard to follow | Add a visual flow diagram (ASCII) in the README showing authorize → code → token → userinfo |

## Migration Plan

This is a documentation-only change. No migration or deployment steps needed. Simply commit and push.

## Open Questions

- Should we include a token refresh example? (Server behavior for refresh tokens not yet documented — will note as "if supported" in examples)
