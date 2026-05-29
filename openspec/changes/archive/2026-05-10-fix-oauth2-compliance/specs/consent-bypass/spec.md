# Consent Flow Integrity

## Requirements

### REQ-1: Login MUST NOT bypass the consent page

When a user logs in with `client_id` in the query string, the server MUST NOT automatically call the authorization handler. Instead, the user MUST be redirected to the consent page (`/oauth/authorize`) with all original OAuth parameters preserved.

**Current (wrong):**
```
POST /login?client_id=foo&redirect_uri=...&response_type=code&state=bar
  └─▶ (validates credentials, sets session)
      └─▶ o.Srv.HandleAuthorizeRequest()  // bypasses consent!
```

**Required:**
```
POST /login?client_id=foo&redirect_uri=...&response_type=code&state=bar
  └─▶ (validates credentials, sets session)
      └─▶ 200 OK {"redirect": "/oauth/authorize?client_id=foo&redirect_uri=...&response_type=code&state=bar"}
GET /oauth/authorize?client_id=foo&redirect_uri=...&response_type=code&state=bar
  └─▶ Renders consent page with client info
POST /oauth/authorize (user approves)
  └─▶ o.Srv.HandleAuthorizeRequest()  // now with consent!
```

### REQ-2: Consent page MUST receive all original params

The redirect from login to `/oauth/authorize` MUST include the full original query string: `client_id`, `redirect_uri`, `response_type`, `state`, `scope`, and any other parameters from the initial authorization request.

### REQ-3: Consent page MUST display client identity

The consent page SHOULD show the client's identity (domain or name) to the user before they approve the authorization request.

## Acceptance Criteria

- [ ] Logging in with `client_id` in query string redirects to `/oauth/authorize` (not directly to authorization)
- [ ] All original OAuth params (`client_id`, `redirect_uri`, `response_type`, `state`, `scope`) are preserved
- [ ] The consent page renders with client domain information
- [ ] User must explicitly approve on the consent page before authorization callback is sent
