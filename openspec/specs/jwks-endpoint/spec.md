# JWKS Endpoint

## ADDED Requirements

### Requirement: Server SHALL generate an RSA-2048 key pair at startup

The server MUST generate a new RSA-2048 key pair on each startup. The private key SHALL be held in memory and MUST never be serialized to disk or transmitted over the network. The public key SHALL be exported to JWK format for the JWKS endpoint.

#### Scenario: Key generation on startup

- **WHEN** the server starts (during `AuthService.InitJWKS()`)
- **THEN** an RSA-2048 key pair is generated and stored in memory

### Requirement: Server SHALL serve public keys at /.well-known/jwks.json

The server MUST expose a `GET /.well-known/jwks.json` endpoint that returns a JWKS (JSON Web Key Set) document conforming to RFC 7517 Section 5. The response MUST be a JSON object with a `keys` array containing one JWK per the server's RSA-2048 public key.

#### Scenario: JWKS endpoint returns valid JWKS

- **WHEN** a client sends GET `/.well-known/jwks.json`
- **THEN** the server responds with HTTP 200 and a JSON body `{"keys": [<JWK>]}` containing one RSA public key

#### Scenario: JWKS response uses RFC 7517 format

- **WHEN** the JWKS response body is parsed as JSON
- **THEN** it contains a `keys` array with one object; each object has the following fields per RFC 7517:
  - `kty` (string): `"RSA"`
  - `use` (string): `"sig"`
  - `kid` (string): opaque key identifier
  - `alg` (string): `"RS256"`
  - `n` (string): base64url-encoded RSA modulus
  - `e` (string): base64url-encoded RSA public exponent (typically `AQAB`)

#### Scenario: JWKS endpoint returns correct HTTP headers

- **WHEN** a client requests `/.well-known/jwks.json`
- **THEN** the response includes:
  - `Content-Type: application/json`
  - `Cache-Control: public, max-age=86400` (24 hours per RFC 8414 Section 6)

### Requirement: JWKS key ID SHALL be derived from public key SPKI bytes

The `kid` value for each JWK MUST be derived deterministically from the key material: base64url(NoPadding)(SHA-256(DER-encoded SubjectPublicKeyInfo bytes of the public key)), per RFC 7517 Section 4.5.

#### Scenario: Key ID derivation

- **WHEN** the server generates or loads a key pair
- **THEN** the `kid` is computed as base64url(NoPadding)(SHA-256(pubkeyDER)) where pubkeyDER is the DER-encoded SubjectPublicKeyInfo structure (RFC 5280)

#### Scenario: Key ID is stable across restarts

- **WHEN** the server is configured with `jwksKeyFile` and the same PEM file persists across restarts
- **THEN** the `kid` value remains identical between restarts

### Requirement: JWKS endpoint SHALL serve only public key

The JWKS endpoint MUST serve only the public key. The private key parameter (`d`) MUST NOT appear in the JWKS response.

#### Scenario: JWKS contains no private key material

- **WHEN** the JWKS response is parsed
- **THEN** the JWK object contains no `d`, `p`, `q`, `dp`, `dq`, or `qi` fields

### Requirement: JWKS endpoint SHALL support key file loading

The server SHALL support loading an RSA private key from a file specified in the `jwksKeyFile` config field. When this config field is set, the server MUST:
- Read the PEM file and decode a RSA private key (PKCS#1 or PKCS#8 format)
- Derive the public key and compute `kid` as specified above
- Log a fatal error if the file does not exist, cannot be read, or does not contain a valid RSA key

#### Scenario: Server loads persisted key from file

- **WHEN** config specifies `jwksKeyFile` pointing to a valid PEM file with a RSA private key
- **THEN** the server loads that key pair and uses it for the JWKS endpoint

#### Scenario: Invalid key file causes startup failure

- **WHEN** config specifies `jwksKeyFile` pointing to an invalid file or a PEM containing a non-RSA key
- **THEN** the server logs a fatal error describing the issue and exits

## MODIFIED Requirements

### Requirement: Auto-generated keys have no persistence

**Reason**: The server now supports optional key persistence via `jwksKeyFile` config.

**Migration**: Users who need stable key identity across restarts can provide a PEM key file via config. The server generates a new random key pair by default if no key file is specified.

The server SHALL generate an RSA-2048 key pair on startup. If the `jwksKeyFile` config field is set and points to a valid PEM file containing a RSA private key, the server MUST load the key from that file. When loading from file, the private key is held in memory and the public key is exported to the JWKS endpoint.

#### Scenario: Default key generation without persisted key

- **WHEN** config does NOT specify `jwksKeyFile`
- **THEN** the server generates a new RSA-2048 key pair at each startup

#### Scenario: Server loads persisted key from file

- **WHEN** config specifies `jwksKeyFile` pointing to a valid PEM file with a RSA private key
- **THEN** the server loads that key pair instead of generating a new one

#### Scenario: Invalid key file causes startup failure

- **WHEN** config specifies `jwksKeyFile` pointing to an invalid or unreadable file
- **THEN** the server refuses to start and logs a fatal error describing the issue