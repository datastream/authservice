#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# OAuth 2.0 Authorization Code Flow with PKCE — Mobile Reference
# -----------------------------------------------------------------------------
# This script demonstrates the token exchange steps using curl.
# It generates PKCE parameters, prints the authorize URL for manual visit,
# and then exchanges the received code for an access token.
#
# For native iOS/Android integration, map each step to the corresponding
# platform HTTP client API (see README.md).
#
# Usage:
#   ./token-exchange.sh
#
# Prerequisites:
#   - A running OAuth server (set SERVER_BASE below)
#   - A registered client with client_id and redirect_uri
#   - curl with support for sha256sum (standard on most systems)
#   - openssl for SHA-256 hashing
# -----------------------------------------------------------------------------

# --- Configuration ---
# Set these to match your server and registered client
SERVER_BASE="${SERVER_BASE:-http://localhost:8080}"
CLIENT_ID="mobile-example"
REDIRECT_URI="http://localhost:8000/callback"

# --- Step 1: Generate code_verifier (random 32 bytes, Base64Url-encoded) ---
echo "=== Step 1: Generating PKCE parameters ==="
code_verifier=$(openssl rand -base64 32 | tr -d '\n' | tr '+/' '-_')
# Ensure verifier is within RFC 7636 limits (43-128 chars)
if [ ${#code_verifier} -lt 43 ]; then
  code_verifier="${code_verifier}$(openssl rand -base64 16 | tr -d '\n' | tr '+/' '-_')"
fi
echo "code_verifier: ${code_verifier}"

# --- Step 2: Compute code_challenge (S256 = Base64UrlEncode(SHA256(verifier))) ---
echo "=== Step 2: Computing code_challenge (S256) ==="
code_challenge=$(echo -n "$code_verifier" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | sed 's/=*$//')
echo "code_challenge: ${code_challenge}"

# --- Step 3: Generate state parameter (for CSRF protection) ---
state=$(openssl rand -hex 16)
echo "state: ${state}"

# --- Step 4: Construct the authorize URL ---
# In a native mobile app, open this URL in SFSafariViewController (iOS) or
# CustomTabs (Android) for the user to authenticate and consent.
AUTHORIZE_URL="${SERVER_BASE}/oauth/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${REDIRECT_URI}'))")&code_challenge=${code_challenge}&code_challenge_method=S256&state=${state}"
echo ""
echo "=== Step 3: Open this URL in your browser to authenticate ==="
echo "${AUTHORIZE_URL}"
echo ""
echo "After authentication and consent, the browser will redirect to:"
echo "${REDIRECT_URI}?code=<CODE>&state=${state}"
echo ""

# --- Step 4a: Wait for user to input the authorization code ---
echo "Paste the authorization code from the redirect URL (or enter 'mock' for demo):"
read -r auth_code

if [ "$auth_code" = "mock" ]; then
  echo "Skipping token exchange (demo mode)."
  exit 0
fi

# --- Step 5: Exchange authorization code for access token ---
echo ""
echo "=== Step 5: Exchanging code for token ==="

token_response=$(curl -s -X POST "${SERVER_BASE}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=${auth_code}" \
  -d "redirect_uri=${REDIRECT_URI}" \
  -d "client_id=${CLIENT_ID}" \
  -d "code_verifier=${code_verifier}")

echo "Token response:"
echo "$token_response" | python3 -m json.tool 2>/dev/null || echo "$token_response"

# --- Step 6: Extract access token and fetch userinfo ---
access_token=$(echo "$token_response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

if [ -z "$access_token" ]; then
  echo "Failed to extract access token from response."
  exit 1
fi

echo ""
echo "=== Step 6: Fetching userinfo ==="
curl -s -X GET "${SERVER_BASE}/userinfo" \
  -H "Authorization: Bearer ${access_token}" | python3 -m json.tool 2>/dev/null

echo ""
echo "=== Done ==="
echo "Access token: ${access_token:0:20}..."
echo "Use it with: curl -H 'Authorization: Bearer <token>' ${SERVER_BASE}/userinfo"
