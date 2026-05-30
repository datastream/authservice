/**
 * OAuth 2.0 Authorization Code Flow with PKCE
 *
 * This script implements the full OAuth flow for a public client:
 *  1. User clicks "Authorize" -> generate PKCE parameters
 *  2. Browser redirected to /oauth/authorize -> user logs in and consents
 *  3. Server redirects back with authorization code
 *  4. App exchanges code for access token (with code_verifier)
 *  5. App fetches userinfo with access token
 *
 * Server endpoints assumed to be at the same origin as this page.
 */

// ---------------------------------------------------------------------------
// Configuration — adjust BASE_URL to match your server
// ---------------------------------------------------------------------------

const BASE_URL = window.location.origin;

// ---------------------------------------------------------------------------
// Error handling helpers
// ---------------------------------------------------------------------------

/**
 * Map common OAuth error codes to user-friendly messages
 */
function friendlyOAuthError(code, description) {
  const messages = {
    invalid_request: "The request is missing a required parameter or contains an invalid value.",
    invalid_client: "The client is not registered or the credentials are invalid.",
    invalid_grant: "The authorization code is expired, invalid, or does not match the PKCE challenge.",
    unauthorized_client: "This client is not authorized to use this flow.",
    unsupported_response_type: "The server does not support the requested response type.",
    access_denied: "You denied consent or the login was cancelled.",
    server_error: "An unexpected error occurred on the server. Please try again later.",
    temporarily_unavailable: "The server is temporarily unavailable. Please try again later.",
  };
  return (
    messages[code] ||
    description ||
    `Unknown error: ${code}`
  );
}

/**
 * Handle fetch errors (network failures, CORS issues)
 */
function handleFetchError(error, operation) {
  if (error instanceof TypeError && error.message.includes("fetch")) {
    return `Network error while ${operation}. Check your connection or CORS settings.`;
  }
  return `${error.message || String(error)} while ${operation}`;
}

/**
 * Display an error and offer a retry option
 */
function showError(message, showRetry = false) {
  errorMessage.textContent = message;
  if (showRetry) {
    errorMessage.classList.add("retryable");
  } else {
    errorMessage.classList.remove("retryable");
  }
  showSection("error");
}

// ---------------------------------------------------------------------------
// PKCE utilities
// ---------------------------------------------------------------------------

/**
 * Generate a random code_verifier: 43-128 ASCII characters
 */
function generateCodeVerifier() {
  const array = new Uint8Array(32); // 32 bytes = 43+ Base64Url chars
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

/**
 * Compute S256 code_challenge: Base64UrlEncode(SHA256(code_verifier))
 */
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(hash));
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// State — protect against CSRF via state parameter
// ---------------------------------------------------------------------------

let state = null;
let codeVerifier = null;

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

const sections = {
  profile: document.getElementById("profile"),
  login: document.getElementById("login-section"),
  authorize: document.getElementById("authorize-section"),
  callback: document.getElementById("callback-section"),
  error: document.getElementById("error-section"),
};
const profileData = document.getElementById("profile-data");
const loginForm = document.getElementById("login-form");
const loginError = document.getElementById("login-error");
const authorizeBtn = document.getElementById("authorize-btn");
const logoutBtn = document.getElementById("logout-btn");
const callbackStatus = document.getElementById("callback-status");
const errorMessage = document.getElementById("error-message");

function showSection(name) {
  Object.values(sections).forEach((s) => s.classList.add("hidden"));
  const target = sections[name];
  if (target) target.classList.remove("hidden");
}

function showError(message) {
  errorMessage.textContent = message;
  showSection("error");
}

// ---------------------------------------------------------------------------
// OAuth flow
// ---------------------------------------------------------------------------

/**
 * Step 1: Generate PKCE params and redirect to /oauth/authorize
 */
async function startAuthorization() {
  state = generateCodeVerifier(); // reuse random generator for state
  codeVerifier = generateCodeVerifier();
  const challenge = await generateCodeChallenge(codeVerifier);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: "web-app-example",
    redirect_uri: BASE_URL + "/callback.html",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: state,
    scope: "openid profile email",
  });

  // Save verifier for token exchange step (callback.html shares this script)
  sessionStorage.setItem("code_verifier", codeVerifier);
  sessionStorage.setItem("state", state);

  window.location.href = BASE_URL + "/oauth/authorize?" + params.toString();
}

/**
 * Step 2-3: Handle the callback with authorization code
 */
async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const error = params.get("error");
  const returnedState = params.get("state");

  // Check for error response from server
  if (error) {
    // OAuth error in query string — show user-friendly message
    const description = params.get("error_description") || "";
    showError(friendlyOAuthError(error, description), error !== "access_denied");
    return;
  }

  // Verify state parameter (CSRF protection)
  if (returnedState !== sessionStorage.getItem("state")) {
    showError("Invalid state parameter. Possible CSRF attack.");
    return;
  }

  if (!code) {
    showError("No authorization code received.");
    return;
  }

  showSection("callback");
  callbackStatus.textContent = "Exchanging code for token...";

  try {
    const verifier = sessionStorage.getItem("code_verifier");
    const tokenResponse = await fetch(BASE_URL + "/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: BASE_URL + "/callback.html",
        client_id: "web-app-example",
        code_verifier: verifier,
      }),
    });

    if (!tokenResponse.ok) {
      const err = await tokenResponse.json().catch(() => ({}));
      throw new Error(err.error || "Token exchange failed");
    }

    const tokenData = await tokenResponse.json();
    sessionStorage.setItem("access_token", tokenData.access_token);

    callbackStatus.textContent = "Fetching user profile...";
    await fetchUserinfo(tokenData.access_token);
  } catch (err) {
    showError("Token exchange failed: " + err.message);
  }
}

/**
 * Step 4: Fetch userinfo and display profile
 */
async function fetchUserinfo(token) {
  try {
    const response = await fetch(BASE_URL + "/userinfo", {
      headers: { Authorization: "Bearer " + token },
    });

    if (!response.ok) {
      const errBody = await response.json().catch(() => ({}));
      throw new Error(errBody.error || "Failed to fetch userinfo: " + response.status);
    }

    const profile = await response.json();
    profileData.textContent = JSON.stringify(profile, null, 2);
    showSection("profile");
  } catch (err) {
    showError(handleFetchError(err, "fetching userinfo"));
  }
}

/**
 * Login via the JSON API, then redirect to authorize flow
 */
async function handleLogin(username, password) {
  try {
    const response = await fetch(BASE_URL + "/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || "Login failed");
    }

    const data = await response.json();
    // Server may return a redirect target — navigate there
    if (data.redirect) {
      window.location.href = data.redirect;
    }
  } catch (err) {
    if (loginError) {
      loginError.textContent = err.message;
      loginError.classList.remove("hidden");
    } else {
      showError("Login failed: " + err.message);
    }
  }
}

/**
 * Logout via the JSON API, then reset UI
 */
async function handleLogout() {
  try {
    await fetch(BASE_URL + "/api/logout", { method: "POST" });
  } catch (_) {
    // Ignore logout errors — still reset UI
  }

  sessionStorage.clear();
  showSection("authorize");
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

authorizeBtn.addEventListener("click", startAuthorization);
if (logoutBtn) {
  logoutBtn.addEventListener("click", handleLogout);
}
loginForm.addEventListener("submit", (e) => {
  e.preventDefault();
  handleLogin(
    document.getElementById("username").value,
    document.getElementById("password").value
  );
});

// On page load, check if we're in the callback URL
if (
  new URLSearchParams(window.location.search).has("code") ||
  new URLSearchParams(window.location.search).has("error")
) {
  showSection("callback");
  handleCallback();
} else {
  showSection("authorize");
}
