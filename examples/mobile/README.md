# Mobile App OAuth 2.0 Integration

Reference implementation for integrating with this OAuth 2.0 authorization server from native mobile apps.

## Security Considerations for Mobile Clients

Mobile apps are **public clients** — they cannot securely store a client secret because their code is distributable. This is why this server uses **PKCE** (RFC 7636) instead of the Authorization Code Flow with client authentication.

**Key security rules:**
- **Never** hardcode `client_secret` in mobile app code
- **Always** use PKCE with `code_challenge_method=S256` (SHA-256)
- **Never** log or transmit access tokens in URLs
- Store tokens in platform secure storage (Keychain/Keystore)
- Validate the `state` parameter to prevent CSRF attacks

## Quick Start: Curl Reference Script

The `token-exchange.sh` script demonstrates the full token exchange flow using curl:

```bash
# Set your server URL
export SERVER_BASE=http://localhost:8080

# Run the script
chmod +x token-exchange.sh
./token-exchange.sh
```

The script:
1. Generates a random `code_verifier` (32 bytes)
2. Computes `code_challenge` using SHA-256 (S256)
3. Prints the authorize URL for manual visit
4. Waits for the authorization code input
5. Exchanges the code for an access token
6. Fetches userinfo with the token

## Native Integration

### iOS (Swift)

Use `ASWebAuthenticationSession` for the browser-based auth flow:

```swift
import AuthenticationServices

class OAuthService {
    func authorize(clientID: String, redirectURL: URL) {
        // Step 1: Generate PKCE parameters
        let codeVerifier = generateRandomString(length: 32)
        let codeChallenge = sha256Base64url(codeVerifier)
        let state = generateRandomString(length: 16)
        
        // Step 2: Build authorize URL
        var components = URLComponents(string: "\(BASE_URL)/oauth/authorize")!
        components.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURL.absoluteString),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "scope", value: "openid profile email")
        ]
        
        // Step 3: Start authentication session
        let session = ASWebAuthenticationSession(
            url: components.url!,
            callbackURLScheme: redirectURL.scheme!
        ) { callbackURL, error in
            // Step 4a: Parse callback for code or error
            if let error = error {
                // Handle error
                return
            }
            guard let url = callbackURL,
                  let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  let code = components.queryItems?.first(where: { $0.name == "code" })?.value
            else {
                return
            }
            
            // Step 5: Exchange code for token
            self.exchangeCode(code: code, verifier: codeVerifier, redirectURL: redirectURL)
        }
        session.presentationContextProvider = self
        session.start()
    }
    
    func exchangeCode(code: String, verifier: String, redirectURL: URL) {
        var request = URLRequest(url: URL(string: "\(BASE_URL)/oauth/token")!)
        request.httpMethod = "POST"
        request.httpBody = "grant_type=authorization_code&code=\(code.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)&redirect_uri=\(redirectURL.absoluteString)&client_id=\(clientID)&code_verifier=\(verifier)".data(using: .utf8)
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        URLSession.shared.dataTask(with: request) { data, _, _ in
            guard let data = data else { return }
            // Parse response and store access_token securely
            if let token = try? JSONDecoder().decode(TokenResponse.self, from: data) {
                SecureStorage.save(token.accessToken, forKey: "access_token")
            }
        }.resume()
    }
    
    private func sha256Base64url(_ input: String) -> String {
        let data = Data(input.utf8)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return Data(hash).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
```

**Key mappings to curl script:**
| curl step | iOS SDK equivalent |
|-----------|-------------------|
| `openssl rand -base64 32` | `ProcessInfo().globallyUniqueString` + `SecRandomCopyBytes` |
| `openssl dgst -sha256` | `CommonCrypto.CC_SHA256` |
| `echo -n "$url"` (authorize URL) | `ASWebAuthenticationSession` |
| `curl POST /oauth/token` | `URLSession.dataTask` with POST request |
| `curl GET /userinfo` | `URLSession.dataTask` with GET + Bearer header |

### Android (Kotlin)

Use `CustomTabsIntent` for the browser-based auth flow:

```kotlin
class OAuthService @Inject constructor(
    private val customTabsService: CustomTabsService
) {
    suspend fun authorize(clientId: String, redirectUri: String): String {
        // Step 1: Generate PKCE parameters
        val codeVerifier = generateRandomString(32)
        val codeChallenge = sha256Base64url(codeVerifier)
        val state = generateRandomString(16)
        
        // Step 2: Build authorize URL
        val url = buildUri("$BASE_URL/oauth/authorize") {
            setQueryParameter("response_type", "code")
            setQueryParameter("client_id", clientId)
            setQueryParameter("redirect_uri", redirectUri)
            setQueryParameter("code_challenge", codeChallenge)
            setQueryParameter("code_challenge_method", "S256")
            setQueryParameter("state", state)
            setQueryParameter("scope", "openid profile email")
        }
        
        // Step 3: Open in CustomTabs
        // (Show a WebView or CustomTab for the user to log in)
        
        // Step 4: Receive callback via deeplink
        // Parse the Intent data for the authorization code
        
        // Step 5: Exchange code for token
        val tokenResponse = RetrofitClient.api.exchangeCode(
            ExchangeCodeRequest(
                grantType = "authorization_code",
                code = authorizationCode,
                redirectUri = redirectUri,
                clientId = clientId,
                codeVerifier = codeVerifier
            )
        )
        return tokenResponse.accessToken
    }
    
    private fun sha256Base64url(input: String): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }
}
```

**Key mappings to curl script:**
| curl step | Android SDK equivalent |
|-----------|----------------------|
| `openssl rand -base64 32` | `SecureRandom` + `Base64.encode` |
| `openssl dgst -sha256` | `MessageDigest.getInstance("SHA-256")` |
| `curl GET/POST` | `Retrofit` or `OkHttpClient` |
| `code_verifier` storage | `SharedPreferences` (in-memory preferred during flow) |

## Token Storage

**iOS**: Use `Keychain Services` (`SecItemAdd`/`SecItemCopyMatching`) to store the access token and refresh token.

**Android**: Use `Android Keystore` + `EncryptedSharedPreferences` to store tokens. Never store tokens in plain SharedPreferences or file storage.

## Refresh Tokens

This server may support refresh tokens. If the `offline_access` scope is requested and supported, the token response will include a `refresh_token`. Use it to obtain a new access token without requiring user re-authentication:

```bash
curl -X POST ${SERVER_BASE}/oauth/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN" \
  -d "client_id=${CLIENT_ID}"
```

Refer to `examples/README.md` for the complete server endpoint documentation.
