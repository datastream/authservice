## Context
The user wants a comprehensive test suite covering all HTTP API endpoints using SQLite backend. Current implementation has import cycles preventing tests from compiling. We need to refactor test utilities and tests to eliminate the cycle and ensure all tests pass.

## Revised Plan
1. **Break import cycle**:
   - Remove the `controllers` import from `testutils/helpers.go`.
   - Change `LoadTestService` to only initialize the `AuthService` and return it (no router).
   - Add a new helper `BuildRouter(svc *core.AuthService) *gin.Engine` in `helpers.go` that registers all routes using the `controllers` package. This keeps route setup separate from service init.
2. **Update test files**:
   - In `pkg/controllers/api_test.go`, call `svc := testutils.LoadTestService(t)` then `router := testutils.BuildRouter(svc)`.
   - Adjust existing test code to use the new router variable.
3. **Adjust imports**:
   - Add `controllers` import in `helpers.go` only for the `BuildRouter` function.
   - Ensure no circular dependencies: `testutils` imports `core` and `controllers`; `controllers` does not import `testutils`.
4. **Fix missing imports**:
   - Add missing `github.com/gin-gonic/gin` import in `helpers.go` for router building.
5. **Run `go mod tidy`** to clean dependencies.
6. **Run tests**:
   - Execute `go test ./...`.
   - Verify all tests pass and coverage meets >80%.
7. **Cleanup**:
   - Remove any unused code/comments.
   - Ensure `config_test.yaml` uses SQLite backend.

## Verification Steps
1. `go test ./...` runs without import cycle errors.
2. All tests succeed (health, login, token create/list/revoke, etc.).
3. SQLite DB file `test_authserver.db` is created and removed after tests.
4. Coverage report shows high coverage for controller code.

---
*This updated plan is ready for approval.*
The user wants comprehensive test coverage for all HTTP API endpoints in the auth service, using SQLite as the backend storage during tests. The project already supports SQLite via the `github.com/glebarez/sqlite` driver (see `pkg/core/service.go`). No test files currently exist.

## Recommended Approach
1. **Create a test configuration** – Add a `config_test.yaml` that sets:
   ```yaml
   database:
     postgres:
       enabled: false
       uri: ""
     sqlite:
       enabled: true
       uri: "test_authserver.db"
   redis: ""
   sessionName: "test_session"
   origins: []
   ```
   This ensures the service uses SQLite in a temporary file for the test run.
2. **Write integration tests** – For each HTTP handler identified (see list from the Explore agent), add a test function in `pkg/controllers/api_test.go` that:
   - Starts the server in a goroutine using the test config (`go run ./cmd/oauthservice/main.go -c config_test.yaml`).
   - Uses `httptest.NewRecorder` and `http.NewRequest` to invoke the endpoint.
   - Performs necessary setup (e.g., creates a user session, inserts required DB records via GORM).
   - Checks response status codes, JSON payloads, and side‑effects (e.g., token created in DB, token revoked).
3. **Test setup/teardown** – In `TestMain(m *testing.M)`:
   - Load the test config with `core.LoadConfig`.
   - Call `svc.InitDB()` to create the SQLite DB.
   - Run `svc.InitOAuthServer()`.
   - Clean up the `test_authserver.db` file after tests.
4. **Coverage of all endpoints** – Implement test functions for:
   - Login flow (`GET /login`, `POST /login` if present).
   - Logout (`GET /logout`).
   - Manager page (`GET /manager`).
   - Token list/create/revoke (`GET /tokens`, `POST /tokens`, `DELETE /tokens/:id`).
   - OAuth endpoints (`GET /oauth/authorize`, `POST /oauth/authorize`, `POST /oauth/token`).
   - Userinfo (`GET /userinfo`, `GET /userinfo/emails`).
   - FGA routes (`POST /api/v1/fga/models`, `GET /api/v1/fga/models/:id`, `POST /api/v1/fga/models/:id/evaluate`, `POST /api/v1/fga/models/:id/tuples`, `DELETE /api/v1/fga/models/:id/tuples`).
   - Signup (`GET /signup`, `POST /signup`).
   - Token authentication (`POST /authentication`).
5. **Helper utilities** – Add a `testutils` package with functions to:
   - Create a user and obtain a session cookie.
   - Insert a token record directly via GORM.
   - Parse JSON responses into structs for assertions.
6. **Run tests** – Execute `go test ./...` ensuring the SQLite driver is available. Verify that coverage includes all handler files.

## Files to Create / Modify
- `cmd/oauthservice/config_test.yaml` – test configuration (SQLite enabled).
- `pkg/controllers/api_test.go` – integration tests for all HTTP handlers.
- `testutils/helpers.go` – helper functions for test setup.
- (Optional) `go.mod` – ensure `github.com/glebarez/sqlite` is required (already present).

## Verification Steps
1. Run `go test ./...`.
2. Confirm that the SQLite DB file `test_authserver.db` is created and removed after the test suite.
3. Ensure all tests pass and each HTTP endpoint returns the expected status and payload.
4. Check coverage with `go test -cover ./...` – aim for >80% of handler code.

## Notes & Edge Cases
- SQLite does not support concurrent writes; tests run sequentially to avoid conflicts.
- Some handlers rely on session cookies; the test helpers must simulate login and store the cookie in subsequent requests.
- FGA endpoints require an OpenFGA server; for unit tests you can mock the FGA client or skip those tests if the service is not reachable (mark with `t.Skip`).
- Ensure the test config disables Redis to avoid external dependencies.
- Clean up any persisted data (users, tokens) between tests to keep them isolated.

---
*This plan is ready for approval.*
