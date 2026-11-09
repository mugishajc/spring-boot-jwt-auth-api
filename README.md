# spring-boot-jwt-auth-api

[![CI](https://github.com/mugishajc/spring-boot-jwt-auth-api/actions/workflows/ci.yml/badge.svg)](https://github.com/mugishajc/spring-boot-jwt-auth-api/actions/workflows/ci.yml)

A stateless authentication service built with Spring Boot 3 and Spring Security 6.
Users register and log in with email and password, receive a short-lived JWT
access token plus a rotating refresh token, and are authorised by role
(`USER` or `ADMIN`).

## Stack

- Java 21, Maven
- Spring Boot 3.5: Web, Security 6, Data JPA, Validation
- JJWT 0.12 for HS256 access tokens
- H2 in memory for development, PostgreSQL profile for real databases
- springdoc-openapi for the OpenAPI spec and Swagger UI
- JUnit 5, MockMvc, AssertJ

## Design notes

- **Access tokens** are HS256 JWTs valid for 15 minutes. They carry the user id,
  email, role, issuer and a `typ=access` claim. The filter rejects anything that
  fails signature, expiry, issuer or type checks, including `alg=none` tokens.
- **Refresh tokens** are random 256-bit opaque strings, not JWTs. Only their
  SHA-256 hash is stored, so a database dump does not leak usable tokens.
- **Rotation with reuse detection.** Each refresh consumes the old token and
  issues a new one. If a consumed token is presented again, the API assumes it
  was stolen and revokes every active session for that user.
- **Passwords** are hashed with BCrypt (cost 12). Passwords are capped at 72
  characters because BCrypt ignores anything past 72 bytes.
- **Login does not leak which emails exist.** Wrong password and unknown email
  return the same message, and unknown emails still run a BCrypt comparison so
  response times match.
- **Role changes take effect quickly.** Changing a user's role or disabling the
  account revokes their refresh tokens. Their current access token keeps working
  until it expires, at most 15 minutes. Admins cannot change their own role or
  disable themselves.
- **Admin routes are guarded twice:** a URL rule in `SecurityConfig` and
  `@PreAuthorize("hasRole('ADMIN')")` on the controller.
- **Errors** use RFC 9457 problem details (`application/problem+json`), including
  401 and 403 responses produced by the security filter chain.
- **No secret in the base config.** `app.jwt.secret` comes from `JWT_SECRET`.
  Only the `dev` profile has a fallback value, and the app refuses to start if
  the secret is missing or shorter than 32 bytes.

## Running locally

Requires JDK 21+.

```bash
./mvnw spring-boot:run      # or: mvn spring-boot:run
```

The `dev` profile is active by default. It uses an in-memory H2 database and
creates an admin account `admin@example.com` / `Admin123!dev` (override with
`ADMIN_EMAIL` and `ADMIN_PASSWORD`).

Swagger UI: http://localhost:8080/swagger-ui.html

### PostgreSQL

```bash
export SPRING_PROFILES_ACTIVE=postgres
export DB_URL=jdbc:postgresql://localhost:5432/authdb
export DB_USERNAME=auth
export DB_PASSWORD=...
export JWT_SECRET=$(openssl rand -base64 48)
export ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=...   # optional, first run only
mvn spring-boot:run
```

## Endpoints

| Method | Path | Access | Description |
|---|---|---|---|
| POST | `/api/auth/register` | public | Create a USER account, returns tokens |
| POST | `/api/auth/login` | public | Email and password for tokens |
| POST | `/api/auth/refresh` | public | Rotate a refresh token |
| POST | `/api/auth/logout` | public | Revoke a refresh token |
| GET | `/api/users/me` | USER, ADMIN | Current user's profile |
| GET | `/api/admin/users` | ADMIN | Paged user list (`page`, `size`, `sort`) |
| GET | `/api/admin/users/{id}` | ADMIN | One user |
| PATCH | `/api/admin/users/{id}/role` | ADMIN | Body `{"role":"ADMIN"}` |
| PATCH | `/api/admin/users/{id}/status` | ADMIN | Body `{"enabled":false}` |

### Example session

```bash
# Register
curl -s -X POST localhost:8080/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"aline@example.com","password":"Str0ngPassw0rd","fullName":"Aline Uwase"}'
```

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "q2b0V4Lr...",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "user": { "id": 2, "email": "aline@example.com", "fullName": "Aline Uwase", "role": "USER", "enabled": true, "createdAt": "..." }
}
```

```bash
# Call a protected endpoint
curl -s localhost:8080/api/users/me -H "Authorization: Bearer $ACCESS_TOKEN"

# Get a new access token when the old one expires
curl -s -X POST localhost:8080/api/auth/refresh \
  -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}"
```

A USER calling an admin endpoint gets:

```json
{ "type": "about:blank", "title": "Forbidden", "status": 403,
  "detail": "You do not have permission to perform this action", "instance": "/api/admin/users" }
```

## Tests

```bash
mvn verify
```

- `AuthFlowIntegrationTest`: registration, duplicate email, validation errors,
  login, forged and malformed tokens, refresh rotation, reuse detection, logout.
- `RoleAccessIntegrationTest`: 401 vs 403, admin paging, promotion revoking
  sessions, self-demotion blocked, disabled accounts.
- `JwtServiceTest`: expiry with a fixed clock, wrong secret, wrong issuer,
  `alg=none`, startup checks on the secret.

Tests run against H2 with BCrypt cost 4 to keep them fast.

## Project layout

```
src/main/java/io/github/mugishajc/authapi
├── auth        register/login/refresh/logout, refresh token storage
├── user        user entity, profile and admin endpoints
├── security    JWT service, filter, security config, 401/403 writer
├── config      clock, password encoder, OpenAPI, admin bootstrap
└── common      exceptions and the global problem-detail handler
```

## License

[MIT](LICENSE)
