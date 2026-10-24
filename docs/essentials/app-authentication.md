# App authentication

How the app proves itself to Teams, and how Teams proves itself to the app.

## Inbound validation

Every `POST /api/messages` request must carry a Bot Framework JWT. Token decoding, JWK import, RS256 signature verification, and standard claims use the established [`jwt` gem](https://github.com/jwt/ruby-jwt). This experimental branch delegates JWKS retrieval and caching to [`jwk-loader`](https://github.com/anakinj/jwk-loader), while retaining Teams-specific endpoint selection and service URL checks.

The app validates:

- **Signature** against Microsoft's published signing keys (RS256, JWKS fetched and cached)
- **Issuer** — the Bot Framework issuer, or your tenant's Entra issuers (v1 and v2 forms) when `TENANT_ID` is configured
- **Audience** — your app id, in any of the three accepted forms: the bare id, `api://{id}`, `api://botid-{id}`
- **Expiry / not-before** with five minutes of clock tolerance, matching the JavaScript Teams SDK
- **`serviceurl` claim** — must match the activity's service URL, preventing spoofed routing

Rejected requests get a 401 with a warn log line. Requests are rejected wholesale when no credentials are configured (with a loud startup warning) unless `dangerously_allow_unauthenticated_requests: true` is set explicitly — which is for local development only. The option can also come from the `DANGEROUSLY_ALLOW_UNAUTHENTICATED_REQUESTS` environment variable (`true`/`false`, `1`/`0`, `yes`/`no`, or `on`/`off`); the older `skip_auth:` name still works as a deprecated alias.

### Signing-key caching and rotation

**Draft experiment, not a production-ready replacement for [PR #12](https://github.com/bavmind/teams_rb/pull/12).** This branch deliberately uses `jwk-loader`'s default rollover policy rather than implementing the parent's JavaScript-style cache. The feature discussion is tracked in [jwk-loader issue #15](https://github.com/anakinj/jwk-loader/issues/15).

Each trusted JWKS URI has a provider with an isolated memory cache that stores the whole key set. An unknown `kid` can invalidate and re-fetch that set only after the default fifteen-minute grace period. Known keys have no TTL or capacity limit: even after Microsoft removes a key, a process can continue using its cached copy indefinitely until an unknown key triggers refresh. There is no background refresh, and refresh timing uses the loader's wall clock. The existing validator mutex still coordinates concurrent lookups.

The loader fetches JWKS through `Net::HTTP`; the validator's injected `http:` client now handles only Bot Framework discovery. JWT, JSON, transport, and key-import failures become authentication errors, yielding logged HTTP 401 responses through the Rack adapter. After invalidation, a failed fetch does not retain the previous key set. The loader also parses response bodies without explicitly rejecting non-2xx HTTP statuses; an error object can become a cached empty set that prevents immediate recovery during the grace period. These are intentional, documented limitations of this draft, not equivalent guarantees to the parent PR.

Bot Framework discovery still resolves `jwks_uri` once per validator, and tenant keys still use the configured tenant endpoint. RS256, issuer, audience, five-minute clock tolerance, service URL checks, and rejection of ambiguous missing-`kid` tokens remain in place.

## Outbound bot tokens

Replies and proactive sends authenticate with an app-only token from the Entra client-credentials flow, acquired and cached automatically (single-flight refresh with expiry skew — the other SDKs get the equivalent from MSAL). Nothing to configure beyond the three credentials.

## The trust model in one paragraph

Teams never talks to your bot directly — the Bot Framework service does, signing every request with Microsoft-issued tokens audienced to *your* app id. Your bot talks back through the service URL from the validated activity, authenticating with *your* app's token. User identity inside activities (`ctx.activity.from`) is asserted by Teams and safe to trust once the JWT validates; user identity for *external* calls (Graph, your own API) comes from [user authentication](../in-depth-guides/user-authentication.md) instead.

## Sovereign clouds

Pass a `cloud:` environment to route logins, token services, and Graph to sovereign endpoints. The public cloud is the default.
