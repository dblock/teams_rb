# App authentication

How the app proves itself to Teams, and how Teams proves itself to the app. All of it matches the TypeScript, Python, and .NET SDKs.

## Inbound validation

Every `POST /api/messages` request must carry a Bot Framework JWT. The app validates:

- **Signature** against Microsoft's published signing keys (RS256, JWKS fetched and cached)
- **Issuer** — the Bot Framework issuer, or your tenant's Entra issuers (v1 and v2 forms) when `TENANT_ID` is configured
- **Audience** — your app id, in any of the three accepted forms: the bare id, `api://{id}`, `api://botid-{id}`
- **Expiry / not-before**
- **`serviceurl` claim** — must match the activity's service URL, preventing spoofed routing

Rejected requests get a 401 with a warn log line. Requests are rejected wholesale when no credentials are configured (with a loud startup warning) unless `dangerously_allow_unauthenticated_requests: true` is set explicitly — which is for local development only. The option can also come from the `DANGEROUSLY_ALLOW_UNAUTHENTICATED_REQUESTS` environment variable (`true`/`false`, `1`/`0`, `yes`/`no`, or `on`/`off`); the older `skip_auth:` name still works as a deprecated alias.

### Signing-key rotation

Signing keys are cached separately for each accepted issuer for up to 24 hours. The next validation after expiry refreshes the keys; an unknown key ID also triggers a refresh, provided at least five minutes have elapsed since the previous attempt for that issuer. Both paths re-run OpenID discovery for Bot Framework tokens, so changes to the key-set URL are picked up too. Refreshes are serialized across threads, and use a monotonic clock for expiry and throttling.

Fetch failures propagate to the caller (the Rack endpoint logs them and returns 500); they do not replace the previous cached keys or bypass validation. Requests using known keys can continue while that cache is unexpired. Further fetch attempts are throttled for five minutes, including after a failure. If no unexpired cache is available during that interval, validation fails with an authentication error. A key ID still absent after refresh is rejected as before.

This follows the [Bot Connector requirement to refresh signing keys at least every 24 hours](https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-authentication?view=azure-bot-service-4.0#step-3-get-the-list-of-valid-signing-keys) and the [Microsoft signing-key rollover guidance for throttled refresh on an unknown key ID](https://learn.microsoft.com/en-us/entra/identity-platform/signing-key-rollover#best-practices-for-keys-metadata-caching-and-validation). No user sign-in, client-secret rotation, or Teams app reinstallation is required to pick up new Microsoft signing keys.

## Outbound bot tokens

Replies and proactive sends authenticate with an app-only token from the Entra client-credentials flow, acquired and cached automatically (single-flight refresh with expiry skew — the other SDKs get the equivalent from MSAL). Nothing to configure beyond the three credentials.

## The trust model in one paragraph

Teams never talks to your bot directly — the Bot Framework service does, signing every request with Microsoft-issued tokens audienced to *your* app id. Your bot talks back through the service URL from the validated activity, authenticating with *your* app's token. User identity inside activities (`ctx.activity.from`) is asserted by Teams and safe to trust once the JWT validates; user identity for *external* calls (Graph, your own API) comes from [user authentication](../in-depth-guides/user-authentication.md) instead.

## Sovereign clouds

Pass a `cloud:` environment to route logins, token services, and Graph to sovereign endpoints. The public cloud is the default.
