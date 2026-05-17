# xyOps OIDC SSO Plugin

`xyplug-sso-oidc` is a custom SSO command plugin for `xyOps`.

It lets xyOps perform a direct OpenID Connect (OIDC) login flow without placing OAuth2-Proxy, Authentik, AWS ALB, or another trusted-header proxy in front of it. The plugin redirects the browser to your identity provider, handles the callback, validates the OIDC tokens, fetches user profile data, and emits trusted headers back to xyOps.

Please read the [xyOps SSO](https://docs.xyops.io/sso) documentation before using this plugin.

## What This Does

The plugin runs during the xyOps SSO login flow. It:

1. Receives the xyOps SSO command payload over STDIN.
2. Redirects the browser to your OIDC authorization endpoint when no callback code is present.
3. Receives the callback request with the OIDC `code` and `state` query parameters.
4. Validates an encrypted, short-lived `state` value.
5. Exchanges the authorization code for tokens.
6. Validates the `id_token` with `jose` and the provider JWKS.
7. Fetches UserInfo with the access token, when configured and available.
8. Maps OIDC claims to trusted headers such as `x-forwarded-user`, `x-forwarded-name`, `x-forwarded-email`, and `x-forwarded-groups`.

xyOps then continues through its normal SSO trusted-header login, creates or updates the local user, and starts its own xyOps session.

## Requirements

- Node.js 20 or higher
- `npx` available on the xyOps conductor
- xyOps with SSO custom command support
- An OIDC application/client configured at your identity provider
- The OIDC redirect/callback URI set to your xyOps `base_app_url` exactly

Example redirect URI:

```text
https://xyops.yourcompany.com
```

Do not add `/callback`, `/oauth2/callback`, or any other path. xyOps activates this plugin from the root URI.

Make sure you also add this exact URL to your IdP application's **Allowed Callback URLs**, **Callback URLs**, **Sign-in redirect URIs**, or equivalent setting. The name varies by provider, but the value must match your xyOps Base App URL exactly, including scheme, hostname, and port.

## Install and Run

Recommended command in `sso.json`:

```json
"command": "npx -y @pixlcore/xyplug-sso-oidc@1.0.0"
```

If you prefer, you can preinstall the package globally using `npm i -g @pixlcore/xyplug-sso-oidc@1.0.0` and then execute it directly from xyOps:

```json
"command": "/usr/bin/xyplug-sso-oidc"
```

## SSO Configuration

Here is a complete generic `sso.json` configuration:

```json
{
	"enabled": true,
	"whitelist": false,
	"header_map": {
		"username": "x-forwarded-user",
		"full_name": "x-forwarded-name",
		"email": "x-forwarded-email",
		"groups": "x-forwarded-groups"
	},
	"cleanup_username": false,
	"cleanup_full_name": false,
	"group_role_map": {},
	"group_privilege_map": {},
	"logout_url": "https://YOUR_IDP_LOGOUT_URL",
	"command": "npx -y @pixlcore/xyplug-sso-oidc@1.0.0",
	"oidc": {
		"issuer": "https://YOUR_OIDC_ISSUER",
		"client_id": "YOUR_CLIENT_ID",
		"client_secret": "YOUR_CLIENT_SECRET",
		"state_secret": "GENERATE_A_LONG_RANDOM_SECRET",
		"scope": "openid profile email",
		"token_endpoint_auth_method": "client_secret_basic",
		"use_pkce": true,
		"claim_map": {
			"username": ["preferred_username", "email", "sub"],
			"full_name": ["name", "email"],
			"email": "email",
			"groups": ["groups", "roles"]
		}
	}
}
```

This works because:

- xyOps ignores the custom `oidc` block.
- The plugin reads `oidc` from the command input.
- The plugin emits headers matching your `header_map`.
- xyOps consumes those headers through its normal SSO login system.

## Generate a State Secret

The plugin does not set cookies. Instead, it stores the OIDC nonce and PKCE verifier inside an encrypted `state` value that is sent through the browser and returned by the IdP.

Generate a secret like this:

```sh
openssl rand -base64 48
```

Then set it here:

```json
"state_secret": "PASTE_THE_RANDOM_VALUE_HERE"
```

If `state_secret` is omitted, the plugin can use `client_secret` as a fallback. A dedicated `state_secret` is cleaner, and is required for public clients that do not have a client secret.

## OIDC Configuration Reference

### oidc.issuer

Your OIDC issuer URL. For most providers this is the main value you need. The plugin uses OIDC Discovery by default:

```text
ISSUER/.well-known/openid-configuration
```

Examples:

```json
"issuer": "https://integrator-123456.okta.com/oauth2/default"
```

```json
"issuer": "https://your-tenant.us.auth0.com/"
```

For AWS Cognito, this is **not** your Hosted UI domain. See the AWS Cognito Hosted UI setup chapter below.

### oidc.client_id

The OIDC client/application ID.

### oidc.client_secret

The OIDC client secret, if your client uses one.

### oidc.state_secret

A long random secret used to encrypt and authenticate OIDC `state`.

### oidc.scope

Defaults to:

```text
openid profile email
```

Add any provider-specific scopes needed for groups or roles.

### oidc.token_endpoint_auth_method

Controls how the client authenticates to the token endpoint.

Supported values:

| Value | Description |
|-------|-------------|
| `client_secret_basic` | Sends the client secret using HTTP Basic auth. This is the default when `client_secret` is set. |
| `client_secret_post` | Sends the client secret in the POST body. |
| `none` | Public client mode. Use this with PKCE and a `state_secret`. |

### oidc.use_pkce

Defaults to `true`. The plugin uses S256 PKCE for the authorization code flow.

### oidc.claim_map

Maps xyOps user fields to OIDC claims.

Each value may be:

- a claim name, such as `"email"`
- a dotted path, such as `"userinfo.email"`
- an array of fallbacks, such as `["preferred_username", "email", "sub"]`

Common fields:

| xyOps Field | Common OIDC Claims |
|-------------|--------------------|
| `username` | `preferred_username`, `email`, `sub` |
| `full_name` | `name`, `given_name` plus `family_name`, `email` |
| `email` | `email` |
| `groups` | `groups`, `roles`, custom provider-specific claims |
| `avatar` | `picture`, `avatar`, `avatar_url` |

### oidc.auth_params

Additional query parameters to include on the authorization redirect.

Example for Auth0 API audiences:

```json
"auth_params": {
	"audience": "https://api.yourcompany.com"
}
```

Example to force a provider login prompt:

```json
"auth_params": {
	"prompt": "login"
}
```

### oidc.domain and endpoint overrides

Most providers work from `issuer` and OIDC Discovery alone. Some providers, notably AWS Cognito Hosted UI, may use a hosted UI domain that is separate from the token issuer.

You can provide `domain` plus endpoint paths:

```json
"domain": "frogger.auth.us-west-1.amazoncognito.com",
"login_uri": "/login",
"oauth_uri": "/oauth2/token",
"userinfo_uri": "/oauth2/userInfo"
```

You can also provide full endpoint URLs:

```json
"authorization_endpoint": "https://idp.example.com/oauth2/authorize",
"token_endpoint": "https://idp.example.com/oauth2/token",
"userinfo_endpoint": "https://idp.example.com/oauth2/userInfo",
"jwks_uri": "https://idp.example.com/.well-known/jwks.json"
```

### oidc.fetch_userinfo

Defaults to `true`. Set to `false` to use only ID token claims.

### oidc.userinfo_method

Defaults to `GET`. Set to `POST` for providers that prefer POST requests to UserInfo.

### oidc.require_id_token

Defaults to `true`. Keep this enabled for normal OIDC. If disabled, the plugin can proceed with UserInfo only, but this is less strict and is not recommended unless your provider requires it.

### oidc.request_timeout_ms

Timeout in milliseconds for discovery, token, JWKS, and UserInfo requests. Defaults to `15000`.

### oidc.clock_tolerance_seconds

Optional clock-skew tolerance in seconds for ID token validation.

Example:

```json
"clock_tolerance_seconds": 30
```

### oidc.signing_algorithms

Optional allow-list of ID token signing algorithms.

Example:

```json
"signing_algorithms": ["RS256"]
```

## Provider Setup

### Okta

Create an **OIDC - OpenID Connect** app integration in Okta, and choose **Web Application** as the application type. This is the right fit for xyOps because the plugin runs server-side and can safely use a client secret.

Okta may only show you an org domain, such as:

```text
integrator-123456.okta.com
```

That is normal. You convert that domain into the `issuer` URL yourself.

For Okta Integrator Free Plan orgs, Okta usually creates a custom authorization server named `default`. In that case, use:

```json
"issuer": "https://integrator-123456.okta.com/oauth2/default"
```

For an older or production Okta org that is using the Okta org authorization server instead, use only the domain with `https://`:

```json
"issuer": "https://integrator-123456.okta.com"
```

If you are unsure, try the default custom authorization server first. You can verify it in a browser by opening:

```text
https://integrator-123456.okta.com/oauth2/default/.well-known/openid-configuration
```

If that URL returns JSON with an `issuer` property, copy that exact `issuer` value into the `oidc.issuer` property in `sso.json`.

#### Okta Setup Tips

- Grant types: enable **Authorization Code**.
- Grant types: leave **Refresh Token** disabled unless you have a separate reason to issue refresh tokens. This plugin does not store or reuse refresh tokens.
- Grant types: leave **Client Credentials** disabled. That flow is for machine-to-machine access, not user login.
- Advanced grant types: leave **Implicit (hybrid)** disabled. This plugin uses the code flow and does not need tokens returned directly through the browser.
- Client authentication: use the normal client secret option. In xyOps config, keep `token_endpoint_auth_method` as `client_secret_basic`, or omit it and let the plugin choose that automatically.
- PKCE: it is fine for PKCE to be optional when using a client secret. The plugin sends PKCE by default either way.
- Sign-in redirect URIs: add your xyOps Base App URL exactly, with no path. Example: `https://xyops.yourcompany.com`.
- Assignments or controlled access: assign the Okta users or groups who should be allowed to log into xyOps.
- Scopes: start with only `openid profile email`. Do not request `groups` until you have explicitly added the `groups` scope and claim in Okta.
- Groups: configure group claims later, after basic login works. This keeps first setup much easier to debug.
- Access policies: if you use `/oauth2/default`, make sure the `default` authorization server has an access policy and rule. Without one, Okta may deny token issuance even when users are assigned to the app.

#### Okta Authorization Server Access Policy

If your issuer contains `/oauth2/default`, Okta expects the `default` authorization server to have at least one access policy and one rule.

In Okta:

1. Go to **Security**, then **API**.
2. Open **Authorization Servers**.
3. Click **default**.
4. Open **Access Policies**.
5. If it says **No access policies added**, click **Add Policy**.
6. Name it something like: `xyOps Test`
7. For initial testing, assign it to **All Clients**, or choose your xyOps client if Okta offers that option.
8. Create the policy.
9. Add a rule inside the policy.

For the first rule, use a permissive testing setup:

- Name: `Authorization Code`
- Grant type: **Authorization Code**
- Users: any assigned user, or the specific user/group you are testing with
- Scopes: any scopes, or at least `openid`, `profile`, and `email`
- Access token lifetime: the default is fine
- Refresh token: not needed

Once login works, tighten this policy to only the xyOps client and the users or groups who should be allowed.

#### Okta Groups

Leave `groups` out of `oidc.scope` at first:

```json
"scope": "openid profile email"
```

If you request `groups` before configuring it in Okta, you may get an error like:

```text
One or more scopes are not configured for the authorization server resource.
```

After basic login works, add groups:

1. Go to **Security**, then **API**.
2. Open **Authorization Servers**.
3. Click **default**.
4. Open **Scopes**.
5. Add a scope named `groups`, if it does not already exist.
6. Open **Claims**.
7. Add a claim named `groups`.
8. Include it in the ID token or UserInfo response.
9. Filter it to the Okta groups you want to send to xyOps.
10. Then update xyOps: `"scope": "openid profile email groups"`

For group mappings, verify that the token or UserInfo response actually contains a `groups` claim before debugging xyOps role maps.

#### Okta References

- [Okta authorization servers](https://developer.okta.com/docs/concepts/auth-servers/)
- [Okta well-known OpenID configuration](https://support.okta.com/help/s/article/how-to-find-the-okta-well-known-url?language=en_US)
- [Okta Authorization Code flow](https://developer.okta.com/docs/guides/implement-grant-type/main/)
- [Okta OIDC app integration settings](https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_oidc.htm)

#### Okta Example

```json
{
	"enabled": true,
	"whitelist": false,
	"header_map": {
		"username": "x-forwarded-user",
		"full_name": "x-forwarded-name",
		"email": "x-forwarded-email",
		"groups": "x-forwarded-groups"
	},
	"cleanup_username": false,
	"cleanup_full_name": false,
	"group_role_map": {},
	"group_privilege_map": {},
	"command": "npx -y @pixlcore/xyplug-sso-oidc@1.0.0",
	"oidc": {
		"issuer": "https://YOUR_OKTA_DOMAIN.okta.com/oauth2/default",
		"client_id": "YOUR_OKTA_CLIENT_ID",
		"client_secret": "YOUR_OKTA_CLIENT_SECRET",
		"state_secret": "GENERATE_A_LONG_RANDOM_SECRET",
		"scope": "openid profile email",
		"claim_map": {
			"username": ["preferred_username", "email"],
			"full_name": ["name", "email"],
			"email": "email",
			"groups": "groups"
		}
	}
}
```

### Auth0

Create an Auth0 application with the **Regular Web Application** type. This is Auth0's confidential server-side application type, which matches this plugin because xyOps can safely hold the client secret.

Auth0 setup tips:

- Application type: choose **Regular Web Application**.
- Allowed Callback URLs: add your xyOps Base App URL exactly, with no path. Example: `https://xyops.yourcompany.com`.
- Allowed Logout URLs: add the page you want users to land on after logout, if you configure xyOps `logout_url` to send users to Auth0 logout.
- Allowed Web Origins: usually not needed for this plugin because the browser is not calling Auth0 with JavaScript. If you use custom Auth0 flows or silent auth elsewhere, add the xyOps origin only, without a path.
- Grant types: **Authorization Code** is required.
- Grant types: **Refresh Token** is not needed by this plugin.
- Grant types: **Client Credentials** may be enabled by default on confidential Auth0 apps, but this plugin does not use it.
- Grant types: **Implicit** is not needed and can be disabled for this use case.
- Client authentication: use the client secret. In xyOps config, keep `token_endpoint_auth_method` as `client_secret_basic`, or omit it and let the plugin choose that automatically.
- Connections: make sure the database, enterprise, or social connections your users need are enabled for this application.
- Groups or roles: Auth0 does not usually emit a plain `groups` claim by default. Use Actions, Rules, Organizations, or another Auth0 feature to add a custom namespaced claim, then point `claim_map.groups` at that exact claim name.

#### Auth0 References

- [Auth0 Regular Web App SSO setup](https://auth0.com/docs/get-started/architecture-scenarios/sso-for-regular-web-apps/part-2)
- [Auth0 application grant types](https://auth0.com/docs/get-started/applications/application-grant-types)
- [Auth0 application settings](https://auth0.com/docs/get-started/applications/application-settings)

#### Auth0 Example

```json
{
	"enabled": true,
	"whitelist": false,
	"header_map": {
		"username": "x-forwarded-user",
		"full_name": "x-forwarded-name",
		"email": "x-forwarded-email",
		"groups": "x-forwarded-groups"
	},
	"cleanup_username": true,
	"cleanup_full_name": false,
	"group_role_map": {},
	"group_privilege_map": {},
	"command": "npx -y @pixlcore/xyplug-sso-oidc@1.0.0",
	"oidc": {
		"issuer": "https://your-tenant.us.auth0.com/",
		"client_id": "YOUR_AUTH0_CLIENT_ID",
		"client_secret": "YOUR_AUTH0_CLIENT_SECRET",
		"state_secret": "GENERATE_A_LONG_RANDOM_SECRET",
		"scope": "openid profile email",
		"claim_map": {
			"username": ["email", "nickname", "sub"],
			"full_name": ["name", "email"],
			"email": "email",
			"groups": ["https://yourcompany.example/groups", "groups", "roles"]
		}
	}
}
```

Auth0 custom claims are commonly namespaced, such as:

```json
"https://yourcompany.example/groups"
```

Use the exact claim key in `claim_map`. Dots in a URL-style claim name are part of the claim key, not path separators, so keep the complete string as the claim name.

### Microsoft Entra ID

Microsoft Entra ID was previously known as Azure AD. Create an app registration for xyOps in the Microsoft Entra admin center.

Entra setup tips:

- App registration: choose **New registration** under **App registrations**.
- Supported account types: choose the narrowest option that fits your environment. For most company-internal xyOps installs, use single tenant.
- Redirect URI: choose platform **Web**, then add your xyOps Base App URL exactly, with no path. Example: `https://xyops.yourcompany.com`.
- Certificates & secrets: create a **Client secret** and copy the secret **Value** immediately. The secret ID is not the value to paste into xyOps.
- Authentication: keep **Access tokens** and **ID tokens** under implicit/hybrid flows disabled. This plugin uses the authorization code flow, not implicit flow.
- Authentication: make sure the redirect URI is listed under the **Web** platform, not SPA.
- API permissions: `openid`, `profile`, and `email` are standard OIDC scopes. You usually do not need Microsoft Graph permissions for basic xyOps login.
- Groups: if you want group-based xyOps roles or privileges, configure **Token configuration** to add a groups claim. Entra may emit group object IDs by default, so map those IDs in xyOps or configure optional claims to emit a different group attribute.
- Group overage: users in many groups may not receive a complete `groups` claim in the token. In that case, Entra can emit an overage marker instead, and this plugin will not call Microsoft Graph to expand it.
- Issuer: use a tenant-specific issuer such as `https://login.microsoftonline.com/TENANT_ID/v2.0`. Avoid `common` for production xyOps SSO because ID tokens are tenant-specific.

#### Entra References

- [Microsoft authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Microsoft OpenID Connect protocol](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc)
- [Microsoft optional claims](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims)

#### Entra Example

```json
{
	"enabled": true,
	"whitelist": false,
	"header_map": {
		"username": "x-forwarded-user",
		"full_name": "x-forwarded-name",
		"email": "x-forwarded-email",
		"groups": "x-forwarded-groups"
	},
	"cleanup_username": true,
	"cleanup_full_name": false,
	"group_role_map": {},
	"group_privilege_map": {},
	"command": "npx -y @pixlcore/xyplug-sso-oidc@1.0.0",
	"oidc": {
		"issuer": "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0",
		"client_id": "YOUR_ENTRA_APPLICATION_CLIENT_ID",
		"client_secret": "YOUR_ENTRA_CLIENT_SECRET_VALUE",
		"state_secret": "GENERATE_A_LONG_RANDOM_SECRET",
		"scope": "openid profile email",
		"token_endpoint_auth_method": "client_secret_post",
		"claim_map": {
			"username": ["preferred_username", "email", "upn", "oid", "sub"],
			"full_name": ["name", "preferred_username", "email"],
			"email": ["email", "preferred_username", "upn"],
			"groups": "groups"
		}
	}
}
```

Entra often includes `preferred_username` even when `email` is absent, especially for work accounts. The sample above uses `preferred_username` as a fallback for both username and email so xyOps can still create the local SSO user.

### AWS Cognito Hosted UI

Create or edit a Cognito User Pool app client with Hosted UI or Managed Login enabled.

Cognito setup tips:

- App type: use a user-pool app client for an interactive web app.
- Client secret: enabled is fine and recommended for this plugin, because xyOps runs server-side.
- Callback URLs: add your xyOps Base App URL exactly, with no path. Example: `https://xyops.yourcompany.com`.
- Sign-out URLs or Allowed logout URLs: add the page you want Cognito to redirect to after logout if you use Cognito's logout endpoint.
- OAuth grant types: enable **Authorization code grant**.
- OAuth grant types: disable **Implicit grant**. This plugin does not need tokens returned directly through the browser.
- OAuth grant types: disable **Client credentials** for this app client. Cognito requires client credentials to be the only allowed OAuth flow when it is used, and this plugin needs the code flow.
- OpenID Connect scopes: include `openid`, `profile`, and `email`.
- Custom scopes: only add custom resource-server scopes if you need them. They are not required for basic xyOps login.
- Hosted UI domain: configure a Cognito domain or custom domain. This becomes `oidc.domain`.
- Issuer: use the User Pool issuer, not the Hosted UI domain. See [Cognito issuer versus domain](#cognito-issuer-versus-domain).
- Groups: Cognito user pool groups are typically exposed as `cognito:groups`. Keep that in `claim_map.groups` if you want xyOps group mapping.

#### Cognito References

- [Cognito app client OAuth settings](https://docs.aws.amazon.com/cli/latest/reference/cognito-idp/create-user-pool-client.html)

#### Cognito Issuer vs. Domain

AWS Cognito has two similar-looking values that mean different things:

| Setting | What it is | Example |
|---------|------------|---------|
| `issuer` | Your Cognito User Pool issuer | `https://cognito-idp.us-west-1.amazonaws.com/us-west-1_abcef12345` |
| `domain` | Your Cognito Hosted UI domain | `frogger.auth.us-west-1.amazoncognito.com` |

The `issuer` is built from your AWS region and User Pool ID:

```text
https://cognito-idp.REGION.amazonaws.com/USER_POOL_ID
```

For example, if your User Pool ID is:

```text
us-west-1_abcef12345
```

Then your issuer is:

```json
"issuer": "https://cognito-idp.us-west-1.amazonaws.com/us-west-1_abcef12345"
```

The `domain` is the Hosted UI domain where users are sent to log in:

```json
"domain": "frogger.auth.us-west-1.amazoncognito.com"
```

So a minimal Cognito `oidc` block looks like this:

```json
"oidc": {
	"issuer": "https://cognito-idp.us-west-1.amazonaws.com/us-west-1_abcef12345",
	"domain": "frogger.auth.us-west-1.amazoncognito.com",
	"client_id": "YOUR_COGNITO_CLIENT_ID",
	"client_secret": "YOUR_COGNITO_CLIENT_SECRET",
	"state_secret": "GENERATE_A_LONG_RANDOM_SECRET",
	"scope": "openid profile email"
}
```

#### Cognito Example

```json
{
	"enabled": true,
	"whitelist": false,
	"header_map": {
		"username": "x-forwarded-user",
		"full_name": "x-forwarded-name",
		"email": "x-forwarded-email",
		"groups": "x-forwarded-groups"
	},
	"cleanup_username": true,
	"cleanup_full_name": false,
	"group_role_map": {},
	"group_privilege_map": {},
	"command": "npx -y @pixlcore/xyplug-sso-oidc@1.0.0",
	"oidc": {
		"issuer": "https://cognito-idp.us-west-1.amazonaws.com/us-west-1_abcef12345",
		"domain": "frogger.auth.us-west-1.amazoncognito.com",
		"login_uri": "/login",
		"oauth_uri": "/oauth2/token",
		"userinfo_uri": "/oauth2/userInfo",
		"client_id": "YOUR_COGNITO_CLIENT_ID",
		"client_secret": "YOUR_COGNITO_CLIENT_SECRET",
		"state_secret": "GENERATE_A_LONG_RANDOM_SECRET",
		"scope": "openid profile email",
		"claim_map": {
			"username": ["cognito:username", "preferred_username", "email", "sub"],
			"full_name": ["name", "email"],
			"email": "email",
			"groups": ["cognito:groups", "groups"]
		},
		"userinfo_method": "GET"
	}
}
```

For Cognito, the `issuer` is the User Pool issuer, while `domain` is the Hosted UI domain. Those are deliberately separate in the config.

### SAML via SSOReady

If your customer or company requires SAML, you can use [SSOReady](https://ssoready.com/) as a SAML-to-OIDC bridge. SSOReady handles the SAML side of the integration, and this plugin talks to SSOReady as a generic OIDC provider.

This is useful because xyOps does not need to speak SAML directly. The flow becomes:

1. xyOps launches this plugin.
2. The plugin redirects the user to SSOReady's OAuth/OIDC authorization endpoint.
3. SSOReady redirects the user into the configured SAML IdP.
4. The SAML IdP authenticates the user and sends the SAML response back to SSOReady.
5. SSOReady returns an OIDC authorization code to xyOps.
6. This plugin exchanges the code, validates the ID token, and emits trusted headers for xyOps.

SSOReady setup tips:

- Create a SSOReady environment.
- Create an Organization in SSOReady.
- Set or copy the Organization's `organization_external_id`, for example `acme`.
- Configure your external SAML IdP connection inside that Organization.
- Create a **SAML OAuth Client** in SSOReady.
- Copy the SAML OAuth Client ID. It usually looks like `saml_oauth_client_...`.
- Copy the SAML OAuth Client Secret. It usually looks like `ssoready_oauth_client_secret_...`.
- Add your xyOps Base App URL to the SSOReady **OAuth Redirect URI** field. Example: `https://xyops.yourcompany.com`.
- For this plugin, the callback URL is xyOps `base_app_url` exactly, with no path.

Unlike most OIDC providers, SSOReady needs an organization selector on the authorization URL:

```text
organization_external_id=acme
```

This plugin adds that using `oidc.auth_params`.

SSOReady endpoints:

| Setting | Value |
|---------|-------|
| Issuer | `https://auth.ssoready.com/v1/oauth` |
| Authorization endpoint | `https://auth.ssoready.com/v1/oauth/authorize` |
| Token endpoint | `https://auth.ssoready.com/v1/oauth/token` |
| JWKS URI | `https://auth.ssoready.com/v1/oauth/jwks` |

#### SSOReady References

- [SSOReady](https://ssoready.com/)
- [SSOReady self-hosting](https://ssoready.com/docs/self-hosting-ssoready)

#### SSOReady Example

```json
{
	"enabled": true,
	"whitelist": false,
	"header_map": {
		"username": "x-forwarded-user",
		"full_name": "x-forwarded-name",
		"email": "x-forwarded-email",
		"groups": "x-forwarded-groups"
	},
	"cleanup_username": true,
	"cleanup_full_name": true,
	"group_role_map": {},
	"group_privilege_map": {},
	"command": "npx -y @pixlcore/xyplug-sso-oidc@1.0.0",
	"oidc": {
		"discovery": false,
		"issuer": "https://auth.ssoready.com/v1/oauth",
		"authorization_endpoint": "https://auth.ssoready.com/v1/oauth/authorize",
		"token_endpoint": "https://auth.ssoready.com/v1/oauth/token",
		"jwks_uri": "https://auth.ssoready.com/v1/oauth/jwks",
		"client_id": "YOUR_SSOREADY_SAML_OAUTH_CLIENT_ID",
		"client_secret": "YOUR_SSOREADY_SAML_OAUTH_CLIENT_SECRET",
		"state_secret": "GENERATE_A_LONG_RANDOM_SECRET",
		"scope": "openid profile email",
		"auth_params": {
			"organization_external_id": "acme"
		},
		"claim_map": {
			"username": ["email", "sub"],
			"full_name": ["name", "email", "sub"],
			"email": ["email", "sub"],
			"groups": ["groups", "roles"]
		}
	}
}
```

For many SAML IdPs, the most stable user identifier may appear in `sub`, and the email may or may not also appear in `email`. The example above falls back to `sub` so xyOps can still create a user if SSOReady does not receive a dedicated email attribute from the SAML IdP.

If you need groups, make sure the upstream SAML IdP sends group or role attributes to SSOReady, and verify the resulting ID token claims before configuring xyOps group mappings.

## Header map recommendations

Recommended header map:

```json
"header_map": {
	"username": "x-forwarded-user",
	"full_name": "x-forwarded-name",
	"email": "x-forwarded-email",
	"groups": "x-forwarded-groups"
}
```

Using distinct headers is the cleanest configuration.

You can map multiple xyOps fields to the same header name if you want:

```json
"header_map": {
	"username": "x-forwarded-email",
	"full_name": "x-forwarded-email",
	"email": "x-forwarded-email"
}
```

In that case xyOps can derive the username and display name using `cleanup_username` and `cleanup_full_name`.

## Groups and roles

The plugin emits groups as a delimited string for xyOps. If the OIDC claim is an array like this:

```json
["devops", "platform-admins"]
```

The default emitted header is:

```text
x-forwarded-groups: devops,platform-admins
```

If you configure a custom xyOps separator:

```json
"group_role_separator": "|"
```

The emitted header becomes:

```text
x-forwarded-groups: devops|platform-admins
```

Then map groups to roles or privileges using normal xyOps SSO settings:

```json
"group_privilege_map": {
	"platform-admins": ["admin"]
}
```

## Security notes

- The plugin does not set cookies.
- The plugin does not create xyOps sessions. xyOps handles that after trusted-header login.
- The plugin validates encrypted `state` before exchanging an authorization code.
- The plugin uses PKCE by default.
- The plugin validates the ID token issuer, audience, signature, expiration, and nonce.
- The plugin verifies UserInfo `sub` matches ID token `sub` when both are present.
- The plugin overwrites all trusted headers listed in `header_map`, so spoofed incoming trusted headers do not survive the command response.
- Keep `state_secret`, `client_secret`, and xyOps SSO debug logs private.
- Use HTTPS for xyOps and for all IdP endpoints.

Because this plugin performs authentication itself, `whitelist` is usually set to `false`. There is no trusted proxy IP to whitelist. The plugin is effectively acting as the authentication bridge.

## Logout

This plugin does not manage IdP logout. xyOps clears its own local session cookie when the user logs out. To send the user to your IdP logout page afterwards, configure normal xyOps SSO `logout_url`.

Example:

```json
"logout_url": "https://your-idp.example.com/logout"
```

The exact logout URL is provider-specific.

## Troubleshooting

### Login redirects to the IdP but callback fails

Check:

- the IdP redirect URI exactly matches xyOps `base_app_url`
- the xyOps Base App URL is listed in your IdP application's allowed callback URLs
- `base_app_url` has the correct scheme, host, and port
- `state_secret` has not changed between phase one and phase two
- system clocks are reasonably accurate

### Token validation fails

Check:

- `oidc.issuer`
- `oidc.client_id`
- provider discovery output
- network access from the xyOps conductor to the provider JWKS URI
- `clock_tolerance_seconds` if your hosts have small clock skew

### User is missing email or username

Check:

- requested scopes
- provider claim configuration
- `oidc.claim_map`
- whether the desired fields are in the ID token or UserInfo response

### Groups are missing

Check:

- your IdP is configured to include groups in tokens or UserInfo
- the requested scope includes provider-specific group access
- `oidc.claim_map.groups`
- `group_role_separator`

### Need more debugging output

On the xyOps side:

- set `debug_level` to `9`
- inspect `logs/SSO.log`

On the plugin side:

- set `XYP_SSO_DEBUG=1` in the environment for the xyOps service

xyOps logs raw plugin STDOUT and STDERR at SSO debug level 9. Be careful with these logs in production, because SSO config can contain secrets.

## Local development

To syntax-check the CLI:

```sh
npm test
```

To run it manually with a saved xyOps SSO command payload:

```sh
node index.js < sample-input.json
```

The plugin expects the same XYWP payload that xyOps sends to custom SSO commands.
