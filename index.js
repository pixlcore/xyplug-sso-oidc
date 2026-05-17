#!/usr/bin/env node

'use strict';

const crypto = require('crypto');

const XYWP_VERSION = 1;
const DEFAULT_SCOPE = 'openid profile email';
const DEFAULT_GROUP_SEPARATOR = ',';
const DEFAULT_STATE_TTL = 10 * 60;
const DEFAULT_TIMEOUT_MS = 15000;
const FIELD_PRIORITY = ['email', 'username', 'full_name', 'groups', 'avatar'];

// Emit one XYWP response object to STDOUT, followed by a newline.
function respond(body) {
	process.stdout.write(JSON.stringify(body) + "\n");
}

// Emit a final XYWP error response that xyOps will display to the user.
function respondError(description) {
	respond({
		xy: XYWP_VERSION,
		code: 1,
		description: description || 'Unknown error'
	});
}

// Emit a successful trusted-header response for xyOps to merge into the request.
function respondSuccess(headers) {
	respond({
		xy: XYWP_VERSION,
		code: 0,
		headers
	});
}

// Emit a successful redirect response for the initial OIDC login hop.
function respondRedirect(location) {
	respond({
		xy: XYWP_VERSION,
		code: 0,
		redirect: true,
		headers: {
			Location: location
		}
	});
}

// Write opt-in debug details to STDERR so normal STDOUT stays clean XYWP.
function logDebug(message, data) {
	if (!process.env.XYP_SSO_DEBUG) return;
	const payload = (data === undefined) ? '' : ' ' + JSON.stringify(data);
	process.stderr.write('[xyplug-sso-oidc] ' + message + payload + "\n");
}

// Read the full one-line XYWP payload sent by xyOps on STDIN.
function readStdin() {
	return new Promise(function(resolve, reject) {
		let data = '';
		process.stdin.setEncoding('utf8');
		process.stdin.on('data', function(chunk) { data += chunk; });
		process.stdin.on('end', function() { resolve(data); });
		process.stdin.on('error', reject);
	});
}

// Require a plain object and throw a configuration-style error if missing.
function requireObject(value, name) {
	if (!value || (typeof value !== 'object') || Array.isArray(value)) {
		throw new Error('Missing or invalid object: ' + name);
	}
	return value;
}

// Require a non-empty string and return it trimmed.
function requireString(value, name) {
	if ((typeof value !== 'string') || !value.trim()) {
		throw new Error('Missing required string: ' + name);
	}
	return value.trim();
}

// Return a trimmed string, or an empty string if the value is absent.
function optionalString(value) {
	return ((typeof value === 'string') && value.trim()) ? value.trim() : '';
}

// Normalize a query value that may be a scalar or an array.
function firstQueryValue(value) {
	if (Array.isArray(value)) return value.length ? String(value[0]) : '';
	return (value === undefined || value === null) ? '' : String(value);
}

// Determine whether a claim or setting contains meaningful data.
function hasValue(value) {
	if (value === null || value === undefined) return false;
	if (typeof value === 'string') return !!value.trim();
	if (Array.isArray(value)) return !!value.length;
	return true;
}

// Convert request header names to lowercase for predictable lookup.
function normalizeHeaders(headers) {
	const output = {};
	Object.keys(headers || {}).forEach(function(key) {
		output[String(key).toLowerCase()] = headers[key];
	});
	return output;
}

// Resolve a claim by name, dotted path, or array of fallback paths.
function getPathValue(obj, keyPath) {
	if (!keyPath) return undefined;
	if (Array.isArray(keyPath)) {
		for (const candidate of keyPath) {
			const value = getPathValue(obj, candidate);
			if (hasValue(value)) return value;
		}
		return undefined;
	}
	if (typeof keyPath !== 'string') return undefined;
	if (obj && Object.prototype.hasOwnProperty.call(obj, keyPath)) return obj[keyPath];
	if (!keyPath.includes('.')) return obj ? obj[keyPath] : undefined;
	return keyPath.split('.').reduce(function(accum, key) {
		if ((accum === null) || (accum === undefined)) return undefined;
		return accum[key];
	}, obj);
}

// Return the first meaningful value in a list, or an empty string.
function firstValue(values) {
	for (const value of values) {
		if (hasValue(value)) return value;
	}
	return '';
}

// Build a display name from given_name and family_name claims when available.
function composeName(claims) {
	const given = (claims && claims.given_name) ? String(claims.given_name).trim() : '';
	const family = (claims && claims.family_name) ? String(claims.family_name).trim() : '';
	return (given && family) ? (given + ' ' + family) : '';
}

// Convert group claims into the delimited string format xyOps expects.
function normalizeGroupsForHeader(rawValue, separator) {
	if (!hasValue(rawValue)) return '';
	if (Array.isArray(rawValue)) {
		return rawValue
			.map(function(value) { return String(value).trim(); })
			.filter(Boolean)
			.join(separator || DEFAULT_GROUP_SEPARATOR);
	}
	return String(rawValue).trim();
}

// Choose which xyOps field wins when several fields map to one header.
function chooseFieldForHeader(fields) {
	const sorted = fields.slice().sort(function(a, b) {
		const aidx = FIELD_PRIORITY.indexOf(a);
		const bidx = FIELD_PRIORITY.indexOf(b);
		return (aidx === -1 ? 999 : aidx) - (bidx === -1 ? 999 : bidx);
	});
	return sorted[0];
}

// Reject header values that could smuggle additional HTTP headers.
function assertSafeHeaderValue(value, name) {
	const text = String(value);
	if (text.match(/[\r\n]/)) throw new Error('Unsafe newline found in generated header: ' + name);
	return text;
}

// Derive a fixed-length AES key from the configured state secret.
function makeStateKey(secret) {
	return crypto.createHash('sha256').update(String(secret)).digest();
}

// Encrypt and authenticate the OIDC state payload for stateless redirects.
function sealState(state, secret) {
	const iv = crypto.randomBytes(12);
	const key = makeStateKey(secret);
	const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
	const plaintext = Buffer.from(JSON.stringify(state), 'utf8');
	const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	const tag = cipher.getAuthTag();
	return [
		iv.toString('base64url'),
		ciphertext.toString('base64url'),
		tag.toString('base64url')
	].join('.');
}

// Decrypt, authenticate, parse, and expiration-check the OIDC state payload.
function openState(token, secret) {
	const parts = String(token || '').split('.');
	if (parts.length !== 3) throw new Error('Invalid OIDC state format');
	const iv = Buffer.from(parts[0], 'base64url');
	const ciphertext = Buffer.from(parts[1], 'base64url');
	const tag = Buffer.from(parts[2], 'base64url');
	const key = makeStateKey(secret);
	const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
	decipher.setAuthTag(tag);
	const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
	const state = JSON.parse(plaintext.toString('utf8'));
	const now = Math.floor(Date.now() / 1000);
	if (!state.exp || (now > Number(state.exp))) throw new Error('Expired OIDC state');
	return state;
}

// Generate a URL-safe random string with the requested number of random bytes.
function randomBase64Url(bytes) {
	return crypto.randomBytes(bytes).toString('base64url');
}

// SHA-256 hash a value and encode it for PKCE's S256 challenge format.
function sha256Base64Url(value) {
	return crypto.createHash('sha256').update(String(value)).digest('base64url');
}

// Choose the secret used for state encryption and validate its minimum length.
function getStateSecret(oidc) {
	const secret = optionalString(oidc.state_secret) || optionalString(oidc.client_secret);
	if (!secret) throw new Error('config.oidc.state_secret is required when no client_secret is configured');
	if (secret.length < 16) throw new Error('config.oidc.state_secret must be at least 16 characters');
	return secret;
}

// Normalize the xyOps callback URL to the exact root URL used with the IdP.
function cleanBaseUrl(url) {
	const value = requireString(url, 'input.base_app_url');
	return value.replace(/\?.*$/, '').replace(/#.*$/, '').replace(/\/+$/, '');
}

// Remove trailing slashes so issuer URLs compare reliably.
function normalizeIssuerForCompare(value) {
	return String(value || '').replace(/\/+$/, '');
}

// Construct an HTTPS endpoint URL from a provider domain and URI path.
function makeDomainUrl(domain, uri) {
	const base = String(domain || '').match(/^https?:\/\//) ? String(domain) : ('https://' + String(domain || ''));
	const cleanBase = base.replace(/\/+$/, '');
	const cleanPath = String(uri || '').match(/^\//) ? String(uri) : ('/' + String(uri || ''));
	return cleanBase + cleanPath;
}

// Determine the OIDC discovery URL, unless explicit endpoints are being used.
function getDiscoveryUrl(oidc) {
	if (oidc.discovery_uri) return String(oidc.discovery_uri);
	if (!oidc.issuer) return '';
	return String(oidc.issuer).replace(/\/+$/, '') + '/.well-known/openid-configuration';
}

// Merge discovery metadata with explicit endpoint and Cognito-style overrides.
function applyEndpointOverrides(oidc, discovery) {
	const output = Object.assign({}, discovery || {});
	if (oidc.domain) {
		if (!output.authorization_endpoint) {
			output.authorization_endpoint = makeDomainUrl(oidc.domain, oidc.authorization_uri || oidc.login_uri || '/oauth2/authorize');
		}
		if (!output.token_endpoint) {
			output.token_endpoint = makeDomainUrl(oidc.domain, oidc.token_uri || oidc.oauth_uri || '/oauth2/token');
		}
		if (!output.userinfo_endpoint) {
			output.userinfo_endpoint = makeDomainUrl(oidc.domain, oidc.userinfo_uri || '/oauth2/userInfo');
		}
	}
	['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'issuer'].forEach(function(key) {
		if (oidc[key]) output[key] = oidc[key];
	});
	return output;
}

// Fetch a URL with AbortController so hung IdP calls do not hang xyOps login.
async function fetchWithTimeout(url, options, timeoutMs) {
	const controller = new AbortController();
	const timer = setTimeout(function() { controller.abort(); }, timeoutMs || DEFAULT_TIMEOUT_MS);
	try {
		return await fetch(url, Object.assign({}, options || {}, { signal: controller.signal }));
	}
	finally {
		clearTimeout(timer);
	}
}

// Fetch an HTTP JSON response and turn provider errors into readable failures.
async function fetchJson(url, options, name, timeoutMs) {
	const response = await fetchWithTimeout(url, options, timeoutMs);
	const text = await response.text();
	let json = null;
	try {
		json = text ? JSON.parse(text) : {};
	}
	catch (err) {
		throw new Error((name || 'HTTP request') + ' returned invalid JSON');
	}
	if (!response.ok) {
		const detail = json.error_description || json.error || response.statusText || ('HTTP ' + response.status);
		throw new Error((name || 'HTTP request') + ' failed: ' + detail);
	}
	return json;
}

// Load OIDC provider metadata from discovery and validate required endpoints.
async function loadProviderMetadata(oidc) {
	let discovery = {};
	const timeoutMs = oidc.request_timeout_ms || DEFAULT_TIMEOUT_MS;
	const discoveryUrl = getDiscoveryUrl(oidc);
	if (discoveryUrl && (oidc.discovery !== false)) {
		discovery = await fetchJson(discoveryUrl, { method: 'GET' }, 'OIDC discovery', timeoutMs);
	}
	const provider = applyEndpointOverrides(oidc, discovery);
	if (oidc.issuer && provider.issuer && (oidc.validate_issuer !== false)) {
		if (normalizeIssuerForCompare(provider.issuer) !== normalizeIssuerForCompare(oidc.issuer)) {
			throw new Error('OIDC discovery issuer does not match config.oidc.issuer');
		}
	}
	requireString(provider.authorization_endpoint, 'config.oidc.authorization_endpoint');
	requireString(provider.token_endpoint, 'config.oidc.token_endpoint');
	if (oidc.require_id_token !== false) requireString(provider.jwks_uri, 'config.oidc.jwks_uri');
	return provider;
}

// Add administrator-supplied authorization request parameters to the redirect.
function addAuthParams(url, oidc) {
	const params = oidc.auth_params || {};
	Object.keys(params).forEach(function(key) {
		if (params[key] === undefined || params[key] === null) return;
		url.searchParams.set(key, String(params[key]));
	});
}

// Build the IdP authorization URL for phase one of the SSO flow.
async function buildLoginRedirect(hook, oidc, provider) {
	const now = Math.floor(Date.now() / 1000);
	const redirectUri = cleanBaseUrl(oidc.redirect_uri || hook.base_app_url);
	const usePkce = (oidc.use_pkce !== false);
	const codeVerifier = usePkce ? randomBase64Url(32) : '';
	const nonce = randomBase64Url(24);
	const stateSecret = getStateSecret(oidc);
	const state = sealState({
		iat: now,
		exp: now + (oidc.state_ttl_seconds || DEFAULT_STATE_TTL),
		nonce,
		code_verifier: codeVerifier,
		redirect_uri: redirectUri
	}, stateSecret);
	const url = new URL(provider.authorization_endpoint);
	url.searchParams.set('response_type', 'code');
	url.searchParams.set('client_id', requireString(oidc.client_id, 'config.oidc.client_id'));
	url.searchParams.set('redirect_uri', redirectUri);
	url.searchParams.set('scope', oidc.scope || DEFAULT_SCOPE);
	url.searchParams.set('state', state);
	url.searchParams.set('nonce', nonce);
	if (usePkce) {
		url.searchParams.set('code_challenge_method', 'S256');
		url.searchParams.set('code_challenge', sha256Base64Url(codeVerifier));
	}
	addAuthParams(url, oidc);
	logDebug('Redirecting to OIDC authorization endpoint', { id: hook.id, endpoint: provider.authorization_endpoint });
	return url.toString();
}

// Build the standard authorization-code token request form body.
function buildTokenRequestBody(hook, oidc, state) {
	const body = new URLSearchParams();
	body.set('grant_type', 'authorization_code');
	body.set('code', firstQueryValue(hook.query.code));
	body.set('redirect_uri', state.redirect_uri);
	body.set('client_id', requireString(oidc.client_id, 'config.oidc.client_id'));
	if (state.code_verifier) body.set('code_verifier', state.code_verifier);
	return body;
}

// Build token endpoint headers and body based on the client auth method.
function buildTokenRequestHeadersAndBody(hook, oidc, state) {
	const method = oidc.token_endpoint_auth_method || (oidc.client_secret ? 'client_secret_basic' : 'none');
	const body = buildTokenRequestBody(hook, oidc, state);
	const headers = {
		'Accept': 'application/json',
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	if (method === 'client_secret_basic') {
		const clientId = requireString(oidc.client_id, 'config.oidc.client_id');
		const clientSecret = requireString(oidc.client_secret, 'config.oidc.client_secret');
		body.delete('client_id');
		headers.Authorization = 'Basic ' + Buffer.from(clientId + ':' + clientSecret, 'utf8').toString('base64');
	}
	else if (method === 'client_secret_post') {
		body.set('client_secret', requireString(oidc.client_secret, 'config.oidc.client_secret'));
	}
	else if (method !== 'none') {
		throw new Error('Unsupported config.oidc.token_endpoint_auth_method: ' + method);
	}
	return { headers, body };
}

// Exchange the callback authorization code for OIDC tokens.
async function exchangeCodeForTokens(hook, oidc, provider, state) {
	const request = buildTokenRequestHeadersAndBody(hook, oidc, state);
	return await fetchJson(provider.token_endpoint, {
		method: 'POST',
		headers: request.headers,
		body: request.body
	}, 'OIDC token exchange', oidc.request_timeout_ms || DEFAULT_TIMEOUT_MS);
}

// Validate the ID token signature and core claims using the provider JWKS.
async function verifyIdToken(oidc, provider, idToken, state) {
	if (!idToken) {
		if (oidc.require_id_token === false) return {};
		throw new Error('OIDC token response did not include an id_token');
	}
	const jose = await import('jose');
	const jwks = jose.createRemoteJWKSet(new URL(requireString(provider.jwks_uri, 'provider.jwks_uri')), {
		timeoutDuration: oidc.request_timeout_ms || DEFAULT_TIMEOUT_MS
	});
	const options = {
		issuer: oidc.issuer || provider.issuer,
		audience: requireString(oidc.client_id, 'config.oidc.client_id')
	};
	if (oidc.clock_tolerance_seconds !== undefined) options.clockTolerance = Number(oidc.clock_tolerance_seconds);
	if (Array.isArray(oidc.signing_algorithms) && oidc.signing_algorithms.length) options.algorithms = oidc.signing_algorithms;
	const result = await jose.jwtVerify(idToken, jwks, options);
	if (state.nonce && (result.payload.nonce !== state.nonce)) {
		throw new Error('OIDC id_token nonce did not match state');
	}
	return result.payload || {};
}

// Fetch standard OIDC UserInfo claims using the access token.
async function fetchUserInfo(oidc, provider, accessToken) {
	if (!accessToken || !provider.userinfo_endpoint || (oidc.fetch_userinfo === false)) return {};
	const method = String(oidc.userinfo_method || 'GET').toUpperCase();
	const options = {
		method,
		headers: {
			'Accept': 'application/json',
			'Authorization': 'Bearer ' + accessToken
		}
	};
	if (method === 'POST') {
		options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
		options.body = new URLSearchParams();
	}
	return await fetchJson(provider.userinfo_endpoint, options, 'OIDC userinfo', oidc.request_timeout_ms || DEFAULT_TIMEOUT_MS);
}

// Resolve one xyOps field from the configured claim map and fallback claims.
function resolveClaim(claims, claimMap, field, fallback) {
	const mapped = getPathValue(claims, claimMap[field]);
	if (hasValue(mapped)) return mapped;
	if (hasValue(fallback)) return getPathValue(claims, fallback);
	return undefined;
}

// Resolve the xyOps username from preferred claims in stable order.
function resolveUsername(claims, claimMap) {
	return firstValue([
		resolveClaim(claims, claimMap, 'username'),
		resolveClaim(claims, claimMap, 'preferred_username', 'preferred_username'),
		resolveClaim(claims, claimMap, 'email', 'email'),
		resolveClaim(claims, claimMap, 'sub', 'sub')
	]);
}

// Resolve the xyOps display name from OIDC profile claims.
function resolveFullName(claims, claimMap) {
	return firstValue([
		resolveClaim(claims, claimMap, 'full_name', 'name'),
		composeName(claims),
		resolveClaim(claims, claimMap, 'preferred_username', 'preferred_username'),
		resolveClaim(claims, claimMap, 'email', 'email'),
		resolveUsername(claims, claimMap)
	]);
}

// Resolve the xyOps email field from OIDC claims.
function resolveEmail(claims, claimMap) {
	return firstValue([
		resolveClaim(claims, claimMap, 'email', 'email'),
		resolveUsername(claims, claimMap)
	]);
}

// Resolve an optional avatar URL from common profile image claims.
function resolveAvatar(claims, claimMap) {
	return firstValue([
		resolveClaim(claims, claimMap, 'avatar', ['picture', 'avatar', 'avatar_url'])
	]);
}

// Build the exact trusted headers that xyOps will consume for SSO login.
function buildInjectedHeaders(hook, claims) {
	const config = requireObject(hook.config, 'input.config');
	const oidc = requireObject(config.oidc, 'config.oidc');
	const headerMap = requireObject(config.header_map, 'config.header_map');
	const claimMap = (oidc.claim_map && (typeof oidc.claim_map === 'object')) ? oidc.claim_map : {};
	const separator = config.group_role_separator || DEFAULT_GROUP_SEPARATOR;
	const fieldValues = {
		username: resolveUsername(claims, claimMap),
		full_name: resolveFullName(claims, claimMap),
		email: resolveEmail(claims, claimMap),
		groups: normalizeGroupsForHeader(resolveClaim(claims, claimMap, 'groups', ['groups', 'roles']), separator),
		avatar: resolveAvatar(claims, claimMap)
	};

	// Support custom xyOps header_map fields by resolving matching claim names.
	Object.keys(headerMap).forEach(function(field) {
		if (fieldValues[field] !== undefined) return;
		fieldValues[field] = firstValue([
			resolveClaim(claims, claimMap, field, field)
		]);
	});

	const headerToFields = {};
	Object.keys(headerMap).forEach(function(field) {
		const headerName = headerMap[field];
		if (!headerName) return;
		const normalized = String(headerName).toLowerCase();
		if (!headerToFields[normalized]) headerToFields[normalized] = [];
		headerToFields[normalized].push(field);
	});

	// Start every mapped trusted header as blank. This overwrites any spoofed
	// incoming trusted headers before xyOps performs its normal SSO processing.
	const headers = {};
	Object.keys(headerToFields).forEach(function(headerName) {
		headers[headerName] = '';
		const fields = headerToFields[headerName];
		const chosenField = chooseFieldForHeader(fields);
		let value = fieldValues[chosenField];
		if (!hasValue(value)) {
			for (const field of fields) {
				if (hasValue(fieldValues[field])) {
					value = fieldValues[field];
					break;
				}
			}
		}
		if (hasValue(value)) headers[headerName] = assertSafeHeaderValue(value, headerName);
	});

	const usernameHeader = String(headerMap.username || '').toLowerCase();
	const emailHeader = String(headerMap.email || '').toLowerCase();
	if (!usernameHeader) throw new Error('config.header_map.username is required');
	if (!emailHeader) throw new Error('config.header_map.email is required');
	if (!hasValue(headers[usernameHeader])) throw new Error('Unable to resolve username from OIDC claims');
	if (!hasValue(headers[emailHeader])) throw new Error('Unable to resolve email from OIDC claims');

	return headers;
}

// Handle phase two by validating state, exchanging code, and mapping claims.
async function handleCallback(hook, oidc, provider) {
	if (hook.query.error) {
		const error = firstQueryValue(hook.query.error);
		const description = firstQueryValue(hook.query.error_description);
		throw new Error('OIDC authorization failed: ' + (description || error));
	}
	const code = firstQueryValue(hook.query.code);
	if (!code) throw new Error('OIDC callback is missing code');
	const stateToken = firstQueryValue(hook.query.state);
	if (!stateToken) throw new Error('OIDC callback is missing state');

	const state = openState(stateToken, getStateSecret(oidc));
	const expectedRedirectUri = cleanBaseUrl(oidc.redirect_uri || hook.base_app_url);
	if (state.redirect_uri !== expectedRedirectUri) throw new Error('OIDC state redirect_uri did not match this request');

	const tokens = await exchangeCodeForTokens(hook, oidc, provider, state);
	const idClaims = await verifyIdToken(oidc, provider, tokens.id_token, state);
	const userInfo = await fetchUserInfo(oidc, provider, tokens.access_token);
	if (idClaims.sub && userInfo.sub && (String(idClaims.sub) !== String(userInfo.sub))) {
		throw new Error('OIDC userinfo sub did not match id_token sub');
	}

	const claims = Object.assign({}, idClaims, userInfo, {
		id_token: idClaims,
		userinfo: userInfo
	});
	const headers = buildInjectedHeaders(hook, claims);
	logDebug('Generated trusted headers from OIDC claims', {
		id: hook.id,
		sub: claims.sub || '',
		headers: Object.keys(headers)
	});
	return headers;
}

// Route a single xyOps SSO command request through phase one or phase two.
async function run(hook) {
	if (!hook || (typeof hook !== 'object')) throw new Error('Missing XYWP input payload');
	if (hook.xy !== XYWP_VERSION) throw new Error('Unsupported XYWP version: ' + String(hook.xy || ''));
	if (hook.type !== 'sso') throw new Error('Unsupported XYWP type: ' + String(hook.type || ''));

	hook.headers = normalizeHeaders(hook.headers || {});
	hook.query = hook.query || {};
	const config = requireObject(hook.config, 'input.config');
	const oidc = requireObject(config.oidc, 'config.oidc');
	requireObject(config.header_map, 'config.header_map');
	requireString(oidc.client_id, 'config.oidc.client_id');

	const provider = await loadProviderMetadata(oidc);
	if (hook.query.error || hook.query.code) {
		return {
			redirect: false,
			headers: await handleCallback(hook, oidc, provider)
		};
	}
	return {
		redirect: true,
		location: await buildLoginRedirect(hook, oidc, provider)
	};
}

// CLI entry point: read XYWP input, execute the flow, and emit XYWP output.
async function main() {
	try {
		const raw = (await readStdin()).trim();
		if (!raw) return respondError('No XYWP input found on STDIN');
		const hook = JSON.parse(raw);
		const result = await run(hook);
		if (result.redirect) return respondRedirect(result.location);
		return respondSuccess(result.headers);
	}
	catch (err) {
		logDebug('Fatal plugin error', { error: err.message || String(err) });
		return respondError(err.message || String(err));
	}
}

if (require.main === module) {
	main();
}
else {
	module.exports = {
		run,
		buildInjectedHeaders,
		normalizeGroupsForHeader,
		sealState,
		openState,
		loadProviderMetadata,
		buildLoginRedirect,
		buildTokenRequestHeadersAndBody
	};
}
