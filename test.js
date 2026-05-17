#!/usr/bin/env node

'use strict';

const assert = require('assert');
const plugin = require('./index.js');

// Verify encrypted OIDC state survives a valid round trip and rejects tampering.
function testStateRoundTrip() {
	const secret = '0123456789abcdef0123456789abcdef';
	const state = {
		exp: Math.floor(Date.now() / 1000) + 60,
		nonce: 'nonce-value',
		code_verifier: 'verifier-value',
		redirect_uri: 'https://xyops.example.com'
	};
	const sealed = plugin.sealState(state, secret);
	const opened = plugin.openState(sealed, secret);
	assert.strictEqual(opened.nonce, state.nonce);
	assert.strictEqual(opened.code_verifier, state.code_verifier);
	assert.strictEqual(opened.redirect_uri, state.redirect_uri);
	assert.throws(function() {
		plugin.openState(sealed, 'different-secret-value');
	});
}

// Verify OIDC claims map cleanly into the configured xyOps trusted headers.
function testHeaderMapping() {
	const headers = plugin.buildInjectedHeaders({
		config: {
			header_map: {
				username: 'x-forwarded-user',
				full_name: 'x-forwarded-name',
				email: 'x-forwarded-email',
				groups: 'x-forwarded-groups',
				avatar: 'x-forwarded-avatar'
			},
			group_role_separator: '|',
			oidc: {
				claim_map: {
					username: ['preferred_username', 'email'],
					full_name: 'name',
					email: 'email',
					groups: ['groups', 'roles'],
					avatar: 'picture'
				}
			}
		}
	}, {
		preferred_username: 'joseph',
		name: 'Joseph Huckaby',
		email: 'joseph@example.com',
		groups: ['devops', 'admins'],
		picture: 'https://example.com/avatar.png'
	});
	assert.deepStrictEqual(headers, {
		'x-forwarded-user': 'joseph',
		'x-forwarded-name': 'Joseph Huckaby',
		'x-forwarded-email': 'joseph@example.com',
		'x-forwarded-groups': 'devops|admins',
		'x-forwarded-avatar': 'https://example.com/avatar.png'
	});
}

// Verify optional mapped trusted headers are blanked to defeat spoofed input.
function testSpoofedMappedHeadersAreBlanked() {
	const headers = plugin.buildInjectedHeaders({
		config: {
			header_map: {
				username: 'x-forwarded-email',
				full_name: 'x-forwarded-email',
				email: 'x-forwarded-email',
				groups: 'x-forwarded-groups'
			},
			oidc: {
				claim_map: {
					email: 'email'
				}
			}
		}
	}, {
		email: 'user@example.com'
	});
	assert.strictEqual(headers['x-forwarded-email'], 'user@example.com');
	assert.strictEqual(headers['x-forwarded-groups'], '');
}

// Verify URL-style Auth0 claim names are treated as exact keys, not paths.
function testNamespacedClaimMapping() {
	const headers = plugin.buildInjectedHeaders({
		config: {
			header_map: {
				username: 'x-forwarded-user',
				email: 'x-forwarded-email',
				groups: 'x-forwarded-groups'
			},
			oidc: {
				claim_map: {
					username: 'email',
					email: 'email',
					groups: 'https://yourcompany.example/groups'
				}
			}
		}
	}, {
		email: 'user@example.com',
		'https://yourcompany.example/groups': ['operators']
	});
	assert.strictEqual(headers['x-forwarded-groups'], 'operators');
}

// Verify client_secret_basic sends credentials only in the Authorization header.
function testBasicTokenAuthDoesNotDuplicateClientId() {
	const request = plugin.buildTokenRequestHeadersAndBody({
		query: {
			code: 'abc123'
		}
	}, {
		client_id: 'client-id',
		client_secret: 'client-secret',
		token_endpoint_auth_method: 'client_secret_basic'
	}, {
		redirect_uri: 'https://xyops.example.com',
		code_verifier: 'verifier'
	});
	assert.ok(request.headers.Authorization.match(/^Basic /));
	assert.strictEqual(request.body.get('client_id'), null);
	assert.strictEqual(request.body.get('client_secret'), null);
	assert.strictEqual(request.body.get('code'), 'abc123');
}

// Verify client_secret_post sends both client credentials in the POST body.
function testPostTokenAuthIncludesClientCredentialsInBody() {
	const request = plugin.buildTokenRequestHeadersAndBody({
		query: {
			code: 'abc123'
		}
	}, {
		client_id: 'client-id',
		client_secret: 'client-secret',
		token_endpoint_auth_method: 'client_secret_post'
	}, {
		redirect_uri: 'https://xyops.example.com'
	});
	assert.strictEqual(request.headers.Authorization, undefined);
	assert.strictEqual(request.body.get('client_id'), 'client-id');
	assert.strictEqual(request.body.get('client_secret'), 'client-secret');
}

testStateRoundTrip();
testHeaderMapping();
testSpoofedMappedHeadersAreBlanked();
testNamespacedClaimMapping();
testBasicTokenAuthDoesNotDuplicateClientId();
testPostTokenAuthIncludesClientCredentialsInBody();

console.log('All tests passed.');
