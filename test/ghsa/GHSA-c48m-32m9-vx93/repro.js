/**
 * GHSA-c48m-32m9-vx93 — NodeVM external-package allowlist bypass via an
 * unanchored bare-specifier matcher.
 *
 * ## Vulnerability
 * With `require: { external: ['left-pad'], resolve, context: 'host' }`,
 * `LegacyResolver.customResolve` gates whether a bare specifier is handed to
 * the custom resolver by testing it against `externalCache` — regexes built
 * from `makeExternalMatcherRegex(pattern)` with NO anchors. So `left-pad`
 * compiles to `/left\-pad/`, which matches `evil-left-pad`, `left-pad-evil`,
 * `xleft-padx`, etc. as a SUBSTRING. A colliding host package whose name merely
 * contains the allowlisted string is therefore located by the resolver and its
 * top-level code runs in host context — a host-realm escape from the sandbox's
 * external-module allowlist.
 *
 * ## Fix
 * `lib/resolver-compat.js`: anchor the `externalCache` matcher so a bare
 * specifier matches only the allowlisted package name exactly, optionally
 * followed by a subpath — `^(?:<pattern>)(?:[\\/].*)?$`. Wildcards in the
 * pattern (`*` / `**`) keep their meaning; substring collisions no longer pass.
 *
 * ## Sound oracle
 * The custom resolver records which specifiers it is consulted for. Consultation
 * for a colliding name proves the allowlist pre-check passed. After the fix the
 * resolver is consulted only for the allowlisted name and its subpaths.
 */

'use strict';

const assert = require('assert');
const { NodeVM } = require('../../../lib/main.js');

function consultedFor(specifiers) {
	const consulted = [];
	const vm = new NodeVM({
		require: {
			external: ['left-pad'],
			resolve: moduleName => { consulted.push(moduleName); return undefined; },
			context: 'host',
		},
	});
	for (const spec of specifiers) {
		try { vm.run(`require(${JSON.stringify(spec)})`); } catch (e) { /* module-not-found is fine */ }
	}
	return consulted;
}

describe('GHSA-c48m-32m9-vx93 (external allowlist unanchored bare-specifier matcher)', function () {
	it('does not consult the resolver for substring-colliding package names', function () {
		const consulted = consultedFor(['evil-left-pad', 'left-pad-evil', 'xleft-padx', 'left-padx']);
		assert.deepStrictEqual(consulted, [], 'colliding specifiers passed the allowlist pre-check: ' + JSON.stringify(consulted));
	});

	it('still consults the resolver for the allowlisted name and its subpaths', function () {
		const consulted = consultedFor(['left-pad', 'left-pad/index.js', 'left-pad/lib/x']);
		assert.deepStrictEqual(
			consulted,
			['left-pad', 'left-pad/index.js', 'left-pad/lib/x'],
			'the allowlisted package or a legitimate subpath was wrongly denied: ' + JSON.stringify(consulted),
		);
	});

	it('does not consult the resolver for `..` traversal subpaths of an allowlisted name', function () {
		// The anchored matcher permits `left-pad/<subpath>`, but a subpath carrying
		// `..` segments resolves to an un-allowlisted sibling package. Such specifiers
		// must be rejected before the custom resolver is consulted.
		const consulted = consultedFor([
			'left-pad/../evil-package',
			'left-pad/sub/../../evil-package',
			'left-pad/a/b/../../../evil-package',
			'left-pad/..',
		]);
		assert.deepStrictEqual(consulted, [], 'a `..` traversal specifier reached the resolver: ' + JSON.stringify(consulted));
	});

	it('wildcard allowlist entries still match by segment, not substring', function () {
		const consulted = [];
		const vm = new NodeVM({
			require: {
				external: ['@scope/*'],
				resolve: moduleName => { consulted.push(moduleName); return undefined; },
				context: 'host',
			},
		});
		for (const spec of ['@scope/pkg', '@scope/pkg/sub', 'x@scope/pkg', '@scope-evil/pkg']) {
			try { vm.run(`require(${JSON.stringify(spec)})`); } catch (e) {}
		}
		assert.deepStrictEqual(consulted, ['@scope/pkg', '@scope/pkg/sub'], 'wildcard matched a substring collision: ' + JSON.stringify(consulted));
	});
});
