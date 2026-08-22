/**
 * GHSA-jxxv-8r27-vm4p — the shipped vm2 CLI provided no sandbox isolation.
 *
 * lib/cli.js ran NodeVM.file(path, { require: { external: true } }) with no root
 * and the default context:'host', so a script passed to `vm2 ./script.js` could
 * `require(__filename)` (or any path) and execute in the host realm — equivalent
 * to `node ./script.js`.
 *
 * Fix: the CLI now bounds requires to the script's directory (root: pa.dirname)
 * and loads them inside the sandbox (context: 'sandbox'). That configuration
 * change is the entire fix for THIS advisory.
 *
 * Scope note: bare `require.external: true` with no root still does NOT throw at
 * construction, and still host-requires any named path. That breadth is the
 * documented meaning of the option and is an accepted residual, warn-only until
 * the next major (deny-by-default is a breaking change). GHSA-j3hm-6rg5-mchv —
 * the nesting-default bypass via requiring vm2 from disk — is itself fixed. The
 * last assertion below pins the no-throw behaviour deliberately; it is a statement
 * of current behaviour, not of safety.
 *
 * Sound oracle: a self-requiring script that would write a host marker file via
 * host fs must not do so under the CLI configuration.
 */

'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { NodeVM } = require('../../../lib/main.js');

// The exact require config lib/cli.js now uses.
function cliRequireConfig(scriptPath) {
	return { external: true, root: path.dirname(scriptPath), context: 'sandbox' };
}

describe('GHSA-jxxv-8r27-vm4p — CLI sandbox isolation', () => {
	it('a self-requiring script cannot reach the host realm under the CLI config', () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vm2-jxxv-'));
		try {
			const marker = path.join(dir, 'HOST_ESCAPED.txt');
			const scriptPath = path.join(dir, 'poc.js');
			fs.writeFileSync(scriptPath, `
				'use strict';
				try { require('fs').writeFileSync(${JSON.stringify(marker)}, 'host pid=' + process.pid); }
				catch (e) { try { require(__filename); } catch (e2) {} }
			`);
			try { NodeVM.file(scriptPath, { require: cliRequireConfig(scriptPath) }); } catch (e) { /* fine */ }
			assert.strictEqual(fs.existsSync(marker), false,
				'script reached host fs — CLI still runs the target in the host realm');
		} finally { fs.rmSync(dir, { recursive: true, force: true }); }
	});

	it('the shipped lib/cli.js uses sandbox context and a bounded root', () => {
		// The jxxv fix is the CLI config, not a construction throw — bind the test to
		// the actual shipped file so a regression that drops either is caught.
		// The doesNotThrow below records that construction with external-and-no-root
		// still succeeds (the still-open GHSA-j3hm-6rg5-mchv hole), NOT that it is safe.
		const cliSrc = fs.readFileSync(path.resolve(__dirname, '../../../lib/cli.js'), 'utf8');
		assert.match(cliSrc, /context:\s*'sandbox'/, 'CLI must load requires in sandbox context');
		assert.match(cliSrc, /root:\s*pa\.dirname/, 'CLI must bound requires to the script directory');
		assert.doesNotThrow(() => new NodeVM({ require: { external: true } }));
	});
});
