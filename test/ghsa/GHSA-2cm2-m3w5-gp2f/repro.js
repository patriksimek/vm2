'use strict';

/**
 * GHSA-2cm2-m3w5-gp2f — Bracket-access bypass of GHSA-wp5r-2gw5-m7q7
 *
 * ## Vulnerability
 * GHSA-wp5r-2gw5-m7q7 closed the transformer fast-path bypass that allowed
 * sandboxed code to reach `VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL`
 * as a bare identifier. The transformer's AST walker rejects identifiers with
 * that name and instruments `with(...)` heads. But the internal state was still
 * defined as a non-enumerable own property of `globalThis`, so attacker code
 * could read it via any computed-property path: bracket access, `Reflect.get`,
 * `Object.getOwnPropertyDescriptor`, or by enumerating `Object.getOwnPropertyNames(globalThis)`.
 *
 * The transformer-level filter is a syntactic control. It cannot see through
 * `globalThis['VM2_...']` because that is just a string-keyed property read —
 * the AST walker has no way to evaluate the dynamic key, and tightening the
 * regex to forbid the literal substring would still miss `'VM2' + '_INTERNAL_…'`,
 * `String.fromCharCode(...)`, base64-decoded keys, etc.
 *
 * ## Fix
 * Structural: do not expose the internal state on `globalThis` at all. Each
 * user script is wrapped with a small prologue that pulls the state into a
 * Script-scope `let` binding via a per-call random token, then deletes that
 * token from `globalThis` before user code runs. The transformer-emitted
 * identifier reference (`VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL`)
 * resolves to the `let` binding, which lives in the Script's lexical record
 * and is NOT reachable from `globalThis[…]`. After the prologue executes,
 * `globalThis['VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL']` is
 * `undefined`, and the per-call token has been deleted.
 *
 * This eliminates the entire class of computed-key bypasses: bracket access,
 * Reflect, descriptor probing, and own-property enumeration all return
 * `undefined` / no entry, because the state is genuinely not on `globalThis`.
 */

const assert = require('assert');
const { VM, NodeVM } = require('../../../lib/main.js');

const STATE_NAME = 'VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL';

function expectUnreachable(result, label) {
	// State exposes wrapWith / handleException / import — any of those means
	// the attacker reached it. `undefined` is the success state.
	if (result == null) return;
	if (typeof result === 'object' || typeof result === 'function') {
		const keys = Object.keys(result);
		assert.fail(`${label}: internal state leaked. typeof=${typeof result}, keys=${JSON.stringify(keys)}`);
	}
}

describe('GHSA-2cm2-m3w5-gp2f (bracket access to internal state)', function () {
	describe('VM', function () {
		it('PoC: globalThis["VM2_…"] returns undefined', function () {
			const result = new VM().run(`globalThis['${STATE_NAME}']`);
			expectUnreachable(result, 'globalThis bracket access');
			assert.strictEqual(result, undefined);
		});

		it('string concatenation bracket access returns undefined', function () {
			const result = new VM().run(`globalThis['VM2_INTERNAL_STATE' + '_DO_NOT_USE_OR_PROGRAM_WILL_FAIL']`);
			expectUnreachable(result, 'string-concat bracket access');
			assert.strictEqual(result, undefined);
		});

		it('Reflect.get returns undefined', function () {
			const result = new VM().run(`Reflect.get(globalThis, '${STATE_NAME}')`);
			expectUnreachable(result, 'Reflect.get');
			assert.strictEqual(result, undefined);
		});

		it('Object.getOwnPropertyDescriptor returns undefined', function () {
			const result = new VM().run(`Object.getOwnPropertyDescriptor(globalThis, '${STATE_NAME}')`);
			assert.strictEqual(result, undefined);
		});

		it('Object.getOwnPropertyNames does not expose the state name', function () {
			const result = new VM().run(
				`Object.getOwnPropertyNames(globalThis).filter(n => n.includes('VM2_INTERNAL'))`,
			);
			assert.deepStrictEqual(result, []);
		});

		it('this[name] at top level returns undefined', function () {
			const result = new VM().run(`this['${STATE_NAME}']`);
			expectUnreachable(result, 'this[name]');
			assert.strictEqual(result, undefined);
		});

		it('eval-built name returns undefined', function () {
			const result = new VM().run(
				`globalThis[String.fromCharCode(86,77,50,95) + 'INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL']`,
			);
			expectUnreachable(result, 'fromCharCode-built key');
			assert.strictEqual(result, undefined);
		});

		it('eval can not see the state either', function () {
			const result = new VM().run(`eval("globalThis['${STATE_NAME}']")`);
			expectUnreachable(result, 'eval bracket access');
			assert.strictEqual(result, undefined);
		});

		it('Function constructor body can not see the state', function () {
			// Note: Function constructor is allowed by default; this verifies the
			// state does not appear on globalThis when accessed from a freshly
			// built function body.
			const result = new VM().run(`Function("return globalThis['${STATE_NAME}']")()`);
			expectUnreachable(result, 'Function constructor bracket access');
			assert.strictEqual(result, undefined);
		});

		it('regression: transformer-instrumented try/catch still works', function () {
			// The transformer emits `e = VM2_…HANDLE.handleException(e)` inside
			// catch blocks. With the state moved off globalThis, this only works
			// because the per-script wrapper re-binds it as a Script-scope let.
			const result = new VM().run(`try { throw new Error('boom'); } catch(e) { e.message }`);
			assert.strictEqual(result, 'boom');
		});

		it('regression: transformer-instrumented with(...) still works', function () {
			const result = new VM().run(`var captured; with({foo: 7}) { captured = foo; } captured`);
			assert.strictEqual(result, 7);
		});

		it('regression: import() in source is rewritten to throw', function () {
			assert.throws(function () {
				new VM().run(`import('fs')`);
			});
		});

		it('regression: bare-identifier access still rejected', function () {
			assert.throws(function () {
				new VM().run(`var x = ${STATE_NAME}; x`);
			}, /Use of internal vm2 state variable/);
		});

		it('regression: multiple sequential vm.run() calls still work', function () {
			const vm = new VM();
			assert.strictEqual(vm.run(`1 + 2`), 3);
			assert.strictEqual(vm.run(`try { throw new Error('a'); } catch(e) { e.message }`), 'a');
			assert.strictEqual(vm.run(`globalThis['${STATE_NAME}']`), undefined);
			assert.strictEqual(vm.run(`try { throw new Error('b'); } catch(e) { e.message }`), 'b');
		});

		it('regression: VMScript (cached compile) still works', function () {
			const { VMScript } = require('../../../lib/main.js');
			const script = new VMScript(`try { throw new Error('s'); } catch(e) { e.message }`);
			const vm = new VM();
			assert.strictEqual(vm.run(script), 's');
			assert.strictEqual(vm.run(script), 's'); // cached path
		});
	});

	describe('NodeVM', function () {
		it('PoC: globalThis["VM2_…"] returns undefined inside NodeVM module', function () {
			const result = new NodeVM().run(`module.exports = globalThis['${STATE_NAME}']`);
			expectUnreachable(result, 'NodeVM bracket access');
			assert.strictEqual(result, undefined);
		});

		it('regression: NodeVM try/catch still works', function () {
			const result = new NodeVM().run(
				`module.exports = (() => { try { throw new Error('n'); } catch(e) { return e.message; } })()`,
			);
			assert.strictEqual(result, 'n');
		});
	});
});
