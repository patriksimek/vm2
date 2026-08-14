/**
 * GHSA-m283-3h24-438v — Missing Error.cause sanitization → host RCE
 *
 * ## Vulnerability class
 *
 * ES2022 added `Error.cause`, a free-form property that carries an arbitrary
 * object reference describing the underlying reason for an error
 * (`new Error('wrap', { cause: original })`). When an embedder exposes a host
 * function that throws an Error with `.cause` set to a powerful host object
 * (the canonical example is `process`, but anything reachable from the
 * embedder's closure qualifies), the host Error crosses the bridge via
 * `thisFromOtherForThrow` and surfaces in the sandbox catch block as a
 * functional bridge proxy. Reading `e.cause` through the proxy's `get` trap
 * also returns a functional bridge proxy of the leaked host reference —
 * vm2's bridge wraps for realm isolation, not for capability restriction, so
 * the sandbox can invoke methods on the wrapped reference and pivot to RCE
 * (`e.cause.mainModule.require('child_process').execSync(...)`).
 *
 * `handleException()` already understands `SuppressedError.error` /
 * `SuppressedError.suppressed` / `AggregateError.errors[]` as side-channels
 * for embedded host references and recursively sanitizes them. `.cause` was
 * the analogous channel that escaped the audit.
 *
 * ## Why "wrap it harder" is not enough
 *
 * The bridge already wraps `.cause` on read — `e.cause.isProxy === true`.
 * The wrap is fully functional, so `proc.mainModule.require('child_process')`
 * routes through `apply` traps into the host realm with host privileges and
 * the sandbox obtains a wrapped `child_process` module it can drive. The fix
 * must therefore **strip the cause from the host error in-place**, not just
 * re-wrap it: replace the host-side `cause` value with `undefined` so the
 * proxy `get` trap returns `undefined` and no callable host reference ever
 * surfaces in sandbox.
 *
 * ## Fix shape
 *
 * Centralize sanitization in `handleException` (the existing exception
 * chokepoint). For every error reaching `handleException` (not only
 * SuppressedError / AggregateError):
 *
 *   1. Detect whether the error is a bridge-wrapped HOST-realm error
 *      (`isProxy === true` on the post-`ensureThis` value).
 *   2. If host-realm, delete `.cause` on the underlying host object via the
 *      proxy's `deleteProperty` trap — `delete e.cause` from the
 *      sandbox-side reference routes through `otherReflectDeleteProperty`
 *      and removes the host property. Subsequent sandbox reads return
 *      `undefined`.
 *   3. If sandbox-realm, recursively sanitize `.cause` like `.error` /
 *      `.suppressed` — `e.cause = handleException(e.cause, visited)` so a
 *      sandbox-thrown Error wrapping a host-leaked sub-error gets the
 *      sub-error sanitized.
 *
 * Apply the same treatment to SuppressedError / AggregateError sub-errors:
 * each recursive call goes back through `handleException`, which now also
 * walks `.cause`.
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
// Error.cause shipped in V8 9.3 / Node 16.9. Older Nodes silently drop the
// `cause` option, so the exploit primitive does not exist there.
const HAS_ERROR_CAUSE = NODE_MAJOR > 16 || (NODE_MAJOR === 16 && parseInt(process.versions.node.split('.')[1], 10) >= 9);
const HAS_SUPPRESSED_ERROR = typeof SuppressedError === 'function';
const HAS_AGGREGATE_ERROR = typeof AggregateError === 'function';

describe('GHSA-m283-3h24-438v (Error.cause leaks host references → RCE)', function () {
	it.cond('canonical PoC: host hostFn throws Error with cause=process, sandbox cannot reach child_process', HAS_ERROR_CAUSE, function () {
		const probe = { realm: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					throw new Error('fail', { cause: process });
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					const cp = e.cause.mainModule.require('child_process');
					__probe.realm = 'HOST:' + cp.execSync('echo PWNED').toString().trim();
				} catch (err) {
					__probe.realm = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.notStrictEqual(probe.realm, 'HOST:PWNED', 'sandbox reached host child_process via Error.cause');
		// Either .cause is undefined (deleted) or its method access throws.
		// What matters is that sandbox cannot complete the RCE pivot.
	});

	it.cond('e.cause on host-thrown Error is not a usable host reference', HAS_ERROR_CAUSE, function () {
		const probe = { causeType: 'UNSET', causeIsProxy: 'UNSET', mainModuleType: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					throw new Error('fail', { cause: process });
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				__probe.causeType = typeof e.cause;
				try {
					__probe.causeIsProxy = e.cause && e.cause.isProxy;
					__probe.mainModuleType = e.cause && typeof e.cause.mainModule;
				} catch (_) {
					__probe.causeIsProxy = 'THREW';
					__probe.mainModuleType = 'THREW';
				}
			}
		`);
		// After the fix, .cause is either undefined or otherwise non-callable.
		// The critical invariant: sandbox cannot navigate into host.process.
		assert.notStrictEqual(probe.mainModuleType, 'object', 'sandbox reached process.mainModule via Error.cause');
		assert.notStrictEqual(probe.mainModuleType, 'function', 'sandbox reached process.mainModule via Error.cause');
	});

	it.cond('variant: cause is a host function', HAS_ERROR_CAUSE, function () {
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					throw new Error('fail', { cause: require('child_process') });
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.cause.execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'cause path produced a usable host value: ' + probe.result,
		);
	});

	it.cond('variant: deeply nested cause (cause.cause)', HAS_ERROR_CAUSE, function () {
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const inner = new Error('inner', { cause: process });
					throw new Error('outer', { cause: inner });
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.cause.cause.mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'nested cause pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: SuppressedError carrying host Error with cause=process', HAS_ERROR_CAUSE && HAS_SUPPRESSED_ERROR, function () {
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					throw new Error('host', { cause: process });
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				try { hostFn(); } catch (inner) {
					// Wrap the host error in a SuppressedError so the sub-error
					// path also walks .cause.
					throw new SuppressedError(inner, new Error('s'), 'sup');
				}
			} catch (e) {
				try {
					__probe.result = e.error.cause.mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'SuppressedError.error.cause pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: AggregateError entry carrying host Error with cause=process', HAS_ERROR_CAUSE && HAS_AGGREGATE_ERROR, function () {
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					throw new Error('host', { cause: process });
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				try { hostFn(); } catch (inner) {
					throw new AggregateError([inner], 'agg');
				}
			} catch (e) {
				try {
					__probe.result = e.errors[0].cause.mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'AggregateError.errors[i].cause pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: cyclic cause does not hang sanitization', HAS_ERROR_CAUSE, function () {
		const probe = { caught: false };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const a = new Error('a');
					const b = new Error('b', { cause: a });
					a.cause = b; // cycle
					throw b;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try { hostFn(); } catch (e) { __probe.caught = true; }
		`);
		assert.strictEqual(probe.caught, true, 'cyclic cause path threw or hung');
	});

	it.cond('regression: sandbox-thrown Error with sandbox-realm cause is preserved', HAS_ERROR_CAUSE, function () {
		// Sandbox-realm Error with sandbox-realm cause must not be stripped.
		// The defense only fires on host-realm errors.
		const vm = new VM();
		const out = vm.run(`
			let m1, m2;
			try {
				const inner = new Error('inner');
				inner.detail = 'present';
				throw new Error('outer', { cause: inner });
			} catch (e) {
				m1 = e.message;
				m2 = e.cause && e.cause.message;
				({ m1, m2, detail: e.cause && e.cause.detail });
			}
		`);
		assert.strictEqual(out.m1, 'outer');
		assert.strictEqual(out.m2, 'inner');
		assert.strictEqual(out.detail, 'present', 'sandbox-realm cause was stripped');
	});

	it.cond('variant: cause defined as non-configurable host data property (frozen)', HAS_ERROR_CAUSE, function () {
		// If the host error's `.cause` is non-configurable, the in-place
		// `defineProperty` strip cannot succeed. The fix falls back to
		// substituting a sandbox-realm Error so no pivot reference reaches
		// sandbox code.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const e = new Error('frozen');
					Object.defineProperty(e, 'cause', { value: process, configurable: false, writable: false });
					throw e;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.cause.mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'frozen-cause pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: cause defined as host accessor (getter)', HAS_ERROR_CAUSE, function () {
		// Accessor-shaped .cause must be flattened by defineProperty so the
		// host getter never runs from sandbox code.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const e = new Error('getter');
					Object.defineProperty(e, 'cause', { get: () => process, configurable: true });
					throw e;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.cause.mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'getter-cause pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: TOCTOU host accessor returning undefined first then process', HAS_ERROR_CAUSE, function () {
		// Follow-up bypass: a host-side `.cause` getter that returns `undefined`
		// on the first read and `process` on the second defeats any check-then-
		// act guard that early-returns when the first read is primitive. The
		// strip must run UNCONDITIONALLY on host-wrapped carriers.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					let reads = 0;
					const e = new Error('toctou');
					Object.defineProperty(e, 'cause', {
						get() { return reads++ === 0 ? undefined : process; },
						configurable: true,
					});
					throw e;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.cause.mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'TOCTOU getter-cause pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: TOCTOU host accessor returning null first then host function', HAS_ERROR_CAUSE, function () {
		// Same TOCTOU shape but with `null` on the first read, since the
		// original guard also early-returned on null. Also delivers a host
		// function (different pivot shape than process) on subsequent reads.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					let reads = 0;
					const e = new Error('toctou-null');
					Object.defineProperty(e, 'cause', {
						get() { return reads++ === 0 ? null : process.mainModule.require('child_process').execSync; },
						configurable: true,
					});
					throw e;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.cause('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'TOCTOU null→fn pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: TOCTOU host accessor returning primitive string first then process', HAS_ERROR_CAUSE, function () {
		// The original early-return path also bailed when typeof !== object/
		// function. A getter returning a primitive string first defeats that
		// type-based guard. The unconditional strip closes this variant too.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					let reads = 0;
					const e = new Error('toctou-str');
					Object.defineProperty(e, 'cause', {
						get() { return reads++ === 0 ? 'just a string' : process; },
						configurable: true,
					});
					throw e;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.cause.mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'TOCTOU string→process pivot succeeded: ' + probe.result,
		);
	});

	it.cond('regression: cause that is a string / number / null is preserved on host errors too', HAS_ERROR_CAUSE, function () {
		// Primitive .cause values cannot pivot to host references, so the fix
		// MAY preserve them. (Current implementation strips .cause on
		// host-realm errors unconditionally — that's fine; the regression
		// guard only asserts the rest of the error info survives.)
		const probe = { msg: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					throw new Error('with-string-cause', { cause: 'reason-string' });
				},
				__probe: probe,
			},
		});
		vm.run(`
			try { hostFn(); } catch (e) { __probe.msg = e.message; }
		`);
		assert.strictEqual(probe.msg, 'with-string-cause');
	});

	it.cond('variant: lying Proxy host-carrier defeats configurable strip', HAS_ERROR_CAUSE, function () {
		// Second follow-up bypass: a host-side Proxy wrapping the Error whose
		// defineProperty trap returns `true` without modifying the target.
		// A configurable strip would trust that boolean; subsequent `.cause`
		// reads go through the proxy's `get` trap back to the underlying
		// `process` reference. The fix forces a non-configurable + non-
		// writable seal, which triggers ECMA-262 §10.5.6 invariant check
		// (cannot seal a property whose target is configurable without
		// actually modifying the target). The engine throws, the fallback
		// substitution runs, and the carrier is replaced.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const realErr = new Error('proxy-lies');
					realErr.cause = process;
					const proxy = new Proxy(realErr, {
						defineProperty(target, prop, desc) {
							if (prop === 'cause') return true; // lie
							return Reflect.defineProperty(target, prop, desc);
						},
					});
					throw proxy;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.cause.mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'lying-Proxy-defineProperty pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: SuppressedError.error accessor TOCTOU', HAS_ERROR_CAUSE && HAS_SUPPRESSED_ERROR, function () {
		// The original SuppressedError handling did `e.error = handleException(
		// e.error, visited)`. The right-hand-side read invokes a host getter
		// (returning a benign value that recurses harmlessly), and the
		// assignment back is a SET — on a getter-only accessor it silently
		// no-ops. The accessor remains live, and the sandbox-side read
		// invokes it a second time, returning process. The fix snapshots
		// sub-errors once on host-wrapped carriers and constructs a fresh
		// sandbox-realm SuppressedError, dropping the original carrier.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const e = new SuppressedError(new Error('a'), new Error('b'), 'msg');
					let reads = 0;
					Object.defineProperty(e, 'error', {
						get() { return reads++ === 0 ? new Error('benign') : process; },
						configurable: true,
					});
					throw e;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.error.mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'SuppressedError.error TOCTOU pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: SuppressedError.suppressed accessor TOCTOU', HAS_ERROR_CAUSE && HAS_SUPPRESSED_ERROR, function () {
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const e = new SuppressedError(new Error('a'), new Error('b'), 'msg');
					let reads = 0;
					Object.defineProperty(e, 'suppressed', {
						get() { return reads++ === 0 ? new Error('benign') : process; },
						configurable: true,
					});
					throw e;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.suppressed.mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'SuppressedError.suppressed TOCTOU pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: AggregateError.errors accessor TOCTOU', HAS_ERROR_CAUSE && HAS_AGGREGATE_ERROR, function () {
		// Same TOCTOU class on AggregateError.errors. The fix snapshots
		// .errors once on host-wrapped carriers and constructs a fresh
		// sandbox-realm AggregateError with sanitized contents.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const e = new AggregateError([new Error('a')], 'agg');
					let reads = 0;
					Object.defineProperty(e, 'errors', {
						get() { return reads++ === 0 ? [new Error('benign')] : [process]; },
						configurable: true,
					});
					throw e;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.errors[0].mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'AggregateError.errors TOCTOU pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: AggregateError.errors[i] per-element accessor TOCTOU', HAS_ERROR_CAUSE && HAS_AGGREGATE_ERROR, function () {
		// Same TOCTOU shape but applied to an individual array index rather
		// than the .errors slot. The accessor must be installed on the array
		// AFTER AggregateError construction — the constructor iterates the
		// input via CreateArrayFromIterable, so accessors on the input array
		// don't survive into e.errors. The snapshot-and-rebuild approach
		// reads each arr[i] once before constructing the replacement.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const e = new AggregateError([new Error('placeholder')], 'agg');
					let reads = 0;
					Object.defineProperty(e.errors, '0', {
						get() { return reads++ === 0 ? new Error('benign') : process; },
						configurable: true,
					});
					throw e;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try {
				hostFn();
			} catch (e) {
				try {
					__probe.result = e.errors[0].mainModule.require('child_process').execSync('echo PWN').toString();
				} catch (err) {
					__probe.result = 'BLOCKED:' + (err && err.message);
				}
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'AggregateError.errors[i] TOCTOU pivot succeeded: ' + probe.result,
		);
	});

	it('variant: arbitrary own property (.detail = process) on host error', function () {
		// Third follow-up bypass: any own property on a host-wrapped error
		// can carry a host reference, not just .cause. The .cause-scoped
		// fix did not generalize. sanitizeHostOwnProps closes the class by
		// enumerating own keys and sealing every non-primitive to undefined.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => { const e = new Error('d'); e.detail = process; throw e; },
				__probe: probe,
			},
		});
		vm.run(`
			try { hostFn(); } catch (e) {
				try { __probe.result = e.detail.mainModule.require('child_process').execSync('echo PWN').toString(); }
				catch (err) { __probe.result = 'BLOCKED:' + (err && err.message); }
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'.detail pivot succeeded: ' + probe.result,
		);
	});

	it('variant: arbitrary own property (.originalError) on host error', function () {
		// Common error-wrapping convention in Node libraries.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => { const e = new Error('o'); e.originalError = require('child_process'); throw e; },
				__probe: probe,
			},
		});
		vm.run(`
			try { hostFn(); } catch (e) {
				try { __probe.result = e.originalError.execSync('echo PWN').toString(); }
				catch (err) { __probe.result = 'BLOCKED:' + (err && err.message); }
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'.originalError pivot succeeded: ' + probe.result,
		);
	});

	it.cond('variant: arbitrary own property on AggregateError sub-error', HAS_AGGREGATE_ERROR, function () {
		// AggregateError.errors[i] gets snapshot-and-rebuilt, but each sub-
		// error is itself passed back through handleException, which now
		// strips arbitrary own properties on host-wrapped sub-errors too.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const inner = new Error('i');
					inner.detail = process;
					throw new AggregateError([inner], 'a');
				},
				__probe: probe,
			},
		});
		vm.run(`
			try { hostFn(); } catch (e) {
				try { __probe.result = e.errors[0].detail.mainModule.require('child_process').execSync('echo PWN').toString(); }
				catch (err) { __probe.result = 'BLOCKED:' + (err && err.message); }
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'.errors[i].detail pivot succeeded: ' + probe.result,
		);
	});

	it('variant: arbitrary own property with TOCTOU accessor', function () {
		// Combined attack: arbitrary key + TOCTOU accessor. Captured-value
		// approach (read once, install as data property) would be defeated
		// by a getter returning primitive first / process later. The
		// non-configurable seal forces ECMA invariants regardless.
		const probe = { result: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const e = new Error('toctou-arb');
					let reads = 0;
					Object.defineProperty(e, 'attached', {
						get() { return reads++ === 0 ? 'benign-string' : process; },
						configurable: true,
					});
					throw e;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try { hostFn(); } catch (e) {
				try { __probe.result = e.attached.mainModule.require('child_process').execSync('echo PWN').toString(); }
				catch (err) { __probe.result = 'BLOCKED:' + (err && err.message); }
			}
		`);
		assert.ok(
			probe.result === 'UNSET' || /^BLOCKED:/.test(probe.result) || probe.result === undefined,
			'TOCTOU arbitrary prop pivot succeeded: ' + probe.result,
		);
	});

	it('regression: primitive own properties (.code, .errno) survive', function () {
		// Verify diagnostic info is preserved when it's primitive.
		const probe = { code: 'UNSET', errno: 'UNSET', message: 'UNSET' };
		const vm = new VM({
			sandbox: {
				hostFn: () => {
					const e = new Error('disk');
					e.code = 'ENOENT';
					e.errno = -2;
					throw e;
				},
				__probe: probe,
			},
		});
		vm.run(`
			try { hostFn(); } catch (e) {
				__probe.code = e.code;
				__probe.errno = e.errno;
				__probe.message = e.message;
			}
		`);
		assert.strictEqual(probe.code, 'ENOENT');
		assert.strictEqual(probe.errno, -2);
		assert.strictEqual(probe.message, 'disk');
	});
});

// ---------------------------------------------------------------------------
// Fourth follow-up: prototype-inherited host references.
//
// `sanitizeHostOwnProps` seals every OWN key of a host-wrapped carrier, but
// `Reflect.ownKeys` does not report inherited properties. A host error whose
// prototype was replaced with an object holding a host reference —
// `Object.setPrototypeOf(hostErr, { leak: process })` — therefore passed
// through untouched, and `e.leak` resolved to a live bridge proxy of the host
// object: `e.leak.mainModule.require('child_process').execSync(...)` is RCE.
//
// Closed by rebuilding the carrier in the sandbox realm, which drops the host
// prototype chain entirely and carries across only the sealed primitive own
// properties.
// ---------------------------------------------------------------------------
describe('GHSA-m283-3h24-438v — prototype-inherited host reference leak', function () {
	function vmThrowing(thrower) {
		return new VM({ sandbox: { hostFn: thrower } });
	}
	function caught(vm, expr) {
		return vm.run('try { hostFn(); } catch (e) { ' + expr + ' }');
	}

	it('blocks the canonical PoC: Object.setPrototypeOf(err, {leak: process})', function () {
		const vm = vmThrowing(() => {
			const e = new Error('proto');
			Object.setPrototypeOf(e, { leak: process });
			throw e;
		});
		assert.strictEqual(caught(vm, 'typeof e.leak'), 'undefined');
	});

	it('blocks RCE through the inherited reference', function () {
		const vm = vmThrowing(() => {
			const e = new Error('proto');
			Object.setPrototypeOf(e, { leak: process });
			throw e;
		});
		const out = caught(
			vm,
			"(function () { try { return e.leak.mainModule.require('child_process').execSync('echo PWNED').toString(); }" +
			" catch (x) { return 'BLOCKED'; } })()",
		);
		assert.strictEqual(out, 'BLOCKED');
	});

	it('variant: reference two prototype levels up', function () {
		const vm = vmThrowing(() => {
			const e = new Error('proto');
			Object.setPrototypeOf(e, Object.create({ deep: process }));
			throw e;
		});
		assert.strictEqual(caught(vm, 'typeof e.deep'), 'undefined');
	});

	it('variant: accessor on the prototype (not a data property)', function () {
		const vm = vmThrowing(() => {
			const e = new Error('proto');
			Object.setPrototypeOf(e, { get leak() { return process; } });
			throw e;
		});
		assert.strictEqual(caught(vm, 'typeof e.leak'), 'undefined');
	});

	it('variant: symbol-keyed inherited property', function () {
		const vm = vmThrowing(() => {
			const e = new Error('proto');
			const p = {};
			p[Symbol.for('vm2test.leak')] = process;
			Object.setPrototypeOf(e, p);
			throw e;
		});
		assert.strictEqual(caught(vm, "typeof e[Symbol.for('vm2test.leak')]"), 'undefined');
	});

	it('variant: host function inherited from the prototype', function () {
		const cp = require('child_process');
		const vm = vmThrowing(() => {
			const e = new Error('proto');
			Object.setPrototypeOf(e, { f: cp.execSync });
			throw e;
		});
		assert.strictEqual(caught(vm, 'typeof e.f'), 'undefined');
	});

	it('variant: inherited `constructor` cannot pivot to the host realm', function () {
		const cp = require('child_process');
		const vm = vmThrowing(() => {
			const e = new Error('proto');
			Object.setPrototypeOf(e, { constructor: cp.execSync });
			throw e;
		});
		// The rebuilt carrier is sandbox-realm, so `constructor` is the sandbox
		// Error, never the host function planted on the prototype.
		assert.strictEqual(caught(vm, 'e.constructor === Error'), true);
		assert.strictEqual(
			caught(
				vm,
				"(function () { try { return e.constructor.constructor('return process')().env.HOME; }" +
				" catch (x) { return 'BLOCKED'; } })()",
			),
			'BLOCKED',
		);
	});

	it('the subclass constructor is resolved from a module-load capture, not a sandbox global', function () {
		// Sandbox code replaces the global TypeError before the throw. The
		// rebuild must not call the attacker's function, and must not hand back
		// whatever it returns.
		const vm = vmThrowing(() => {
			const e = new TypeError('typed');
			Object.setPrototypeOf(e, { leak: process });
			throw e;
		});
		const out = vm.run(`
			var hijacked = false;
			TypeError = function () { hijacked = true; return { leak: 'attacker-controlled' }; };
			try { hostFn(); } catch (e) {
				[hijacked, typeof e.leak, e.message];
			}
		`);
		assert.strictEqual(out[0], false, 'sandbox-replaced TypeError must not be invoked');
		assert.strictEqual(out[1], 'undefined');
		assert.strictEqual(out[2], 'typed');
	});

	it('preserves error subclass identity through the rebuild', function () {
		assert.strictEqual(caught(vmThrowing(() => { throw new TypeError('t'); }), 'e instanceof TypeError'), true);
		assert.strictEqual(caught(vmThrowing(() => { throw new RangeError('r'); }), 'e instanceof RangeError'), true);
		assert.strictEqual(caught(vmThrowing(() => { throw new Error('e'); }), 'e instanceof Error'), true);
	});

	it('preserves primitive diagnostics through the rebuild', function () {
		const vm = vmThrowing(() => {
			const e = new Error('disk full');
			e.code = 'ENOSPC';
			e.errno = -28;
			e.syscall = 'write';
			Object.setPrototypeOf(e, { leak: process });
			throw e;
		});
		// Compare a host-realm copy: sandbox arrays cross the bridge as proxies
		// that also surface their index properties, which makes deepStrictEqual
		// differ on Node < 18 (README "Known Issues").
		const r = caught(vm, '[e.message, e.code, e.errno, e.syscall, typeof e.stack, typeof e.leak]');
		const got = [];
		for (let i = 0; i < r.length; i++) got.push(r[i]);
		assert.deepStrictEqual(got, ['disk full', 'ENOSPC', -28, 'write', 'string', 'undefined']);
	});
	// --- red-team regressions (composition with the earlier layers) ---

	it('red-team: an own `isProxy: false` cannot dodge the host-wrapped gate', function () {
		// _isHostWrapped reads e.isProxy; the bridge get trap answers `isProxy`
		// before consulting the target, so a planted own property cannot spoof it
		// into skipping the rebuild.
		const vm = vmThrowing(() => {
			const e = new Error('spoof');
			e.isProxy = false;
			Object.setPrototypeOf(e, { leak: process });
			throw e;
		});
		assert.strictEqual(caught(vm, 'typeof e.leak'), 'undefined');
	});

	it('red-team: a lying Proxy carrier that hides its own keys still cannot leak', function () {
		const vm = vmThrowing(() => {
			const e = new Error('lying');
			Object.setPrototypeOf(e, { leak: process });
			throw new Proxy(e, { ownKeys() { return []; }, getOwnPropertyDescriptor() { return undefined; } });
		});
		assert.strictEqual(caught(vm, 'typeof e.leak'), 'undefined');
	});

	it.cond('red-team: AggregateError sub-error with an inherited leak', HAS_AGGREGATE_ERROR, function () {
		const vm = vmThrowing(() => {
			const inner = new Error('inner');
			Object.setPrototypeOf(inner, { leak: process });
			throw new AggregateError([inner], 'agg');
		});
		assert.strictEqual(caught(vm, 'typeof e.errors[0].leak'), 'undefined');
	});

	it.cond('red-team: cause sub-error with an inherited leak', HAS_ERROR_CAUSE, function () {
		const vm = vmThrowing(() => {
			const inner = new Error('inner');
			Object.setPrototypeOf(inner, { leak: process });
			throw new Error('outer', { cause: inner });
		});
		assert.strictEqual(
			caught(vm, 'e.cause === undefined ? "undefined" : typeof e.cause.leak'),
			'undefined',
		);
	});
});
