'use strict';

/**
 * GHSA-248r-7h7q-cr24 — Async generator yield* return-thenable exception capture
 *
 * ## Vulnerability
 * When an async generator delegates via `yield*` to an inner async iterator
 * with no `return` method, calling `i.return(thenable)` causes V8 to await
 * the thenable as the abrupt-return value. If the thenable's `.then` method
 * synchronously throws (e.g. by deep recursion → RangeError, or any
 * attacker-controlled host throw), V8's `PromiseResolveThenableJob`
 * captures the exception and the V8 yield* machinery delivers it to
 * sandbox code as a fulfillment `{ value: thrown, done: false }`.
 *
 * This bypasses two existing defenses:
 *   1. The transformer's `catch`-block instrumentation (the catch is
 *      implicit in V8 internals; no user `catch` block is involved).
 *   2. The `globalPromise.prototype.then` rejection sanitizer in
 *      setup-sandbox.js — V8's internal `Await` uses `PerformPromiseThen`
 *      directly, never invoking the user-visible `.then` override.
 *
 * The result: a value can flow into sandbox code through the async
 * generator state machine without passing through `handleException`.
 *
 * Original PoC: binary-search recursion depths until V8
 * throws a `RangeError` whose realm is the host (this can occur at
 * the precise depth where the overflow strikes during V8's
 * PromiseResolveThenableJob host code), then use
 * `e.constructor.constructor("return process")()` for RCE.
 *
 * ## Fix
 * Wrap `%AsyncGeneratorPrototype%.next` / `.return` / `.throw` to route
 * the resolved-iterator-result `value` through `handleException`, and
 * route any rejection through `handleException` as well. This restores
 * the invariant: every value flowing from an async generator into
 * sandbox code is sanitized.
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

// AsyncGenerators require Node 10+; assume present on supported targets.
const HAS_ASYNC_GEN = (() => {
	try {
		eval('(async function*(){})');
		return true;
	} catch (e) {
		return false;
	}
})();

describe('GHSA-248r-7h7q-cr24 (async generator yield*-return thenable exception capture)', function () {
	it.cond(
		'canonical PoC: cannot reach host process through e.constructor.constructor',
		HAS_ASYNC_GEN,
		async function () {
			this.timeout(60000);
			const vm = new VM();
			const result = await vm.run(`
				class E extends Error {}
				function so(d) {
					if (d > 0) so(d-1);
					const e = new E();
					e.stack;
					throw e;
				}
				async function* helper() {
					yield* {
						[Symbol.asyncIterator]: ()=>({
							next: v=>({value: v, done: false}), throw: v=>({value: v, done: false})
						})
					};
				}
				async function doCatch(f) {
					const i=helper();
					await i.next();
					const v = await i.return({then(r){f();r();}});
					return v.value;
				}
				(async () => {
					let min = 0;
					let max = 200000;
					while (min < max) {
						const mid = (min + max) >> 1;
						let e;
						try { e = await doCatch(()=>so(mid)); }
						catch (err) { return { phase: 'reject', mid }; }
						if (e && e.name === 'RangeError' && !(e instanceof RangeError)) {
							try {
								const proc = e.constructor.constructor('return process')();
								return { ESCAPED: true, mid, version: proc && proc.version };
							} catch (ex) {
								return { nearMiss: true, mid, msg: ex && ex.message };
							}
						}
						if (e instanceof E) min = mid + 1;
						else max = mid;
					}
					return { phase: 'done', min, max };
				})();
			`);
			assert.ok(!result.ESCAPED, 'sandbox escape via canonical PoC: ' + JSON.stringify(result));
			// Either: search converged with all RangeErrors bridged ('done'),
			// or near-miss attempted but the bridged Function constructor
			// returned undefined process. Both are acceptable closures.
		},
	);

	it.cond(
		'thrown value is sanitized: a thrown SuppressedError-like with sub-error is wrapped',
		HAS_ASYNC_GEN,
		async function () {
			this.timeout(10000);
			const vm = new VM();
			// We construct an attacker-controlled Error that, if delivered
			// raw to sandbox via yield*-return-thenable capture, would expose
			// `.constructor.constructor` as the host Function constructor.
			// Verify the value reaching sandbox code is bridge-wrapped.
			const result = await vm.run(`
				async function* helper() {
					yield* {
						[Symbol.asyncIterator]: ()=>({
							next: v=>({value: v, done: false}), throw: v=>({value: v, done: false})
						})
					};
				}
				async function doCatch(f) {
					const i=helper();
					await i.next();
					const v = await i.return({then(r){f();r();}});
					return v.value;
				}
				(async () => {
					const probe = {};
					// Sandbox-thrown Error: confirm value flows through and is sanitized.
					const e = await doCatch(()=>{ throw new Error('sandbox-throw'); });
					probe.ctorIsSandboxError = e && e.constructor === Error;
					probe.instanceofError = e instanceof Error;
					probe.message = e && e.message;
					// Try the canonical escape vector via Function constructor.
					try {
						const fn = e.constructor.constructor('return process');
						probe.gotProcess = !!fn();
					} catch (ex) { probe.escapeBlocked = true; probe.escapeMsg = ex && ex.message; }
					return probe;
				})();
			`);
			assert.strictEqual(result.ctorIsSandboxError, true, 'e.constructor must be sandbox Error');
			assert.strictEqual(result.instanceofError, true, 'e must be instanceof sandbox Error');
			assert.strictEqual(result.message, 'sandbox-throw');
			// Either the Function constructor is sandbox-realm and process is undefined,
			// or it throws. Either way, we must not have obtained host process.
			assert.ok(!result.gotProcess, 'must not obtain host process via thrown value: ' + JSON.stringify(result));
		},
	);

	it.cond(
		'thrown host-realm error via bridged host call is sanitized through yield* capture',
		HAS_ASYNC_GEN,
		async function () {
			this.timeout(10000);
			const vm = new VM();
			const result = await vm.run(`
				async function* helper() {
					yield* {
						[Symbol.asyncIterator]: ()=>({
							next: v=>({value: v, done: false}), throw: v=>({value: v, done: false})
						})
					};
				}
				async function doCatch(f) {
					const i=helper();
					await i.next();
					const v = await i.return({then(r){f();r();}});
					return v.value;
				}
				(async () => {
					// Buffer.alloc(-1) throws a host RangeError that the bridge's
					// apply-trap throw path wraps before propagation. Confirm the
					// wrap survives the yield* capture.
					const e = await doCatch(()=>{ Buffer.alloc(-1); });
					const probe = {
						ctorIsSandboxRangeError: e && e.constructor === RangeError,
						instanceofRangeError: e instanceof RangeError,
						instanceofError: e instanceof Error,
					};
					try {
						const fn = e.constructor.constructor('return process');
						probe.gotProcess = !!fn();
					} catch (ex) { probe.escapeBlocked = true; }
					return probe;
				})();
			`);
			assert.strictEqual(result.ctorIsSandboxRangeError, true);
			assert.strictEqual(result.instanceofRangeError, true);
			assert.ok(!result.gotProcess, 'host process leaked: ' + JSON.stringify(result));
		},
	);

	it.cond(
		'closure-transport bypass: value hidden in `value: ()=>v` closure is still sanitized',
		HAS_ASYNC_GEN,
		async function () {
			// Bypass of the candidate fix: the wrapper's
			// handleException(result.value) sees only the closure when the inner
			// iterator returns `{value: ()=>v, done: false}`. The captured-by-V8
			// throw flows into the closure as the parameter `v` of the second
			// inner.next() call. Sandbox extracts via wrap.value() — the wrapper
			// never inspected what the closure returns.
			//
			// The defense (sanitizeThenableArg) wraps any thenable passed to
			// AsyncGeneratorPrototype.{next,return,throw} so that synchronous
			// throws from the user .then are caught and converted to
			// reject(handleException(e)) BEFORE V8's PromiseResolveThenableJob
			// captures them. By the time V8 forwards the value to inner.next,
			// the realm has been normalized.
			this.timeout(60000);
			const vm = new VM();
			const result = await vm.run(`
				async function* helper() {
					yield* {
						[Symbol.asyncIterator]: () => ({
							next: v => ({ value: () => v, done: false }), throw: v => ({ value: () => v, done: false })
						})
					};
				}
				async function doCatch(f) {
					const i = helper();
					await i.next();
					const v = await i.return({ then(r) { f(); r(); } });
					return v.value();
				}
				(async () => {
					// Sandbox-thrown Error: confirm closure-extracted value is sandbox-realm.
					const e = await doCatch(() => { throw new Error('closure-bypass'); });
					const probe = {
						type: typeof e,
						message: e && e.message,
						ctorIsSandboxError: e && e.constructor === Error,
						instanceofError: e instanceof Error,
					};
					try {
						const proc = e.constructor.constructor('return process')();
						probe.gotProcess = !!proc;
					} catch (ex) {
						probe.escapeBlocked = true;
					}
					return probe;
				})();
			`);
			assert.strictEqual(result.message, 'closure-bypass');
			assert.strictEqual(result.ctorIsSandboxError, true);
			assert.strictEqual(result.instanceofError, true);
			assert.ok(!result.gotProcess, 'host process leaked through closure transport: ' + JSON.stringify(result));
		},
	);

	it.cond('closure-transport bypass: deep-recursion variant cannot escape', HAS_ASYNC_GEN, async function () {
		// Full canonical bypass PoC with binary-search over recursion depths.
		// Even at the threshold where V8 might produce a host-realm RangeError
		// from PromiseResolveThenableJob host bookkeeping, the thenable-arg
		// sanitization ensures the captured value is bridged before reaching
		// the inner iterator's `next` parameter.
		this.timeout(120000);
		const vm = new VM();
		const result = await vm.run(`
				class E extends Error {}
				function so(d) {
					if (d > 0) so(d-1);
					const e = new E();
					e.stack;
					throw e;
				}
				async function* helper() {
					yield* {
						[Symbol.asyncIterator]: () => ({
							next: v => ({ value: () => v, done: false }), throw: v => ({ value: () => v, done: false })
						})
					};
				}
				async function doCatch(f) {
					const i = helper();
					await i.next();
					const v = await i.return({ then(r) { f(); r(); } });
					return v.value();
				}
				(async () => {
					let min = 0;
					let max = 200000;
					while (min < max) {
						const mid = (min + max) >> 1;
						let e;
						try { e = await doCatch(() => so(mid)); }
						catch (err) { return { phase: 'reject', mid }; }
						if (e && e.name === 'RangeError' && !(e instanceof RangeError)) {
							try {
								const proc = e.constructor.constructor('return process')();
								return { ESCAPED: true, mid, version: proc && proc.version };
							} catch (ex) { return { nearMiss: true, mid, msg: ex && ex.message }; }
						}
						if (e instanceof E) min = mid + 1;
						else max = mid;
					}
					return { phase: 'done', min, max };
				})();
			`);
		assert.ok(!result.ESCAPED, 'sandbox escape via closure-transport bypass: ' + JSON.stringify(result));
	});

	it.cond(
		'nested-thenable bypass: outer .then resolving with inner thenable cannot smuggle host throw',
		HAS_ASYNC_GEN,
		async function () {
			// Reviewer's 2nd bypass-A:
			//   `await i.return({ then(r){ r({ then(r){ f(); r(); }}) }})`
			// The outer .then synchronously calls `resolve(innerThenable)`.
			// V8 detects innerThenable is itself a thenable and schedules
			// another PromiseResolveThenableJob, which would call the inner
			// .then directly — outside the v2 thenable-arg wrapper. The v3
			// fix wraps the resolve callback so any thenable handed to it is
			// re-sanitised before V8 sees it; safeResolve(inner) becomes
			// resolve(sanitizeThenableArg(inner)), so V8 only ever invokes
			// our safeThen, never the user's inner .then directly.
			this.timeout(60000);
			const vm = new VM();
			const result = await vm.run(`
				let innerThenCalls = 0;
				async function* helper() {
					yield* {
						[Symbol.asyncIterator]: () => ({
							next: v => ({ value: () => v, done: false }), throw: v => ({ value: () => v, done: false })
						})
					};
				}
				(async () => {
					const i = helper();
					await i.next();
					const wrap = await i.return({
						then(r) {
							r({
								then(rr) {
									innerThenCalls++;
									const e = new Error('nested-bypass');
									e.name = 'PWN';
									throw e;
								}
							});
						}
					});
					const e = wrap.value();
					const probe = {
						innerThenCalls,
						hasError: e instanceof Error,
						msg: e && e.message,
						ctorIsSandboxError: e && e.constructor === Error,
					};
					try {
						const proc = e.constructor.constructor('return process')();
						probe.gotProcess = !!proc;
					} catch (ex) { probe.escapeBlocked = true; }
					return probe;
				})();
			`);
			assert.strictEqual(result.innerThenCalls, 1, 'inner .then must be called exactly once via the wrapper');
			assert.strictEqual(result.ctorIsSandboxError, true);
			assert.strictEqual(result.msg, 'nested-bypass');
			assert.ok(
				!result.gotProcess,
				'host process leaked through nested-thenable transport: ' + JSON.stringify(result),
			);
		},
	);

	it.cond(
		'getter-TOCTOU bypass: .then as a getter is read at most once by the sanitiser',
		HAS_ASYNC_GEN,
		async function () {
			// Reviewer's 2nd bypass-B:
			//   `obj = { get then() { return calls++===0 ? undefined : fn } }`
			// On the v2 fix, sanitizeThenableArg pre-reads obj.then once
			// (getter call 1 → undefined → returns value unwrapped); V8 then
			// re-reads obj.then (getter call 2 → fn) and calls fn directly,
			// outside our wrapper. The v3 fix never pre-reads: it always
			// substitutes a wrapper whose .then is a fixed safeThen function.
			// V8 only sees safeThen. safeThen reads value.then once for the
			// initial type check, plus a second time after the descriptor
			// walk to detect TOCTOU getter self-replacement (v6). The
			// security invariant is that V8 itself never invokes the user
			// .then directly — every call goes through our wrapper or the
			// stripped shadow path.
			this.timeout(60000);
			const vm = new VM();
			const result = await vm.run(`
				let calls = 0;
				async function* helper() {
					yield* {
						[Symbol.asyncIterator]: () => ({
							next: v => ({ value: () => v, done: false }), throw: v => ({ value: () => v, done: false })
						})
					};
				}
				(async () => {
					const i = helper();
					await i.next();
					const obj = {
						get then() {
							calls++;
							if (calls === 1) return undefined;
							return function (r) {
								const e = new Error('toctou-bypass');
								e.name = 'PWN';
								throw e;
							};
						}
					};
					let captured;
					try {
						const wrap = await i.return(obj);
						captured = {
							phase: 'resolved',
							done: wrap && wrap.done,
							valueType: typeof (wrap && wrap.value),
							valueIsCallable: typeof (wrap && wrap.value) === 'function',
						};
						// v7: wrap.value is a shadow (object) when the
						// non-function branch resolves, or a closure
						// (function) when the function branch threw. Either
						// way, sandbox-extracted value must not yield host
						// process.
						let extracted;
						if (typeof wrap.value === 'function') {
							try { extracted = wrap.value(); } catch (e) {}
						} else {
							extracted = wrap.value;
						}
						captured.extractedType = typeof extracted;
						if (extracted && typeof extracted === 'object') {
							try {
								const proc = extracted.constructor && extracted.constructor.constructor('return process')();
								captured.gotProcess = !!proc;
							} catch (ex) { captured.escapeBlocked = true; }
						}
					} catch (rejected) {
						captured = {
							phase: 'rejected',
							msg: rejected && rejected.message,
							ctorIsSandboxError: rejected && rejected.constructor === Error,
						};
						try {
							const proc = rejected.constructor.constructor('return process')();
							captured.gotProcess = !!proc;
						} catch (ex) { captured.escapeBlocked = true; }
					}
					return { calls, captured };
				})();
			`);
			assert.ok(
				!(result.captured && result.captured.gotProcess),
				'host process leaked via getter-TOCTOU bypass: ' + JSON.stringify(result),
			);
		},
	);

	it.cond(
		'Array.prototype setter pollution on args build does not intercept user value',
		HAS_ASYNC_GEN,
		async function () {
			// Reviewer's 3rd bypass:
			//   const args = []; ... args[i] = arguments[i];
			// `[]` inherits Array.prototype. If sandbox installs a setter on
			// `Array.prototype['0']`, `args[0] = arguments[0]` walks the
			// prototype chain, the setter fires, captures (or rewrites) the
			// user value before sanitizeThenableArg ever runs.
			//
			// The fix builds args as `{ __proto__: null, length, ... }` so
			// integer-key writes never walk a user-controlled prototype.
			this.timeout(10000);
			const vm = new VM();
			const result = await vm.run(`
				(async () => {
					let intercepted = null;
					Object.defineProperty(Array.prototype, '0', {
						set(v) { intercepted = v; },
						get() { return undefined; },
						configurable: true,
					});
					async function* helper() {
						yield* {
							[Symbol.asyncIterator]: () => ({
								next: v => ({ value: () => v, done: false }), throw: v => ({ value: () => v, done: false })
							})
						};
					}
					const i = helper();
					await i.next();
					await i.return({ then(r) { r(); } });
					return {
						setterFired: intercepted !== null,
					};
				})();
			`);
			assert.strictEqual(
				result.setterFired,
				false,
				'sandbox-installed Array.prototype setter must not intercept the wrapper args build',
			);
		},
	);

	it.cond(
		'wrapper installation is non-configurable: sandbox cannot delete or replace .next/.return/.throw',
		HAS_ASYNC_GEN,
		async function () {
			// Defense-in-depth (red-team finding): if the wrappers were
			// configurable, sandbox could `delete` them or redefine them
			// with a sandbox-controlled function. Even without a reference
			// to the original native, replacing the wrapper would let
			// sandbox interpose its own logic on V8's yield* protocol
			// invocations.
			this.timeout(5000);
			const vm = new VM();
			const result = await vm.run(`
				(async () => {
					const proto = Object.getPrototypeOf((async function*(){})());
					const agProto = Object.getPrototypeOf(proto);
					const probes = {};
					for (const m of ['next', 'return', 'throw']) {
						const desc = Object.getOwnPropertyDescriptor(agProto, m);
						const originalRef = desc.value;
						probes[m] = { configurable: desc.configurable, writable: desc.writable };
						try { delete agProto[m]; } catch (e) {}
						try { agProto[m] = function malicious() {}; } catch (e) {}
						try { Object.defineProperty(agProto, m, { value: function evil() {} }); } catch (e) {}
						// The only thing that matters is whether tampering succeeded.
						probes[m].stillOriginal = agProto[m] === originalRef;
					}
					return probes;
				})();
			`);
			for (const m of ['next', 'return', 'throw']) {
				assert.strictEqual(result[m].configurable, false, m + ' must not be configurable');
				assert.strictEqual(result[m].writable, false, m + ' must not be writable');
				assert.strictEqual(result[m].stillOriginal, true, m + ' must remain the wrapper after tamper attempts');
			}
		},
	);

	it.cond(
		'i.return(non-thenable) loses identity but the value is sandbox-realm and safe',
		HAS_ASYNC_GEN,
		async function () {
			// SECURITY trade-off (v7 — GHSA-248r-7h7q-cr24): the v5/v6
			// optimisation that preserved `wrap.value === input` for
			// non-thenable inputs was structurally unsound — every
			// detection-based heuristic on the user's `.then` slot is
			// bypassable by a counting getter or a Proxy. v7 always
			// shadows in the non-function branch, which means
			// `wrap.value` is a sandbox-realm `{__proto__: null}` copy of
			// the input's own descriptors, not the input itself.
			//
			// This test pins the new behaviour: identity is NOT preserved,
			// but the surfaced value is a safe sandbox object. Sandbox
			// code that needs the original reference can keep it on the
			// outside of the `i.return()` call.
			this.timeout(5000);
			const vm = new VM();
			const result = await vm.run(`
				(async () => {
					async function* helper() {
						yield* {
							[Symbol.asyncIterator]: () => ({
								next: v => ({ value: v, done: false }), throw: v => ({ value: v, done: false })
							})
						};
					}
					const probes = {};
					{
						const i = helper();
						await i.next();
						const fn = function add(a, b) { return a + b; };
						fn.tag = 'add-fn';
						const wrap = await i.return(fn);
						probes.fn = {
							sameRef: wrap.value === fn,
							typeOf: typeof wrap.value,
							ownTag: wrap.value && wrap.value.tag,
						};
					}
					{
						const i = helper();
						await i.next();
						const obj = { a: 1, b: 2 };
						const wrap = await i.return(obj);
						probes.plainObj = {
							sameRef: wrap.value === obj,
							a: wrap.value && wrap.value.a,
							b: wrap.value && wrap.value.b,
						};
					}
					return probes;
				})();
			`);
			// v7: identity is intentionally lost — the shadow is a safe
			// sandbox-realm copy, not the original.
			assert.strictEqual(result.fn.sameRef, false, 'function value is shadowed (no identity)');
			assert.strictEqual(result.fn.ownTag, 'add-fn', 'shadow preserves own data properties');
			assert.strictEqual(result.plainObj.sameRef, false, 'plain object is shadowed');
			assert.strictEqual(result.plainObj.a, 1, 'shadow preserves own data properties (a)');
			assert.strictEqual(result.plainObj.b, 2, 'shadow preserves own data properties (b)');
		},
	);

	it.cond(
		'TOCTOU getter that counts reads then self-replaces (v6 bypass) cannot smuggle host call',
		HAS_ASYNC_GEN,
		async function () {
			// External review v6 bypass:
			//   "the getter for then just need to count to two and return
			//    the same value twice before replacing itself with a data
			//    property to bypass the thenIsAccessorInChain check."
			//
			// Bypass mechanics:
			//   1. wrapper reads value.then → getter fires (count=1) → returns undefined.
			//   2. wrapper re-reads value.then → getter fires (count=2),
			//      replaces itself with `Object.defineProperty(value, 'then',
			//      {value: maliciousFn, writable: true, configurable: true})`,
			//      returns undefined.
			//   3. Both reads non-function and equal.
			//   4. `thenIsAccessorInChain(value)` reads the descriptor —
			//      now data, not accessor — returns false.
			//   5. Code picks `resolveWith = value`, calls resolve(value).
			//   6. V8's PromiseResolve does [[Get]](value, 'then') → reads
			//      maliciousFn (data property). IsCallable → true.
			//   7. V8 schedules a NEW PromiseResolveThenableJob with
			//      maliciousFn as the .then handler. V8 calls maliciousFn
			//      directly with V8 internal capability resolvers, OUTSIDE
			//      our wrapper.
			//
			// v7 fix: the non-function branch ALWAYS shadows. V8 never
			// reads the user's `.then` slot directly — it sees the
			// sandbox-realm shadow's (absent) `.then`.
			//
			// Structural assertion: if the malicious fn is somehow still
			// reached, its first arg's `.name` must be 'safeResolveCallback'
			// (our wrapper) and never '' (V8's internal resolver).
			this.timeout(15000);
			const vm = new VM();
			const result = await vm.run(`
				const trace = [];
				let calls = 0;
				const value = {};
				Object.defineProperty(value, 'then', {
					configurable: true,
					get() {
						calls++;
						trace.push('getter-' + calls);
						if (calls === 2) {
							// Self-replace AFTER returning the 2nd undefined.
							// Pre-v7 code would do its descriptor walk now,
							// see a data property, conclude "no accessor",
							// pass value to resolve() — V8 then reads this
							// malicious data-property fn and calls it.
							Object.defineProperty(value, 'then', {
								value: function malicious(r, j) {
									trace.push({
										ev: 'malicious-called',
										resolveName: r && r.name,
										rejectName: j && j.name,
									});
									const e = new Error('v6-bypass');
									e.name = 'PWN';
									throw e;
								},
								writable: true,
								configurable: true,
							});
						}
						return undefined;
					},
				});
				async function* helper() {
					yield* {
						[Symbol.asyncIterator]: () => ({
							next: v => ({ value: () => v, done: false }), throw: v => ({ value: () => v, done: false })
						})
					};
				}
				(async () => {
					const i = helper();
					await i.next();
					let out;
					try {
						const wrap = await i.return(value);
						out = {
							phase: 'resolved',
							done: wrap && wrap.done,
							valueType: typeof (wrap && wrap.value),
						};
						let extracted = wrap && wrap.value;
						if (typeof extracted === 'function') {
							try { extracted = extracted(); } catch (e) { extracted = null; }
						}
						out.extractedType = typeof extracted;
						if (extracted && typeof extracted === 'object') {
							try {
								const proc = extracted.constructor && extracted.constructor.constructor('return process')();
								out.gotProcess = !!proc;
							} catch (ex) { out.escapeBlocked = true; }
						}
					} catch (rejected) {
						out = {
							phase: 'rejected',
							msg: rejected && rejected.message,
						};
					}
					return { trace, out };
				})();
			`);
			// Critical (v7): the malicious function must NEVER be called.
			// Pre-v7, V8 invoked it directly in PromiseResolveThenableJob with
			// internal capability resolvers (resolver.name === ''). With v7's
			// always-shadow on the non-function branch, V8 only sees the
			// shadow's absent .then.
			const fnCall = result.trace.find(e => e && typeof e === 'object' && e.ev === 'malicious-called');
			assert.strictEqual(
				fnCall,
				undefined,
				'malicious .then was reached (pre-v7 bypass succeeded): ' + JSON.stringify(result),
			);
			assert.ok(
				!(result.out && result.out.gotProcess),
				'host process leaked via v6 TOCTOU bypass: ' + JSON.stringify(result),
			);
		},
	);

	// NOTE: Proxy is not exposed in the vm2 sandbox (`Proxy: { value: undefined }`
	// in setup-sandbox.js line 370), so a sandbox-driven Proxy bypass of the
	// .then descriptor walk is not reachable from sandbox code. The structural
	// fix still applies the same argument: detection-based heuristics on
	// attacker-controlled .then are unsound, and the only safe answer is to
	// substitute a sandbox-realm shadow that V8 reads instead of `value`.

	it.cond(
		'handleException throwing during sanitisation does not surface raw value to sandbox',
		HAS_ASYNC_GEN,
		async function () {
			// Reviewer's robustness concern: every call to handleException
			// in the wrapper is wrapped via safeSanitize, which falls back
			// to a sandbox-realm VMError if handleException itself throws.
			// We can't easily make handleException throw from sandbox code
			// (it's quite robust), but we can validate that the safeSanitize
			// fallback path is reachable by exercising a SuppressedError
			// with a hostile sub-error — at minimum the rejection still
			// surfaces as a sandbox-realm value.
			this.timeout(10000);
			const vm = new VM();
			const result = await vm.run(`
				(async () => {
					async function* helper() {
						yield* {
							[Symbol.asyncIterator]: () => ({
								next: v => ({ value: () => v, done: false }), throw: v => ({ value: () => v, done: false })
							})
						};
					}
					const i = helper();
					await i.next();
					// Throw a SuppressedError-style nested error from .then.
					// safeSanitize must produce a sandbox-realm value
					// regardless of any internal hiccups in handleException.
					try {
						const wrap = await i.return({
							then(r) {
								const inner = new Error('inner');
								Object.defineProperty(inner, 'name', {
									get() { throw new Error('name-getter-throws'); }
								});
								throw inner;
							}
						});
						const e = wrap.value();
						return {
							phase: 'resolved',
							isObj: typeof e === 'object',
							isInstanceofError: e instanceof Error,
							ctorIsSandboxError: e && e.constructor === Error,
						};
					} catch (rejected) {
						return {
							phase: 'rejected',
							isInstanceofError: rejected instanceof Error,
							ctorIsSandboxError: rejected && rejected.constructor === Error,
						};
					}
				})();
			`);
			// Either path is acceptable as long as the surfaced value is sandbox-realm.
			if (result.phase === 'resolved') {
				assert.strictEqual(result.ctorIsSandboxError, true, 'resolved-path value must be sandbox Error');
			} else {
				assert.strictEqual(result.ctorIsSandboxError, true, 'rejected value must be sandbox Error');
			}
		},
	);

	it.cond(
		'TOCTOU getter self-replacement (v6 PoC): V8 must not invoke a swapped-in function directly',
		HAS_ASYNC_GEN,
		async function () {
			// Reviewer's v6 bypass: a getter on `.then` could fire on the
			// wrapper's first read, install a data property holding a
			// function as its replacement, and return non-function.
			//   - Old descriptor walk would see a data property (not an
			//     accessor) and conclude "safe to pass value directly".
			//   - V8's PromiseResolve would then [[Get]] value.then and
			//     find the data property's function value — V8 calls it
			//     directly, OUTSIDE our wrapper.
			//
			// Defense: re-read value.then after the walk; if it is now a
			// callable, route through the function-branch with the new
			// captured ref. If it changed to something non-function but
			// different from the first read, fall back to the stripped
			// shadow (V8 cannot observe a different value than us).
			//
			// Structural assertion: when the malicious function IS called
			// (which it should be, via our wrapper's apply), its first arg
			// is `safeResolveCallback` and second is `safeRejectCallback`
			// — both sandbox-wrapped sanitisers. If V8 had called it
			// directly, args would be V8's internal capability resolvers
			// with different names.
			this.timeout(10000);
			const vm = new VM();
			const result = await vm.run(`
				(async () => {
					const trace = [];
					const value = {};
					Object.defineProperty(value, 'then', {
						configurable: true,
						get() {
							trace.push('getter-fired');
							Object.defineProperty(value, 'then', {
								value: function malicious(r, j) {
									trace.push({
										ev: 'malicious-fn-called',
										resolveName: r && r.name,
										rejectName: j && j.name,
									});
									const e = new Error('toctou-swap-bypass');
									e.name = 'PWN';
									throw e;
								},
								writable: true,
								configurable: true,
							});
							return undefined;
						},
					});
					async function* helper() {
						yield* {
							[Symbol.asyncIterator]: () => ({
								next: v => ({ value: () => v, done: false }), throw: v => ({ value: () => v, done: false })
							})
						};
					}
					const i = helper();
					await i.next();
					let out;
					try {
						const wrap = await i.return(value);
						out = {
							phase: 'resolved',
							done: wrap && wrap.done,
							valueType: typeof (wrap && wrap.value),
						};
						// v7: with always-shadow on non-function branch, the
						// await fulfills with the shadow → wrap.value === shadow
						// (object), wrap.done === true. Rejection path would
						// produce wrap.value === closure (function).
						let extracted = wrap && wrap.value;
						if (typeof extracted === 'function') {
							try { extracted = extracted(); } catch (e) { extracted = null; }
						}
						out.extractedType = typeof extracted;
						if (extracted && typeof extracted === 'object') {
							try {
								const proc = extracted.constructor && extracted.constructor.constructor('return process')();
								out.gotProcess = !!proc;
							} catch (ex) { out.escapeBlocked = true; }
						}
					} catch (rejected) {
						out = {
							phase: 'rejected',
							msg: rejected && rejected.message,
							ctorIsSandboxError: rejected && rejected.constructor === Error,
						};
						try {
							const proc = rejected.constructor.constructor('return process')();
							out.gotProcess = !!proc;
						} catch (ex) { out.escapeBlocked = true; }
					}
					return { trace, out };
				})();
			`);
			// Critical (v7): the malicious function must NEVER have been
			// called. Pre-v7, V8 invoked it directly with internal capability
			// resolvers (.name === ''). With always-shadow, V8 only sees the
			// shadow's absent .then and never reads the malicious function
			// from `value`.
			const fnCall = result.trace.find(e => e && typeof e === 'object' && e.ev === 'malicious-fn-called');
			assert.strictEqual(
				fnCall,
				undefined,
				'malicious .then must NEVER be called (pre-v7 it was invoked by V8): ' + JSON.stringify(result),
			);
			assert.ok(!(result.out && result.out.gotProcess), 'host process must not leak via TOCTOU swap');
		},
	);

	it.cond('.next/.return/.throw on async generator instances all sanitize results', HAS_ASYNC_GEN, async function () {
		this.timeout(10000);
		const vm = new VM();
		const result = await vm.run(`
				async function* gen() {
					yield 1;
					yield 2;
				}
				(async () => {
					const g = gen();
					const a = await g.next();
					const b = await g.next();
					const c = await g.return('done');
					return [a, b, c];
				})();
			`);
		// Regression guard: the sanitization wrapper must not break normal use.
		assert.deepStrictEqual(result[0], { value: 1, done: false });
		assert.deepStrictEqual(result[1], { value: 2, done: false });
		assert.deepStrictEqual(result[2], { value: 'done', done: true });
	});
});
