/**
 * GHSA-47x8-96vw-5wg6 — Cross-realm symbol extraction via host `Object`
 *
 * Duplicates merged: GHSA-qcp4-v2jj-fjx8, GHSA-f539-x546-3726
 *
 * ## Vulnerability class
 * Sandbox code reaches the host-realm `Object` constructor through a prototype-chain
 * walk (commonly via `({}).__lookupGetter__('__proto__')` composed with
 * `Buffer.apply`) and calls host `Object.getOwnPropertySymbols(Buffer.prototype)` --
 * bypassing the sandbox's own `Object.getOwnPropertySymbols` / `Reflect.ownKeys`
 * overrides, which filter the dangerous cross-realm symbols
 * `Symbol.for('nodejs.util.inspect.custom')` and `Symbol.for('nodejs.rejection')`.
 * The host function returns a host-realm array whose element is the real
 * cross-realm symbol. That symbol, used as a computed key on a plain sandbox
 * object handed to `WebAssembly.compileStreaming`, causes Node's internal error
 * formatter (`util.inspect`) to invoke the sandbox-provided function with a host
 * `inspect` argument whose `.constructor` is the host `Function` -> RCE.
 *
 * ## Fix (defense-in-depth, lib/bridge.js)
 * 1. `thisFromOtherWithFactory` / `thisEnsureThis` / `thisFromOtherForThrow`
 *    (the three host->sandbox primitive chokepoints) add a `case 'symbol'`
 *    branch that returns `undefined` when `isDangerousCrossRealmSymbol(sym)`
 *    is true on the sandbox side (`!isHost`). Every per-symbol read funnels
 *    through one of these, so any host function whose result transits the
 *    bridge element-by-element loses the dangerous symbol.
 * 2. The `ownKeys` trap reads the raw host keys array via `otherReflectGet`
 *    (instead of wrapping it first), so the dangerous-symbol drop happens
 *    before any undefined could land in the Proxy-invariant-constrained
 *    ownKeys result.
 * 3. `apply` and `construct` traps call `stripDangerousSymbolsFromHostResult`
 *    on raw host container return values before wrapping -- removing any
 *    dangerous symbol that sits as an array element or as a plain-object key
 *    (e.g. the key set of `Object.getOwnPropertyDescriptors`'s return).
 *    This closes bypasses where the sandbox obtains the symbol via a host
 *    enumeration path the per-element filter never sees.
 *
 * The invariant: a dangerous cross-realm symbol primitive must never reach
 * sandbox code as a usable symbol value, regardless of which host primitive
 * produced it (`Object.getOwnPropertySymbols`, `Reflect.ownKeys`,
 * `Object.getOwnPropertyDescriptors`, iterator protocols, throw paths).
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
// Some PoC bodies use Array.prototype.at(), which only landed in Node 16.6+.
// On older Nodes the call throws TypeError before the security check runs,
// producing a false-positive "test failure". Gate them.
const HAS_ARRAY_AT = NODE_MAJOR >= 16;

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) { return cond ? it(name, fn) : it.skip(name, fn); };
}

// Host-side sentinel: a successful RCE escape sets this key on `global`.
// A 300ms tick gives Node's microtask + promise-rejection-unhandled-logging
// paths time to invoke the host-side util.inspect formatter if it is going to.
function escapeAttempt(code) {
	const vm = new VM({ timeout: 2000 });
	const pwnKey = '__GHSA_47x8_pwned_' + Math.random().toString(36).slice(2);
	global[pwnKey] = false;
	try {
		vm.run(code.replace(/__PWN_KEY__/g, JSON.stringify(pwnKey)));
	} catch (_) {
		/* bridge-level throws are also blocked */
	}
	return new Promise(function (resolve) {
		setTimeout(function () {
			const escaped = global[pwnKey] === true;
			delete global[pwnKey];
			resolve(escaped);
		}, 300);
	});
}

// Run a string of sandbox code and swallow any VMError. Returns the result.
function safeRun(code) {
	const vm = new VM();
	try {
		return vm.run('(function () { try { ' + code + ' } catch (_) { return undefined; } })()');
	} catch (_) {
		return undefined;
	}
}

describe('GHSA-47x8-96vw-5wg6 (cross-realm symbol extraction via host Object)', function () {
	// ---- Canonical PoCs from the three advisories --------------------------------

	it('blocks PoC 1 (GHSA-47x8-96vw-5wg6): __lookupGetter__ + Buffer.apply + .at(0)', async function () {
		this.timeout(5000);
		const escaped = await escapeAttempt(`
			try {
				const g = {}.__lookupGetter__;
				const a = Buffer.apply;
				const p = a.apply(g, [Buffer, ['__proto__']]);
				const o = p.call(p.call(a));
				const HObject = o.constructor;
				const sym = HObject.getOwnPropertySymbols(Buffer.prototype).at(0);
				const obj = {
					[sym]: (depth, opt, inspect) => {
						inspect.constructor("global[" + __PWN_KEY__ + "] = true")();
					},
					valueOf: undefined,
					constructor: undefined,
				};
				WebAssembly.compileStreaming(obj).catch(() => {});
			} catch (_) {}
		`);
		assert.strictEqual(escaped, false, 'PoC 1 succeeded');
	});

	it('blocks PoC 2 (GHSA-qcp4-v2jj-fjx8): util.inspect showProxy handler leak', async function () {
		this.timeout(5000);
		const escaped = await escapeAttempt(`
			try {
				let obj = {
					subarray: Buffer.prototype.inspect,
					slice: Buffer.prototype.slice,
					hexSlice: () => '',
				};
				let sym;
				obj.slice(10, {
					showHidden: true,
					showProxy: true,
					depth: 10,
					stylize(a) {
						const handler = this.seen && this.seen[1];
						if (handler && handler.getPrototypeOf) {
							const gP = handler.getPrototypeOf;
							const HObjectProto = gP(gP(gP(gP(Buffer))));
							const HObject = HObjectProto.constructor;
							sym = HObject.getOwnPropertySymbols(Buffer.prototype).at(0);
						}
						return a;
					},
				});
				if (sym) {
					const payload = {
						[sym]: (depth, opt, inspect) => {
							inspect.constructor("global[" + __PWN_KEY__ + "] = true")();
						},
						valueOf: undefined,
						constructor: undefined,
					};
					WebAssembly.compileStreaming(payload).catch(() => {});
				}
			} catch (_) {}
		`);
		assert.strictEqual(escaped, false, 'PoC 2 succeeded');
	});

	it('blocks PoC 3 (GHSA-f539-x546-3726): description-match loop over host symbols', async function () {
		this.timeout(5000);
		const escaped = await escapeAttempt(`
			try {
				const g = ({}).__lookupGetter__;
				const fa = Buffer.apply;
				const pg = fa.apply(g, [Buffer, ['__proto__']]);
				const hop = pg.call(pg.call(pg.call(pg.call(Buffer.of()))));
				const hO = hop.constructor;
				const syms = hO.getOwnPropertySymbols(Buffer.prototype);
				let inspectSym;
				for (let i = 0; i < syms.length; i++) {
					if (syms[i] && syms[i].description === 'nodejs.util.inspect.custom') {
						inspectSym = syms[i];
						break;
					}
				}
				if (inspectSym) {
					const obj = {};
					obj[inspectSym] = (depth, opt, inspect) => {
						const F = inspect.constructor.constructor;
						F("global[" + __PWN_KEY__ + "] = true")();
						return '';
					};
					obj.valueOf = undefined;
					obj.constructor = undefined;
					WebAssembly.compileStreaming(obj).catch(() => {});
				}
			} catch (_) {}
		`);
		assert.strictEqual(escaped, false, 'PoC 3 succeeded');
	});

	// ---- Extraction-path (A*) bypass variants ------------------------------------

	// A1: host Object.getOwnPropertySymbols result surfaces via index access.
	it('A1 - blocks host Object.getOwnPropertySymbols + index read', function () {
		const seen = safeRun(`
			const g = {}.__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			const HObject = o.constructor;
			const syms = HObject.getOwnPropertySymbols(Buffer.prototype);
			let found = false;
			for (let i = 0; i < syms.length; i++) {
				const s = syms[i];
				if (typeof s === 'symbol' && s.description === 'nodejs.util.inspect.custom') {
					found = true; break;
				}
			}
			return found;
		`);
		assert.strictEqual(seen, false, 'A1: dangerous symbol surfaced via index read');
	});

	// A2: `Reflect.ownKeys` on a host object via the bridge (mixing strings + symbols).
	it('A2 - blocks host Reflect.ownKeys via bridge proxy', function () {
		const seen = safeRun(`
			const keys = Reflect.ownKeys(Buffer.prototype);
			let found = false;
			for (let i = 0; i < keys.length; i++) {
				const k = keys[i];
				if (typeof k === 'symbol' && k.description === 'nodejs.util.inspect.custom') {
					found = true; break;
				}
			}
			return found;
		`);
		assert.strictEqual(seen, false, 'A2: dangerous symbol surfaced via Reflect.ownKeys');
	});

	// A3: host Object.getOwnPropertyDescriptors returns a host object whose OWN KEYS
	// include the dangerous symbol. Without the post-apply scrub, the host container
	// still carries the symbol key even if per-element iteration filters it.
	it('A3 - blocks host Object.getOwnPropertyDescriptors key-set extraction', function () {
		const seen = safeRun(`
			const g = {}.__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			const HObject = o.constructor;
			const descs = HObject.getOwnPropertyDescriptors(Buffer.prototype);
			// Extract own symbols of the descriptor object via host Object again.
			const descSyms = HObject.getOwnPropertySymbols(descs);
			let found = false;
			for (let i = 0; i < descSyms.length; i++) {
				const s = descSyms[i];
				if (typeof s === 'symbol' && s.description === 'nodejs.util.inspect.custom') {
					found = true; break;
				}
			}
			return found;
		`);
		assert.strictEqual(seen, false, 'A3: dangerous symbol surfaced via descriptor-object keys');
	});

	// A4: spread iteration on a host array of symbols (iterator protocol path).
	it('A4 - blocks spread/iterator extraction of host symbol array', function () {
		const seen = safeRun(`
			const g = {}.__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			const HObject = o.constructor;
			const arr = [...HObject.getOwnPropertySymbols(Buffer.prototype)];
			let found = false;
			for (let i = 0; i < arr.length; i++) {
				const s = arr[i];
				if (typeof s === 'symbol' && s.description === 'nodejs.util.inspect.custom') {
					found = true; break;
				}
			}
			return found;
		`);
		assert.strictEqual(seen, false, 'A4: dangerous symbol surfaced via spread');
	});

	// A5: iterate a host Map-like structure. We don't have direct access to a host
	// Map from the sandbox, but we can simulate the shape by calling
	// `Array.prototype.entries` on a host array and pulling values out. If an
	// iterator-return path were still raw, the dangerous symbol would leak here.
	it('A5 - blocks iterator (.entries) extraction of host symbol array', function () {
		const seen = safeRun(`
			const g = {}.__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			const HObject = o.constructor;
			const syms = HObject.getOwnPropertySymbols(Buffer.prototype);
			const iter = syms.entries();
			let found = false;
			let step = iter.next();
			while (!step.done) {
				const s = step.value[1];
				if (typeof s === 'symbol' && s.description === 'nodejs.util.inspect.custom') {
					found = true; break;
				}
				step = iter.next();
			}
			return found;
		`);
		assert.strictEqual(seen, false, 'A5: dangerous symbol surfaced via iterator');
	});

	// A6: throw path. A host function that throws a raw symbol must not surface the
	// symbol in the sandbox's catch binding.
	it('A6 - blocks host throw of a dangerous symbol', function () {
		const seen = safeRun(`
			const inspectSym = Symbol.for('nodejs.util.inspect.custom'); // sandbox override returns safe symbol
			// Cause a host function to be called in a way that surfaces host cross-realm
			// symbols on an error path. Node may attach the symbol to an error's .cause
			// or similar; the catch block must never see a real host cross-realm symbol.
			// We attempt to harvest any symbol from a thrown host error.
			let harvested = undefined;
			try {
				const g = {}.__lookupGetter__;
				const a = Buffer.apply;
				const p = a.apply(g, [Buffer, ['__proto__']]);
				const o = p.call(p.call(a));
				const HObject = o.constructor;
				// Throw a TypeError from host by calling with an invalid receiver.
				HObject.getOwnPropertySymbols.call(undefined);
			} catch (e) {
				// Walk the error's own symbols.
				const syms = Object.getOwnPropertySymbols(e);
				for (let i = 0; i < syms.length; i++) {
					const s = syms[i];
					if (typeof s === 'symbol' && (s.description === 'nodejs.util.inspect.custom' || s.description === 'nodejs.rejection')) {
						harvested = s;
					}
				}
			}
			return harvested !== undefined;
		`);
		assert.strictEqual(seen, false, 'A6: dangerous symbol surfaced from throw path');
	});

	// ---- Usage-path (B*) bypass variants -----------------------------------------

	// B1: plain assignment `obj[sym] = fn` must not install the host symbol as a key.
	it.cond('B1 - keyed assignment with extracted symbol becomes string "undefined"', HAS_ARRAY_AT, function () {
		const result = safeRun(`
			const g = {}.__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			const HObject = o.constructor;
			const sym = HObject.getOwnPropertySymbols(Buffer.prototype).at(0);
			const obj = {};
			obj[sym] = 'installed';
			// If sym was filtered to undefined, obj has the string key 'undefined'.
			// If the real host symbol leaked, obj has a symbol key whose description
			// is 'nodejs.util.inspect.custom'.
			const syms = Object.getOwnPropertySymbols(obj);
			for (let i = 0; i < syms.length; i++) {
				if (syms[i].description === 'nodejs.util.inspect.custom') return true;
			}
			return false;
		`);
		assert.strictEqual(result, false, 'B1: dangerous symbol installed as key via assignment');
	});

	// B2: defineProperty with an extracted symbol also must not install it.
	it.cond('B2 - defineProperty with extracted symbol cannot install dangerous symbol key', HAS_ARRAY_AT, function () {
		const result = safeRun(`
			const g = {}.__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			const HObject = o.constructor;
			const sym = HObject.getOwnPropertySymbols(Buffer.prototype).at(0);
			const obj = {};
			try { Object.defineProperty(obj, sym, { value: 1 }); } catch (_) {}
			const syms = Object.getOwnPropertySymbols(obj);
			for (let i = 0; i < syms.length; i++) {
				if (syms[i].description === 'nodejs.util.inspect.custom') return true;
			}
			return false;
		`);
		assert.strictEqual(result, false, 'B2: dangerous symbol installed via defineProperty');
	});

	// B3: computed key in an object literal `{[sym]: fn}`.
	it.cond('B3 - object literal computed key with extracted symbol cannot install', HAS_ARRAY_AT, function () {
		const result = safeRun(`
			const g = {}.__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			const HObject = o.constructor;
			const sym = HObject.getOwnPropertySymbols(Buffer.prototype).at(0);
			const obj = { [sym]: 'x' };
			const syms = Object.getOwnPropertySymbols(obj);
			for (let i = 0; i < syms.length; i++) {
				if (syms[i].description === 'nodejs.util.inspect.custom') return true;
			}
			return false;
		`);
		assert.strictEqual(result, false, 'B3: dangerous symbol installed via literal');
	});

	// B4: Reflect.set with an extracted symbol.
	it.cond('B4 - Reflect.set with extracted symbol cannot install dangerous key', HAS_ARRAY_AT, function () {
		const result = safeRun(`
			const g = {}.__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			const HObject = o.constructor;
			const sym = HObject.getOwnPropertySymbols(Buffer.prototype).at(0);
			const obj = {};
			try { Reflect.set(obj, sym, 'x'); } catch (_) {}
			const syms = Object.getOwnPropertySymbols(obj);
			for (let i = 0; i < syms.length; i++) {
				if (syms[i].description === 'nodejs.util.inspect.custom') return true;
			}
			return false;
		`);
		assert.strictEqual(result, false, 'B4: dangerous symbol installed via Reflect.set');
	});

	// ---- Global invariant check --------------------------------------------------

	it('invariant: dangerous nodejs.util.inspect.custom never reaches sandbox via host primitives', function () {
		const result = safeRun(`
			const TARGET = 'nodejs.util.inspect.custom';
			const g = {}.__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			const HObject = o.constructor;
			function scan(arr) {
				if (!arr || typeof arr.length !== 'number') return false;
				for (let i = 0; i < arr.length; i++) {
					const v = arr[i];
					if (typeof v === 'symbol' && v.description === TARGET) return true;
				}
				return false;
			}
			const viaGOPS = HObject.getOwnPropertySymbols(Buffer.prototype);
			const viaSpread = [...viaGOPS];
			const descs = HObject.getOwnPropertyDescriptors(Buffer.prototype);
			const viaDescsGOPS = HObject.getOwnPropertySymbols(descs);
			return scan(viaGOPS) || scan(viaSpread) || scan(viaDescsGOPS);
		`);
		assert.strictEqual(result, false, 'invariant violated: dangerous symbol reached sandbox');
	});

	it('invariant: nodejs.rejection also blocked', function () {
		const result = safeRun(`
			const g = {}.__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			const HObject = o.constructor;
			const scanTargets = [Buffer.prototype, Buffer, o];
			for (let t = 0; t < scanTargets.length; t++) {
				const syms = HObject.getOwnPropertySymbols(scanTargets[t]);
				for (let i = 0; i < syms.length; i++) {
					const s = syms[i];
					if (typeof s === 'symbol' && s.description === 'nodejs.rejection') return true;
				}
			}
			return false;
		`);
		assert.strictEqual(result, false, 'nodejs.rejection symbol reached sandbox');
	});
});
