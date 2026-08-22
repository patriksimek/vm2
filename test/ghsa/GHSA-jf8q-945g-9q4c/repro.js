/**
 * GHSA-jf8q-945g-9q4c — Sandbox escape via unblocked `nodejs.stream.{disturbed,errored}`
 *                       cross-realm brand symbols
 *
 * ## Vulnerability class
 * Same family as GHSA-m5q2-4fm3-vfqp. Node stores a web stream's consumed /
 * errored state under the accessor symbols `Symbol.for('nodejs.stream.disturbed')`
 * and `Symbol.for('nodejs.stream.errored')`, installed on `ReadableStream.prototype`.
 * `stream.Readable.isDisturbed(s)` reads `s[kIsDisturbed]` DIRECTLY off the raw
 * object:
 *
 *     function isDisturbed(stream) {
 *       return !!(stream && (
 *         stream[kIsDisturbed] ??               // <-- our target
 *         (stream.readableDidRead || stream.readableAborted)));
 *     }
 *
 * The prototype accessor's getter returns `this[kState].disturbed`. Because it is
 * `configurable: true` and has no setter, sandbox code can shadow it with an OWN
 * data property valued `false` on the host stream instance — `false` is not
 * nullish, so the `??` short-circuits and `isDisturbed` flips true -> false.
 *
 * These two symbols were ABSENT from vm2's fixed dangerous-`nodejs.*`-symbol
 * lists (`isDangerousCrossRealmSymbol` in bridge.js and `realDangerousSymbols`
 * in setup-sandbox.js), so:
 *   - the READ-side extraction filter did not strip them from
 *     `Object.getOwnPropertySymbols(ReadableStream.prototype)` reached through
 *     the bridge, and
 *   - the WRITE-side `set` / `defineProperty` / `deleteProperty` traps did not
 *     reject them as property keys.
 *
 * Given a host stream exposed via `vm.sandbox.rs`, sandbox code could extract the
 * symbol and `Object.defineProperty(rs, sym, {value:false})` to reset the host's
 * `isDisturbed(rs)` to false after full consumption.
 *
 * ## Fix
 * Add `nodejs.stream.disturbed` and `nodejs.stream.errored` to every fixed list
 * that enumerates dangerous cross-realm `nodejs.*` symbols:
 *   - `lib/bridge.js` — `isDangerousCrossRealmSymbol` (drives the write traps and
 *     the read-side `get`/`has`/`ownKeys`/`getOwnPropertyDescriptor` filters).
 *   - `lib/setup-sandbox.js` — `realDangerousSymbols` (drives the
 *     `getOwnPropertySymbols` / `Reflect.ownKeys` / `getOwnPropertyDescriptors`
 *     extraction filters). The `Symbol.for` namespace override already denies the
 *     whole `nodejs.` prefix, so re-registration was covered; the extraction and
 *     write paths are what this fix closes.
 *
 * ## Sound oracle
 * Host-side `stream.Readable.isDisturbed(rs)` — it must stay `true` after every
 * sandbox attempt.
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) { return cond ? it(name, fn) : it.skip(name, fn); };
}

// Web streams (`stream/web`) landed in Node 16.5 (experimental) / 18 (stable).
// `stream.Readable.isDisturbed` exists since Node 16. The `nodejs.stream.disturbed`
// symbol form of the state is 18+. Gate on the actual capability rather than a
// version number so older Node skips gracefully.
let HAS_WEB_STREAMS = false;
let ReadableStream;
let streamModule;
try {
	streamModule = require('stream');
	ReadableStream = require('stream/web').ReadableStream;
	HAS_WEB_STREAMS = !!ReadableStream &&
		typeof streamModule.Readable.isDisturbed === 'function' &&
		Object.getOwnPropertySymbols(ReadableStream.prototype)
			.some(function (s) { return s.description === 'nodejs.stream.disturbed'; });
} catch (_) {
	HAS_WEB_STREAMS = false;
}

// Build a host web ReadableStream and consume it fully so isDisturbed === true.
function makeDisturbedStream() {
	const rs = new ReadableStream({
		start: function (c) { c.enqueue(1); c.close(); },
	});
	const reader = rs.getReader();
	return reader.read().then(function () {
		// After one read of a closed single-chunk stream, disturbed is set.
		assert.strictEqual(streamModule.Readable.isDisturbed(rs), true,
			'precondition: freshly consumed host stream must be disturbed');
		return rs;
	});
}

describe('GHSA-jf8q-945g-9q4c (nodejs.stream.{disturbed,errored} cross-realm symbol leak)', function () {

	// ---- PRIMARY PoC: flip host isDisturbed via the extracted symbol ------------------

	it.cond('blocks PoC: sandbox cannot flip host isDisturbed via extracted symbol', HAS_WEB_STREAMS, function () {
		return makeDisturbedStream().then(function (rs) {
			const vm = new VM();
			vm.sandbox.rs = rs;
			// Real-world exposure: the host also hands the sandbox the stream class /
			// prototype (the object that actually carries the `disturbed` accessor
			// symbol as an own key). This is the extraction source the advisory names.
			vm.sandbox.proto = ReadableStream.prototype;

			// Sandbox extracts the disturbed symbol off the host prototype (reached
			// through the bridge) and tries all three write primitives with it.
			vm.run(`
				const syms = Object.getOwnPropertySymbols(proto)
					.filter(s => s.description === 'nodejs.stream.disturbed');
				// After the fix, extraction filters the real symbol out — but even if a
				// sandbox-local symbol survives, none of these writes may touch host state.
				for (const sym of syms) {
					try { rs[sym] = false; } catch (_) {}
					try { Object.defineProperty(rs, sym, { value: false, configurable: true }); } catch (_) {}
					try { Reflect.set(rs, sym, false); } catch (_) {}
				}
				// Also try the reconstructed symbol via Symbol.for (namespace-denied).
				try { Object.defineProperty(rs, Symbol.for('nodejs.stream.disturbed'), { value: false, configurable: true }); } catch (_) {}
				try { rs[Symbol.for('nodejs.stream.disturbed')] = false; } catch (_) {}
			`);

			// Sound oracle: host-side isDisturbed must remain true.
			assert.strictEqual(streamModule.Readable.isDisturbed(rs), true,
				'sandbox flipped host isDisturbed back to false');
		});
	});

	// ---- Write-trap denial with the REAL host symbol handed in directly ---------------
	//
	// Independent of the extraction filter: pass the genuine host symbol into the
	// sandbox and confirm the bridge write traps reject it as a key on a host object.

	it.cond('write traps: real nodejs.stream.disturbed symbol denied on host stream', HAS_WEB_STREAMS, function () {
		return makeDisturbedStream().then(function (rs) {
			const realSym = Object.getOwnPropertySymbols(Object.getPrototypeOf(rs))
				.filter(function (s) { return s.description === 'nodejs.stream.disturbed'; })[0];
			assert.ok(realSym, 'host symbol should exist');

			const vm = new VM();
			vm.sandbox.rs = rs;
			vm.sandbox.realSym = realSym;

			try { vm.run(`rs[realSym] = false;`); } catch (_) {}
			try { vm.run(`Object.defineProperty(rs, realSym, { value: false, configurable: true });`); } catch (_) {}
			try { vm.run(`Reflect.set(rs, realSym, false);`); } catch (_) {}

			assert.strictEqual(streamModule.Readable.isDisturbed(rs), true,
				'bridge write trap allowed the real disturbed symbol onto host stream');
			assert.strictEqual(
				Object.prototype.hasOwnProperty.call(rs, realSym), false,
				'sandbox installed the disturbed symbol as an own property on host stream');
		});
	});

	it.cond('write traps: real nodejs.stream.errored symbol denied on host object', HAS_WEB_STREAMS, function () {
		const realSym = Symbol.for('nodejs.stream.errored');
		const hostObj = { [realSym]: 'host-set' };
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;
		vm.sandbox.realSym = realSym;
		try { vm.run(`hostObj[realSym] = 'set';`); } catch (_) {}
		try { vm.run(`Object.defineProperty(hostObj, realSym, { value: 'def' });`); } catch (_) {}
		try { vm.run(`delete hostObj[realSym];`); } catch (_) {}
		assert.strictEqual(hostObj[realSym], 'host-set',
			'nodejs.stream.errored write/delete leaked through bridge');
	});

	// ---- Source-side / extraction denial ---------------------------------------------

	it.cond('Symbol.for("nodejs.stream.disturbed") returns sandbox-local symbol', HAS_WEB_STREAMS, function () {
		const vm = new VM();
		const leaked = vm.run(`
			(function () {
				try { return Symbol.keyFor(Symbol.for('nodejs.stream.disturbed')) !== undefined; }
				catch (_) { return false; }
			})()
		`);
		assert.strictEqual(leaked, false, 'nodejs.stream.disturbed leaked as a real cross-realm symbol');
	});

	it.cond('Symbol.for("nodejs.stream.errored") returns sandbox-local symbol', HAS_WEB_STREAMS, function () {
		const vm = new VM();
		const leaked = vm.run(`
			(function () {
				try { return Symbol.keyFor(Symbol.for('nodejs.stream.errored')) !== undefined; }
				catch (_) { return false; }
			})()
		`);
		assert.strictEqual(leaked, false, 'nodejs.stream.errored leaked as a real cross-realm symbol');
	});

	it.cond('extraction: disturbed/errored symbols filtered from host prototype view', HAS_WEB_STREAMS, function () {
		const vm = new VM();
		vm.sandbox.proto = ReadableStream.prototype;
		// The sandbox-side getOwnPropertySymbols / Reflect.ownKeys overrides must strip
		// the dangerous symbols so they never surface (by identity) to sandbox code.
		const descriptions = vm.run(`
			Object.getOwnPropertySymbols(proto).map(s => s.description)
		`);
		assert.ok(Array.isArray(descriptions));
		assert.strictEqual(descriptions.indexOf('nodejs.stream.disturbed'), -1,
			'nodejs.stream.disturbed symbol surfaced to sandbox extraction');
		assert.strictEqual(descriptions.indexOf('nodejs.stream.errored'), -1,
			'nodejs.stream.errored symbol surfaced to sandbox extraction');
	});

	// ---- No over-blocking: benign non-nodejs.* symbols still cross --------------------

	it('benign non-"nodejs." symbols still cross the bridge normally', function () {
		const benignSym = Symbol.for('user.app.disturbed'); // description contains "disturbed" but not nodejs.*
		const hostObj = {};
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;
		vm.sandbox.benignSym = benignSym;
		vm.run(`hostObj[benignSym] = 'crossed';`);
		assert.strictEqual(hostObj[benignSym], 'crossed',
			'benign non-nodejs symbol was wrongly blocked (over-blocking)');

		// And a well-known symbol keeps working.
		const withIterator = vm.run(`
			const o = {};
			o[Symbol.iterator] = function* () { yield 1; yield 2; };
			Array.from(o);
		`);
		assert.deepStrictEqual(Array.from(withIterator), [1, 2],
			'well-known Symbol.iterator wrongly blocked');
	});

	// ---- Namespace catch-all: a nodejs.* symbol NOT in the explicit list is also blocked ----
	// This is the forward-looking guarantee: the filter is
	// namespace-based, so a future Node `nodejs.*` registered symbol cannot recur as a gap.

	it('a nodejs.* symbol not in the explicit list is still filtered from extraction and writes', function () {
		const novel = Symbol.for('nodejs.futuristic.brand'); // registered, nodejs.* namespace, NOT in vm2's list
		const hostObj = {};
		hostObj[novel] = 'HOST-VALUE';
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;
		const out = vm.run(`
			const keys = Object.getOwnPropertySymbols(hostObj).map(s => Symbol.keyFor(s));
			// Attempt to extract and write the novel nodejs.* symbol back onto the host object.
			let reWritten = false;
			const nv = Object.getOwnPropertySymbols(hostObj).find(s => Symbol.keyFor(s) === 'nodejs.futuristic.brand');
			if (nv) { try { hostObj[nv] = 'PWN'; } catch (e) {} reWritten = hostObj[nv] === 'PWN'; }
			({ extracted: keys.indexOf('nodejs.futuristic.brand') !== -1, reWritten });
		`);
		assert.strictEqual(out.extracted, false, 'a novel nodejs.* symbol was extractable from a host object');
		assert.strictEqual(hostObj[novel], 'HOST-VALUE', 'a novel nodejs.* symbol write reached the host object');
	});
});
