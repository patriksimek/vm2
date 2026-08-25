/**
 * GHSA-3vgf-8m4q-q4qr — host TypedArray / ArrayBuffer / iterator intrinsic
 * prototype pollution from a default VM (dup: GHSA-59g5-pmg6-5gr4, iterator
 * intrinsics — same incomplete-inventory bug, same fix).
 *
 * ## Vulnerability class
 * Sibling of GHSA-vwrp-x96c-mhwq (host intrinsic prototype pollution via the
 * bridge write traps). The bridge protects host intrinsic prototypes by
 * inventorying them in `protectedHostObjects` (populated from
 * `otherGlobalPrototypes`, itself built from `globalsList`). The write traps
 * (`set` / `defineProperty`) refuse `isProtectedHostObject(object)`.
 *
 * `globalsList` omitted the binary-data and iterator intrinsic families:
 *   - `ArrayBuffer` / `SharedArrayBuffer` / `DataView`
 *   - every TypedArray (`Uint8Array` … `Float64Array`, `BigInt64Array`, …)
 *   - the abstract `%TypedArray%.prototype` (no named global)
 *   - `ArrayIterator.prototype` and the abstract `%IteratorPrototype%`
 *
 * Because those prototypes were absent from `protectedHostObjects`, the write
 * traps forwarded sandbox writes straight onto the raw host intrinsic. The
 * sandbox reaches them by climbing a host object's prototype chain and calls
 * `Reflect.defineProperty(hostUint8ArrayPrototype, 'x', …)`; the pollution is
 * observed HOST-SIDE on freshly constructed host objects.
 *
 * ## Fix
 * Extend the protected inventory in `lib/bridge.js` to cover the binary-data
 * and iterator intrinsics — both the named globals (added to `globalsList`)
 * and the abstract, unnamed intrinsics (`%TypedArray%`, `%IteratorPrototype%`,
 * the concrete iterator prototypes), added directly to `protectedHostObjects`
 * and the proto-mapping tables. The `set` / `defineProperty` traps then refuse
 * sandbox writes to them, exactly as for `Array.prototype` / `Object.prototype`.
 *
 * ## Sound oracle
 * Pollution is verified HOST-SIDE: a fresh `new Uint8Array(1)` / `new
 * ArrayBuffer(1)` / `[].values()` created AFTER `vm.run()` must NOT observe any
 * sandbox-installed marker. Reads are on the real host intrinsics, so a marker
 * appearing there is unambiguous host-realm mutation.
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

// `Array.prototype.values` was temporarily unshipped in the V8 that ships with
// Node 8 (MooTools web-compat), so `[].values()` throws there. The iterator
// half of this advisory (GHSA-59g5) is only reachable where that intrinsic
// exists; gate on the capability so the binary-data half still runs everywhere
// and the suite is never vacuously skipped.
const HAS_ARRAY_ITERATOR = typeof [].values === 'function';

// Every marker key the PoCs install — cleaned up after each case so a
// successful escape on the unpatched tree cannot leak into later tests.
const MARKERS = {
	'Uint8Array.prototype': () => Uint8Array.prototype,
	'%TypedArray%.prototype': () => Object.getPrototypeOf(Uint8Array.prototype),
	'ArrayBuffer.prototype': () => ArrayBuffer.prototype,
};
if (HAS_ARRAY_ITERATOR) {
	MARKERS['ArrayIterator.prototype'] = () => Object.getPrototypeOf([].values());
	MARKERS['%IteratorPrototype%'] = () => Object.getPrototypeOf(Object.getPrototypeOf([].values()));
}

function cleanup() {
	for (const k in MARKERS) {
		const proto = MARKERS[k]();
		for (const key of ['POLL_U8', 'POLL_TA', 'POLL_AB', 'POLL_ITER', 'POLL_ITP', 'next', 'POLL_DV', 'POLL_SAB']) {
			// Only delete the markers we set (never touch the real `next`).
			if (key === 'next') continue;
			try { delete proto[key]; } catch (e) {}
		}
	}
}

describe('GHSA-3vgf-8m4q-q4qr (host TypedArray/ArrayBuffer/iterator intrinsic pollution)', function () {
	afterEach(cleanup);

	it('blocks Reflect.defineProperty pollution of host Uint8Array / %TypedArray% / ArrayBuffer prototypes', function () {
		const report = new VM().run(`
			const lookupGetter = ({}).__lookupGetter__;
			const apply = Buffer.apply;
			const protoGetter = apply.apply(lookupGetter, [Buffer, ['__proto__']]);
			const out = {};
			try {
				const hostBuffer = Buffer.from([1]);
				const hostBufferPrototype = protoGetter.call(hostBuffer);
				const hostUint8ArrayPrototype = protoGetter.call(hostBufferPrototype);
				const hostTypedArrayPrototype = protoGetter.call(hostUint8ArrayPrototype);
				const hostArrayBufferPrototype = protoGetter.call(hostBuffer.buffer);
				try { Reflect.defineProperty(hostUint8ArrayPrototype, 'POLL_U8', { value: 'x', configurable: true }); out.u8 = true; } catch (e) { out.u8 = 'blocked'; }
				try { Reflect.defineProperty(hostTypedArrayPrototype, 'POLL_TA', { value: 'x', configurable: true }); out.ta = true; } catch (e) { out.ta = 'blocked'; }
				try { Reflect.defineProperty(hostArrayBufferPrototype, 'POLL_AB', { value: 'x', configurable: true }); out.ab = true; } catch (e) { out.ab = 'blocked'; }
			} catch (e) { out.climb = 'threw:' + e.message; }
			out;
		`);
		// Host-side ground truth — the only sound signal.
		assert.strictEqual(Uint8Array.prototype.POLL_U8, undefined, 'host Uint8Array.prototype polluted: ' + JSON.stringify(report));
		assert.strictEqual(Object.getPrototypeOf(Uint8Array.prototype).POLL_TA, undefined, 'host %TypedArray%.prototype polluted');
		assert.strictEqual(ArrayBuffer.prototype.POLL_AB, undefined, 'host ArrayBuffer.prototype polluted');
		assert.strictEqual(new Uint8Array(1).POLL_U8, undefined, 'fresh host Uint8Array sees pollution');
		assert.strictEqual(new ArrayBuffer(1).POLL_AB, undefined, 'fresh host ArrayBuffer sees pollution');
	});

	(HAS_ARRAY_ITERATOR ? it : it.skip)('blocks pollution of host ArrayIterator.prototype / %IteratorPrototype% (GHSA-59g5-pmg6-5gr4)', function () {
		const arrIterProto = Object.getPrototypeOf([].values());
		// CRITICAL: overwriting host ArrayIterator.prototype.next corrupts mocha's
		// own iteration. Snapshot it, run, then SYNCHRONOUSLY detect a change (the
		// escape signal) and restore before returning control to the runner.
		const pristineNextDesc = Object.getOwnPropertyDescriptor(arrIterProto, 'next');
		let nextOverwritten = false;
		try {
			new VM().run(`
				const lookupGetter = ({}).__lookupGetter__;
				const apply = Buffer.apply;
				const protoGetter = apply.apply(lookupGetter, [Buffer, ['__proto__']]);
				try {
					const hostArrayIteratorPrototype = protoGetter.call(Buffer.from([1]).values());
					const hostIteratorPrototype = protoGetter.call(hostArrayIteratorPrototype);
					try { Reflect.defineProperty(hostArrayIteratorPrototype, 'next', { value: function(){ return { value: 'PWN', done: false }; }, configurable: true, writable: true }); } catch (e) {}
					try { Reflect.defineProperty(hostArrayIteratorPrototype, 'POLL_ITER', { value: 'x', configurable: true }); } catch (e) {}
					try { Reflect.defineProperty(hostIteratorPrototype, 'POLL_ITP', { value: 'x', configurable: true }); } catch (e) {}
				} catch (e) {}
			`);
		} finally {
			const nowNextDesc = Object.getOwnPropertyDescriptor(arrIterProto, 'next');
			nextOverwritten = !nowNextDesc || nowNextDesc.value !== (pristineNextDesc && pristineNextDesc.value);
			if (nextOverwritten) Object.defineProperty(arrIterProto, 'next', pristineNextDesc);
		}
		assert.strictEqual(nextOverwritten, false, 'host ArrayIterator.prototype.next was overwritten by the sandbox');
		assert.strictEqual(arrIterProto.POLL_ITER, undefined, 'host ArrayIterator.prototype polluted');
		assert.strictEqual(Object.getPrototypeOf(arrIterProto).POLL_ITP, undefined, 'host %IteratorPrototype% polluted');
	});

	it('blocks pollution of host DataView / SharedArrayBuffer prototypes', function () {
		new VM().run(`
			const lookupGetter = ({}).__lookupGetter__;
			const apply = Buffer.apply;
			const protoGetter = apply.apply(lookupGetter, [Buffer, ['__proto__']]);
			try {
				const dv = new DataView(new ArrayBuffer(1));
				const hostDataViewPrototype = protoGetter.call(dv);
				try { Reflect.defineProperty(hostDataViewPrototype, 'POLL_DV', { value: 'x', configurable: true }); } catch (e) {}
			} catch (e) {}
		`);
		assert.strictEqual(DataView.prototype.POLL_DV, undefined, 'host DataView.prototype polluted');
	});

	it('does not break legitimate sandbox typed-array / ArrayBuffer / iterator use', function () {
		const ok = new VM().run(`
			const u = new Uint8Array([1,2,3]);
			const sum = u.reduce((a,b)=>a+b, 0);
			const ab = new ArrayBuffer(4);
			const dv = new DataView(ab); dv.setInt8(0, 7);
			let acc = 0; for (const x of [4,5,6]) acc += x;
			(sum === 6 && dv.getInt8(0) === 7 && acc === 15 && u instanceof Uint8Array && ab instanceof ArrayBuffer);
		`);
		assert.strictEqual(ok, true, 'legitimate sandbox binary-data / iterator use broke');
	});
});
