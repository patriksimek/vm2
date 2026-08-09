'use strict';

/**
 * GHSA-v836-6xw4-9cx3 — bufferAllocLimit bypass via ArrayBuffer / SharedArrayBuffer /
 * TypedArray constructors (host memory-exhaustion DoS)
 *
 * ## Vulnerability
 * The `bufferAllocLimit` defense (GHSA-6785-pvv7-mvg7) only wraps the `Buffer.*`
 * family. `new ArrayBuffer(N)`, `new SharedArrayBuffer(N)`, and every TypedArray
 * constructor (`new Uint8Array(N)`, `new Float64Array(N)`, …) allocate host
 * backing-store memory through the SAME synchronous, timeout-immune V8 C++ path,
 * yet are NOT subject to the cap. A single ~200-byte payload amplifies into
 * gigabytes of host RSS in one uninterruptible allocation, OOM-killing the host
 * in memory-constrained environments. `WebAssembly.Memory({initial:N})` is the
 * same primitive (64 KiB host pages).
 *
 * ## Fix
 * When a finite `bufferAllocLimit` is configured, setup-sandbox.js wraps each
 * sandbox-realm allocation constructor with a `construct`-trapping Proxy that
 * checks the requested byte size against the cap before the native allocation,
 * and pins every `prototype.constructor` back-reference to the wrapper so the
 * original uncapped intrinsic cannot be recovered through a constructor walk
 * (`new Uint8Array(0).buffer.constructor`). With the default `Infinity` cap the
 * native intrinsics are left untouched (no behavioural/identity change).
 */

const assert = require('assert');
const { VM, NodeVM } = require('../../../lib/main.js');

const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
// Real ≥64 MB allocations crash older Node runtimes with tighter default heaps.
const LARGE_ALLOC_RUNS = NODE_MAJOR >= 12;
const HAS_SHARED_AB = typeof SharedArrayBuffer === 'function';
const HAS_FLOAT16 = typeof Float16Array === 'function';
const HAS_BIGINT64 = typeof BigInt64Array === 'function';
const HAS_RESIZABLE_AB = (function () {
	try {
		const probe = new ArrayBuffer(8, { maxByteLength: 16 });
		return probe.maxByteLength === 16;
	} catch (e) {
		return false;
	}
})();
const HAS_WASM_MEMORY = typeof WebAssembly !== 'undefined' && typeof WebAssembly.Memory === 'function';

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

// Arrays returned from the sandbox cross the bridge as proxies whose own-key
// enumeration also surfaces the index properties (README "Known Issues":
// "Logging sandbox arrays will repeat the array part in the properties"). On
// Node < 18 that makes `assert.deepStrictEqual` report a difference even when
// every element matches. This is long-standing bridge behaviour, unrelated to
// the allocation caps -- it reproduces identically with and without a finite
// `bufferAllocLimit` -- so compare a host-realm copy of the elements instead.
function plainArray(arr) {
	const out = [];
	for (let i = 0; i < arr.length; i++) out.push(arr[i]);
	return out;
}

const CAP_RE = /Buffer allocation size \d+ exceeds bufferAllocLimit/;

describe('GHSA-v836-6xw4-9cx3 (ArrayBuffer/TypedArray bufferAllocLimit bypass)', function () {
	const CAP = 32 * 1024 * 1024;
	const BIG = 1024 * 1024 * 100; // 100 MB worth of elements

	describe('configured cap blocks oversized backing-store allocations', function () {
		it('rejects new ArrayBuffer(100 MB)', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new ArrayBuffer(' + BIG + ').byteLength');
			}, CAP_RE);
		});

		it.cond('rejects new SharedArrayBuffer(100 MB)', HAS_SHARED_AB, function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new SharedArrayBuffer(' + BIG + ').byteLength');
			}, CAP_RE);
		});

		it('rejects new Uint8Array(100 MB)', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new Uint8Array(' + BIG + ').length');
			}, CAP_RE);
		});

		it('rejects new Float64Array (100 MB → ×8 bytes)', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				// 5 M elements × 8 bytes = 40 MB > 32 MB cap.
				vm.run('new Float64Array(5 * 1024 * 1024).length');
			}, CAP_RE);
		});

		it('rejects new Int32Array (cap counts bytes, not elements)', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				// 9 M elements × 4 bytes = 36 MB > 32 MB cap.
				vm.run('new Int32Array(9 * 1024 * 1024).length');
			}, CAP_RE);
		});

		it.cond('rejects new BigInt64Array (×8 bytes)', HAS_BIGINT64, function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new BigInt64Array(5 * 1024 * 1024).length');
			}, CAP_RE);
		});

		it.cond('rejects new Float16Array (×2 bytes)', HAS_FLOAT16, function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new Float16Array(20 * 1024 * 1024).length');
			}, CAP_RE);
		});
	});

	describe('constructor-walk recovery of the uncapped intrinsic is blocked', function () {
		it('new Uint8Array(0).buffer.constructor is the capped ArrayBuffer', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('var AB = new Uint8Array(0).buffer.constructor; new AB(' + BIG + ').byteLength');
			}, CAP_RE);
		});

		it('Uint8Array.prototype.constructor is the capped wrapper', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('var TA = Uint8Array.prototype.constructor; new TA(' + BIG + ').length');
			}, CAP_RE);
		});

		it('ArrayBuffer.prototype.constructor is the capped wrapper', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('var AB = ArrayBuffer.prototype.constructor; new AB(' + BIG + ').byteLength');
			}, CAP_RE);
		});

		it('Reflect.construct on the recovered constructor is still capped', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('Reflect.construct(Uint8Array, [' + BIG + ']).length');
			}, CAP_RE);
		});

		it('species-derived subclass cannot escape the cap', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('class Big extends Uint8Array {}; new Big(' + BIG + ').length');
			}, CAP_RE);
		});
	});

	describe('resizable/growable buffers (maxByteLength reservation)', function () {
		it.cond('rejects new ArrayBuffer(8, {maxByteLength: 100 MB})', HAS_RESIZABLE_AB, function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new ArrayBuffer(8, { maxByteLength: ' + BIG + ' }).maxByteLength');
			}, CAP_RE);
		});

		it.cond(
			'rejects new SharedArrayBuffer(8, {maxByteLength: 100 MB})',
			HAS_SHARED_AB && HAS_RESIZABLE_AB,
			function () {
				const vm = new VM({ bufferAllocLimit: CAP });
				assert.throws(function () {
					vm.run('new SharedArrayBuffer(8, { maxByteLength: ' + BIG + ' }).maxByteLength');
				}, CAP_RE);
			},
		);
	});

	describe('WebAssembly.Memory (same backing-store DoS class)', function () {
		it.cond('rejects new WebAssembly.Memory({initial: 2000 pages ≈ 128 MB})', HAS_WASM_MEMORY, function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				// 2000 × 64 KiB = ~131 MB > 32 MB cap.
				vm.run('new WebAssembly.Memory({ initial: 2000 }).buffer.byteLength');
			}, CAP_RE);
		});

		it.cond('rejects memory.grow() past the cap', HAS_WASM_MEMORY, function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('var m = new WebAssembly.Memory({ initial: 1 }); m.grow(2000)');
			}, CAP_RE);
		});
	});

	describe('legitimate small allocations still work under the cap', function () {
		it('small ArrayBuffer is allowed and behaves natively', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			const r = vm.run('var a = new ArrayBuffer(64); a.byteLength');
			assert.strictEqual(r, 64);
		});

		it('small typed array is allowed and instanceof holds', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			const r = vm.run('var a = new Uint8Array(8); [a.length, a instanceof Uint8Array, a.buffer instanceof ArrayBuffer]');
			assert.deepStrictEqual(plainArray(r), [8, true, true]);
		});

		it('TypedArray view over an existing buffer is not double-counted', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			const r = vm.run('var b = new ArrayBuffer(16); new Uint8Array(b, 4, 8).length');
			assert.strictEqual(r, 8);
		});

		it('TypedArray from array literal is allowed', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			const r = vm.run('Array.from(new Uint8Array([1,2,3,4]))');
			assert.deepStrictEqual(plainArray(r), [1, 2, 3, 4]);
		});

		it('typed-array .slice() of a within-cap array still works', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			const r = vm.run('Array.from(new Uint8Array([1,2,3,4,5]).slice(1, 3))');
			assert.deepStrictEqual(plainArray(r), [2, 3]);
		});
	});

	describe('default (Infinity) leaves intrinsics untouched — non-breaking', function () {
		it('no cap: ArrayBuffer is the native intrinsic (identity preserved)', function () {
			const vm = new VM();
			const r = vm.run('ArrayBuffer.prototype.constructor === ArrayBuffer');
			assert.strictEqual(r, true);
		});

		it.cond('no cap: large ArrayBuffer is allowed', LARGE_ALLOC_RUNS, function () {
			this.timeout(30000);
			const r = new VM().run('new ArrayBuffer(64 * 1024 * 1024).byteLength');
			assert.strictEqual(r, 64 * 1024 * 1024);
		});

		it('bufferAllocLimit: Infinity disables the cap', function () {
			const r = new VM({ bufferAllocLimit: Infinity }).run('new Uint8Array(1024).length');
			assert.strictEqual(r, 1024);
		});
	});

	describe('NodeVM forwards the cap to ArrayBuffer/TypedArray', function () {
		it('NodeVM enforces bufferAllocLimit on new ArrayBuffer', function () {
			const vm = new NodeVM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('module.exports = new ArrayBuffer(2048).byteLength');
			}, CAP_RE);
		});

		it('NodeVM enforces bufferAllocLimit on new Uint8Array', function () {
			const vm = new NodeVM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('module.exports = new Uint8Array(2048).length');
			}, CAP_RE);
		});
	});

	// The size argument is coerced by V8 via ToIndex (ToNumber first), so a cap
	// that only fires for `typeof === 'number'` is bypassed by a string, an object
	// with `valueOf` / `Symbol.toPrimitive`, etc. The cap measures the COERCED
	// magnitude. (Red-team finding during GHSA-v836 hardening.)
	describe('coercion bypass is closed (ToIndex semantics)', function () {
		const BIGS = String(BIG);
		it('rejects new ArrayBuffer("<big>") (string length)', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new ArrayBuffer("' + BIGS + '").byteLength');
			}, CAP_RE);
		});

		it('rejects new ArrayBuffer({valueOf}) (object length)', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new ArrayBuffer({ valueOf: function () { return ' + BIGS + '; } }).byteLength');
			}, CAP_RE);
		});

		it('rejects new ArrayBuffer({[Symbol.toPrimitive]})', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new ArrayBuffer({ [Symbol.toPrimitive]: function () { return ' + BIGS + '; } })');
			}, CAP_RE);
		});

		it('rejects new Uint8Array("<big>") (string length)', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new Uint8Array("' + BIGS + '").length');
			}, CAP_RE);
		});

		it('rejects maxByteLength supplied as {valueOf}', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new ArrayBuffer(8, { maxByteLength: { valueOf: function () { return ' + BIGS + '; } } })');
			}, CAP_RE);
		});

		it('rejects array-like { length } amplifier (new Uint8Array({length}))', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new Uint8Array({ length: ' + BIGS + ' }).length');
			}, CAP_RE);
		});

		it('rejects new Uint8Array(Array(<big>)) (holey-array length)', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new Uint8Array(Array(' + BIGS + ')).length');
			}, CAP_RE);
		});
	});

	// A value read once for the check and again by V8 lets a toggling accessor
	// read small at check-time and large at allocation-time. The construct traps
	// canonicalize object-valued sizes to the primitive the cap checked and hand
	// V8 that primitive, so check-time and alloc-time observe identical values.
	describe('TOCTOU is closed (single-read canonicalization)', function () {
		it('toggling length valueOf cannot allocate past the cap', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			// The cap reads valueOf once (small) and forwards that primitive to V8;
			// the resulting buffer is the small size, never the toggled-large one.
			const r = vm.run(
				'var t = 0;' +
				'var o = { valueOf: function () { return t++ ? ' + BIG + ' : 8; } };' +
				'new ArrayBuffer(o).byteLength',
			);
			assert.strictEqual(r, 8);
		});

		// Requires resizable ArrayBuffers (`maxByteLength` + `.resize()`, Node 20+);
		// on older runtimes `ab.resize` is undefined and the assertion would observe
		// a TypeError rather than the cap's RangeError.
		it.cond('toggling maxByteLength accessor cannot leave the buffer resizable past the cap', HAS_RESIZABLE_AB, function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			// maxByteLength is canonicalized to 8, so a later resize cannot exceed it.
			assert.throws(function () {
				vm.run(
					'var t = 0;' +
					'var o = { get maxByteLength() { return t++ ? ' + BIG + ' : 8; } };' +
					'var ab = new ArrayBuffer(8, o);' +
					'ab.resize(' + BIG + ');',
				);
			}, /Invalid|exceeds|RangeError|bufferAllocLimit/);
		});
	});

	describe('WebAssembly.Memory coercion + TOCTOU', function () {
		it.cond('rejects {initial: "<pages>"} (string)', HAS_WASM_MEMORY, function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new WebAssembly.Memory({ initial: "4000" })');
			}, CAP_RE);
		});

		it.cond('rejects {initial: {valueOf}}', HAS_WASM_MEMORY, function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('new WebAssembly.Memory({ initial: { valueOf: function () { return 4000; } } })');
			}, CAP_RE);
		});

		it.cond('toggling initial accessor cannot allocate past the cap', HAS_WASM_MEMORY, function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			const r = vm.run(
				'var t = 0;' +
				'var m = new WebAssembly.Memory({ get initial() { return t++ ? 4000 : 1; } });' +
				'm.buffer.byteLength',
			);
			assert.strictEqual(r, 65536); // one page only
		});

		it.cond('rejects grow({valueOf}) coercion', HAS_WASM_MEMORY, function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('var m = new WebAssembly.Memory({ initial: 1 }); m.grow({ valueOf: function () { return 4000; } });');
			}, CAP_RE);
		});
	});

	// KNOWN RESIDUAL (documented, not a regression): a non-iterable array-like
	// whose `length` is a *toggling accessor* (small to the cap's read, large to
	// V8's read) can still over-allocate. V8 reads an array-like's `.length`
	// itself; pinning that read would require Proxy-wrapping the source, which
	// would break the legitimate `new Uint8Array(buffer, offset, length)` view
	// path (a real correctness regression). The common data-property `{length: N}`
	// amplifier IS capped (see above). This narrow accessor variant — and the
	// identical pre-existing gap in `Buffer.from({length: N})` — is accepted as a
	// documented residual. The test asserts current behaviour so any future change
	// is visible.
	describe('known residual: array-like length accessor (documented)', function () {
		it('toggling array-like length accessor is a documented residual', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			let overAllocated = false;
			try {
				const r = vm.run(
					'var t = 0;' +
					'new Uint8Array({ get length() { return t++ ? ' + BIG + ' : 0; } }).length',
				);
				overAllocated = typeof r === 'number' && r >= BIG;
			} catch (e) {
				overAllocated = false; // a throw (incl. future hardening) is strictly safer
			}
			// Documented as currently OPEN. If a future change closes it, flip this
			// expectation to false — the failure will flag the improvement.
			assert.strictEqual(overAllocated, true, 'residual expected open; if closed, update this assertion');
		});
	});
});
