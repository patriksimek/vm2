'use strict';

/**
 * GHSA-grj5-jjm8-h35p — descriptor-chain history coverage (PoCs #1–5)
 *
 * The advisory thread documents seven escape attempts iterating through
 * bypasses. PoC #6 (the `cwu` / Symbol.species
 * self-return chain) is the headline case, closed by the fix on this branch
 * and covered in `repro.js`. PoCs #1-5 are an earlier descriptor-based
 * family that progressively bypassed each tightening of the
 * `__lookupGetter__` + `Buffer.apply` constructor leak.
 *
 * They are CLOSED by intermediate fixes that have already landed on public
 * `main` (e.g. `9084cd6`, `c17c27e`). This file ensures those defenses do
 * not regress: each test exercises the exact PoC verbatim from the report
 * with a host-side `hostMark` for ground truth.
 *
 * Coverage matrix (verified on Node 25.9.0):
 *
 *   PoC #1 (Object.getOwnPropertyDescriptor → .value)            blocked
 *   PoC #2 (ho.getOwnPropertyDescriptor → .value)                blocked
 *   PoC #3 (ho.entries(cd).find('value') chain)                  blocked
 *   PoC #4 (getOwnPropertyDescriptors double indirection)        blocked
 *   PoC #5 (find('constructor') variant)                         blocked
 *
 * RCE payload is replaced with `process.pid` extraction so the test is
 * observation-only.
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

describe('GHSA-grj5-jjm8-h35p — descriptor chain history (PoCs #1–5)', function () {

	it('PoC #1 (Object.getOwnPropertyDescriptor): host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			try {
				const g = ({}).__lookupGetter__;
				const a = Buffer.apply;
				const p = a.apply(g, [Buffer, ['__proto__']]);
				hostMark.pid = Object.getOwnPropertyDescriptor(p.call(a),'constructor').value('return process.pid')();
			} catch (e) { hostMark.err = e.message; }
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});

	it('PoC #2 (ho.getOwnPropertyDescriptor): host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			try {
				const g = ({}).__lookupGetter__;
				const a = Buffer.apply;
				const p = a.apply(g, [Buffer, ['__proto__']]);
				const fp = p.call(a);
				const op = p.call(fp);
				const ho = op.constructor;
				hostMark.pid = ho.getOwnPropertyDescriptor(fp,'constructor').value('return process.pid')();
			} catch (e) { hostMark.err = e.message; }
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});

	it('PoC #3 (ho.entries+a.apply chain): host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			try {
				const g = ({}).__lookupGetter__;
				const a = Buffer.apply;
				const p = a.apply(g, [Buffer, ['__proto__']]);
				const fp = p.call(a);
				const op = p.call(fp);
				const ho = op.constructor;
				const cd = ho.getOwnPropertyDescriptor(fp,'constructor');
				const e = ho.entries(cd).find(v => v[0] === 'value');
				e.shift();
				e.push([undefined, ['return process.pid']]);
				hostMark.pid = a.apply(a, e)();
			} catch (e) { hostMark.err = e.message; }
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});

	it('PoC #4 (getOwnPropertyDescriptors double indirection): host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			try {
				const g = ({}).__lookupGetter__;
				const a = Buffer.apply;
				const p = a.apply(g, [Buffer, ['__proto__']]);
				const fp = p.call(a);
				const op = p.call(fp);
				const ho = op.constructor;
				const cd = ho.getOwnPropertyDescriptor(ho.getOwnPropertyDescriptors(fp,'constructor'),'constructor');
				const ee = ho.entries(cd).find(v => v[0] === 'value');
				ee.shift();
				const e = ho.entries.apply(null, ee).find(v => v[0] === 'value');
				e.shift();
				e.push([undefined, ['return process.pid']]);
				hostMark.pid = a.apply(a, e)();
			} catch (e) { hostMark.err = e.message; }
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});

	it('PoC #5 (find(\'constructor\') variant): host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			try {
				const g = ({}).__lookupGetter__;
				const a = Buffer.apply;
				const p = a.apply(g, [Buffer, ['__proto__']]);
				const fp = p.call(a);
				const op = p.call(fp);
				const ho = op.constructor;
				const cd = ho.getOwnPropertyDescriptors(fp,'constructor');
				const ee = ho.entries(cd).find(v => v[0] === 'constructor');
				ee.shift();
				const e = ho.entries.apply(null, ee).find(v => v[0] === 'value');
				e.shift();
				e.push([undefined, ['return process.pid']]);
				hostMark.pid = a.apply(a, e)();
			} catch (e) { hostMark.err = e.message; }
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});
});
