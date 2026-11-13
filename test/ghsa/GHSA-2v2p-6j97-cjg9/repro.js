'use strict';

/**
 * GHSA-2v2p-6j97-cjg9 — an unhandled host promise delivered through the
 * construct trap (and every other non-call delivery path) aborts the host
 * process.
 *
 * ## Vulnerability
 * GHSA-gjq8-xm47-88rc hardened ONE host->sandbox delivery path: the bridge
 * `apply` trap marks a host promise returned by a host FUNCTION call as
 * handled, so a sandbox that ignores it cannot trip Node's unhandledRejection
 * policy. Every other delivery path was left bare. A host constructor whose
 * body returns a rejected host promise:
 *
 *     function HostRejectCtor() { return Promise.reject(new Error('ctor-boom')); }
 *     new VM({sandbox: {HostRejectCtor}}).run('new HostRejectCtor(); 1');
 *
 * hands the sandbox a wrapped promise whose UNDERLYING host promise has no
 * rejection reaction. Node's default policy (`throw`, Node 15+; `strict` when
 * requested explicitly) then TERMINATES THE HOST PROCESS. The same holds for a
 * host getter returning a fresh rejected promise, and for a rejected host
 * promise passed as an ARGUMENT to a sandbox callback — neither transits the
 * `apply` return path. So sandbox code that merely touches an
 * embedder-exposed host constructor or property is a host DoS.
 *
 * ## Fix
 * `lib/bridge.js` marks the host promise at the host->sandbox DELIVERY
 * chokepoint (`thisProxyOther`, the single place a host object is given a
 * sandbox proxy), gated on a cheap prototype brand check against the cached
 * host `Promise.prototype` so no `.then` is invoked on non-promises. The
 * `apply` trap keeps its unconditional mark and `construct` gains the matching
 * one, so a promise returned from a host call is covered even if its prototype
 * chain was detached host-side.
 *
 * ## How this test proves it
 * The abort is process-level, so each attack case runs in a forked child
 * (`host-promise-child.js`) that installs NO unhandledRejection handler and
 * prints `ALIVE` + exits 0 only if the process was not torn down. Without the
 * fix the child aborts with a non-zero exit and never prints the marker.
 * Delivery/over-block scenarios (the sandbox still observes the sanitized
 * rejection; non-promise and fulfilled results are unaffected) run in-process.
 */

const assert = require('assert');
const path = require('path');
const {fork} = require('child_process');
const {VM} = require('../../../lib/main.js');

const CHILD = path.join(__dirname, 'host-promise-child.js');
const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
// `--unhandled-rejections` landed in Node 12; before that an ignored rejection
// only warns, so there is no host DoS to observe (and passing the unknown flag
// through NODE_OPTIONS would stop the child from starting at all).
const HAS_STRICT_REJECTIONS = NODE_MAJOR >= 12;

const itCond = typeof it.cond === 'function' ? it.cond : function (name, cond, fn) {
	if (cond) it(name, fn); else it.skip(name, fn);
};

// Fork the child for `scenario` under a strict unhandledRejection policy and
// resolve with {code, stdout}. The child is SIGKILLed if it ever hangs, so no
// child process outlives the suite.
function runChild(scenario) {
	return new Promise(function (resolve, reject) {
		let stdout = '';
		let stderr = '';
		const child = fork(CHILD, [scenario], {
			stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
			env: Object.assign({}, process.env, {NODE_OPTIONS: '--unhandled-rejections=strict'})
		});
		// Both pipes are drained: an undrained stderr would block a chatty child
		// on a full pipe, and the captured text is what makes a failure
		// diagnosable (the abort prints the rejection there).
		child.stdout.on('data', function (d) {
			stdout += String(d);
		});
		child.stderr.on('data', function (d) {
			stderr += String(d);
		});
		const timer = setTimeout(function () {
			try { child.kill('SIGKILL'); } catch (e) { /* ignore */ }
			reject(new Error('child timed out for scenario ' + scenario + '; stderr=' + stderr));
		}, 8000);
		child.on('error', function (e) {
			clearTimeout(timer);
			try { child.kill('SIGKILL'); } catch (e2) { /* ignore */ }
			reject(e);
		});
		child.on('exit', function (code) {
			clearTimeout(timer);
			resolve({code: code, stdout: stdout, stderr: stderr});
		});
	});
}

// Trim the child's stderr to the first lines that identify the abort, so a
// failing assertion names the rejection instead of a bare exit code.
function briefly(text) {
	const trimmed = String(text).replace(/\s+$/, '');
	if (trimmed.length <= 800) return trimmed;
	return trimmed.slice(0, 800) + ' […]';
}

function assertSurvived(scenario) {
	return runChild(scenario).then(function (res) {
		const detail = '; stdout=' + JSON.stringify(res.stdout) + '; stderr=' + briefly(res.stderr);
		assert.strictEqual(res.code, 0,
			'host process must exit 0 (survive) for scenario ' + scenario + '; got exit ' + res.code + detail);
		assert.ok(/ALIVE/.test(res.stdout),
			'child must print ALIVE marker for scenario ' + scenario + detail);
	});
}

describe('GHSA-2v2p-6j97-cjg9 (unhandled host promise delivered outside the apply trap)', function () {
	this.timeout(20000);

	itCond('canonical PoC: host constructor returns a rejected promise, sandbox ignores it — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('construct');
		});

	itCond('host constructor returns a promise that rejects LATER — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('construct-late');
		});

	itCond('host class constructor returning a rejected promise via `new` — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('class-new');
		});

	itCond('host class constructor returning a rejected promise via Reflect.construct — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('class-reflect');
		});

	itCond('host constructor returning a prototype-detached rejected promise — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('construct-detached');
		});

	itCond('host constructor returning a rejected promise re-parented onto Object.prototype — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('construct-reparented');
		});

	itCond('host function returning a prototype-detached rejected promise — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('apply-detached');
		});

	itCond('host function returning a rejected promise re-parented onto Object.prototype — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('apply-reparented');
		});

	itCond('host getter returning a fresh rejected promise, read once and ignored — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('getter');
		});

	itCond('rejected host promise passed as an argument to a sandbox callback — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('callback-arg');
		});

	// A promise minted in a SECOND host realm matches neither cached prototype
	// identity, so the brand check has to recognize it by where its prototype
	// chain terminates. The `apply` route already survived this pre-fix (that
	// mark is unconditional), so only the non-call routes are pinned here.
	itCond('cross-realm host promise delivered through a host getter — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('xrealm-getter');
		});

	itCond('cross-realm host promise read as a plain data property — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('xrealm-data');
		});

	itCond('cross-realm host promise passed as an argument to a sandbox callback — host survives',
		HAS_STRICT_REJECTIONS, function () {
			return assertSurvived('xrealm-callback');
		});

	it('sandbox that DOES .catch a constructed host promise still receives the sanitized rejection', function () {
		function HostRejectCtor() {
			return Promise.reject(new Error('ctor-boom'));
		}
		const vm = new VM({sandbox: {HostRejectCtor}});
		const out = vm.run(`
			new HostRejectCtor().catch(function (e) {
				return {
					message: String(e && e.message),
					isSandboxError: e instanceof Error,
					ctorIsSandbox: e && e.constructor === Error
				};
			});
		`);
		return out.then(function (info) {
			assert.strictEqual(info.message, 'ctor-boom', 'sandbox .catch must observe the rejection value');
			assert.strictEqual(info.isSandboxError, true, 'delivered error must be an Error in the sandbox realm');
			assert.strictEqual(info.ctorIsSandbox, true, 'delivered error constructor must be the sandbox Error (sanitized)');
		});
	});

	it('sandbox that DOES .catch a getter-delivered host promise still receives the sanitized rejection', function () {
		const hostAccessorObject = {};
		Object.defineProperty(hostAccessorObject, 'p', {
			get: function () {
				return Promise.reject(new Error('getter-boom'));
			},
			enumerable: true,
			configurable: true
		});
		const vm = new VM({sandbox: {hostAccessorObject}});
		const out = vm.run(`
			hostAccessorObject.p.catch(function (e) {
				return {message: String(e && e.message), ctorIsSandbox: e && e.constructor === Error};
			});
		`);
		return out.then(function (info) {
			assert.strictEqual(info.message, 'getter-boom', 'sandbox .catch must observe the getter rejection');
			assert.strictEqual(info.ctorIsSandbox, true, 'delivered error constructor must be the sandbox Error (sanitized)');
		});
	});

	it('host constructor returning a NON-promise object is unaffected', function () {
		function HostPlain() {
			this.tag = 'plain';
			return {tag: 'returned', nested: {deep: 1}};
		}
		const vm = new VM({sandbox: {HostPlain}});
		const out = vm.run(`
			var o = new HostPlain();
			[o.tag, o.nested.deep, typeof o.then];
		`);
		assert.strictEqual(out[0], 'returned', 'explicit constructor return must still win');
		assert.strictEqual(out[1], 1, 'nested host properties must still be readable');
		assert.strictEqual(out[2], 'undefined', 'a plain host object must not gain a then');
	});

	// The mark asks "is this a promise?" on every object a host call returns.
	// Answering by calling `then` and catching the TypeError costs a host
	// exception per non-promise object, so where the host has a no-throw check
	// (`util.types.isPromise`, Node 10+) `then` must only be reached for promises.
	itCond('host calls returning NON-promise objects never invoke host Promise.prototype.then',
		!!(require('util').types && require('util').types.isPromise), function () {
			const realThen = Promise.prototype.then;
			const nonPromiseReceivers = [];
			let promiseReceivers = 0;
			const p = Promise.resolve(7);
			let out;
			// The bridge caches `then` when the VM is created, so the counting
			// stand-in has to be in place before that and is removed straight after.
			Promise.prototype.then = function (a, b) {
				if (this === p) promiseReceivers++; else nonPromiseReceivers.push(Object.prototype.toString.call(this));
				return Reflect.apply(realThen, this, [a, b]);
			};
			try {
				function HostThing() { this.n = 1; }
				const vm = new VM({sandbox: {
					makeDate: function () { return new Date(0); },
					makePlain: function () { return {v: 1}; },
					makeArray: function () { return [1, 2]; },
					makeFn: function () { return function () {}; },
					makePromise: function () { return p; },
					HostThing: HostThing
				}});
				out = vm.run(`
					var d = makeDate(); var o = makePlain(); var a = makeArray(); var f = makeFn();
					var t = new HostThing(); makePromise();
					[d.getTime(), o.v, a.length, typeof f, t.n];
				`);
			} finally {
				Promise.prototype.then = realThen;
			}
			assert.deepStrictEqual([out[0], out[1], out[2], out[3], out[4]], [0, 1, 2, 'function', 1]);
			assert.deepStrictEqual(nonPromiseReceivers, [], 'then must not be called on a non-promise host object');
			assert.ok(promiseReceivers >= 1, 'a returned host promise must still be marked through then');
		});

	it('host constructor returning a FULFILLED promise still resolves normally to the sandbox', function () {
		function HostResolveCtor() {
			return Promise.resolve(42);
		}
		const vm = new VM({sandbox: {HostResolveCtor}});
		const out = vm.run(`new HostResolveCtor().then(function (v) { return v + 1; });`);
		return out.then(function (v) {
			assert.strictEqual(v, 43, 'fulfilled host promise must resolve unchanged');
		});
	});

	it('a host constructor building a normal instance keeps prototype methods working', function () {
		function HostThing(n) {
			this.n = n;
		}
		HostThing.prototype.double = function () {
			return this.n * 2;
		};
		const vm = new VM({sandbox: {HostThing}});
		const out = vm.run(`var t = new HostThing(21); [t.n, t.double()];`);
		assert.strictEqual(out[0], 21);
		assert.strictEqual(out[1], 42);
	});

	it('a late sandbox .catch on a constructed host promise still observes the rejection', function () {
		function HostRejectCtor() {
			return Promise.reject(new Error('late-catch-boom'));
		}
		const vm = new VM({sandbox: {HostRejectCtor}});
		const out = vm.run(`
			var p = new HostRejectCtor();
			Promise.resolve().then(function () {}).then(function () {
				return p.catch(function (e) { return String(e && e.message); });
			});
		`);
		return out.then(function (msg) {
			assert.strictEqual(msg, 'late-catch-boom', 'late sandbox .catch must still observe the rejection');
		});
	});
});
