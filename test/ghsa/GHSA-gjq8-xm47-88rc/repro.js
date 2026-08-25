'use strict';

/**
 * GHSA-gjq8-xm47-88rc — Ignored host-promise rejection aborts the host process
 *
 * ## Vulnerability
 * A host function exposed to the sandbox returns a REJECTED host Promise. The
 * bridge hands the sandbox a wrapped/proxied promise, but the UNDERLYING host
 * promise never receives a rejection reaction of its own. When the sandbox
 * simply ignores the return value (attaches no `.then`/`.catch`), Node's
 * default `unhandledRejection` policy (throw, Node 15+) sees a raw host promise
 * reject with no handler and TERMINATES THE HOST PROCESS.
 *
 *     const vm = new VM({ sandbox: { hostReject: () => Promise.reject(new Error('boom')) } });
 *     vm.run('hostReject(); 1');   // <-- host process aborts
 *
 * So untrusted sandbox code that merely calls an embedder-exposed host function
 * (or a host builtin like `events.once`) that returns a rejected promise it does
 * not await is a sandbox-triggered host DoS. Sibling of the parent advisory
 * GHSA-hw58-p9xv-2mjh, which hardened the OTHER direction (sandbox-created
 * promise rejecting to the host).
 *
 * ## Fix
 * In the bridge apply trap (`lib/bridge.js`), when a host function invoked from
 * the sandbox (isHost === false) returns a value, `markHostPromiseHandled`
 * attaches a benign no-op reaction to the underlying host promise on the host
 * side, using the cached host `Promise.prototype.then`. This marks the host
 * promise "handled" for Node's bookkeeping. Because promises multicast, the
 * sandbox's own (GHSA-55hx-sanitized) `.then`/`.catch` reaction still fires and
 * still observes the sanitized rejection independently. The no-op onRejected
 * returns undefined, so the derived promise fulfills and no NEW unhandled
 * rejection is created. Fulfilled promises are unaffected.
 *
 * ## How this test proves it
 * The abort is process-level, so the canonical PoC runs in a forked child
 * (`host-reject-child.js`) that installs NO unhandledRejection handler and
 * prints `SURVIVED` + exits 0 only if the process was not torn down. Without the
 * fix the child aborts with a non-zero exit and never prints the marker; with
 * the fix it exits 0. The delivery/regression scenarios (sandbox `.catch` still
 * receives the sanitized value; fulfilled promise still resolves) run in-process.
 */

const assert = require('assert');
const path = require('path');
const {fork} = require('child_process');
const {VM} = require('../../../lib/main.js');

const CHILD = path.join(__dirname, 'host-reject-child.js');
const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
const NODE_MINOR = parseInt(process.versions.node.split('.')[1], 10);
// events.once landed in Node 11.13.
const HAS_EVENTS_ONCE = NODE_MAJOR > 11 || (NODE_MAJOR === 11 && NODE_MINOR >= 13);

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

// Fork the child for `scenario` and resolve with {code, stdout}.
function runChild(scenario) {
	return new Promise(function (resolve, reject) {
		let stdout = '';
		const child = fork(CHILD, [scenario], {stdio: ['ignore', 'pipe', 'pipe', 'ipc']});
		child.stdout.on('data', function (d) {
			stdout += String(d);
		});
		const timer = setTimeout(function () {
			try { child.kill('SIGKILL'); } catch (e) { /* ignore */ }
			reject(new Error('child timed out for scenario ' + scenario));
		}, 8000);
		child.on('error', reject);
		child.on('exit', function (code) {
			clearTimeout(timer);
			resolve({code: code, stdout: stdout});
		});
	});
}

describe('GHSA-gjq8-xm47-88rc (ignored host-promise rejection host DoS)', function () {
	this.timeout(15000);

	it('canonical PoC: host fn returns rejected promise, sandbox ignores it — host survives', function () {
		return runChild('hostfn').then(function (res) {
			assert.strictEqual(res.code, 0, 'host process must exit 0 (survive); got exit ' + res.code);
			assert.ok(/SURVIVED/.test(res.stdout), 'child must print SURVIVED marker; stdout=' + JSON.stringify(res.stdout));
		});
	});

	it('host async function rejecting, sandbox ignores it — host survives', function () {
		return runChild('async').then(function (res) {
			assert.strictEqual(res.code, 0, 'host process must exit 0 (survive); got exit ' + res.code);
			assert.ok(/SURVIVED/.test(res.stdout), 'child must print SURVIVED marker; stdout=' + JSON.stringify(res.stdout));
		});
	});

	it.cond('events.once rejecting, sandbox ignores it — host survives', HAS_EVENTS_ONCE, function () {
		return runChild('once').then(function (res) {
			assert.strictEqual(res.code, 0, 'host process must exit 0 (survive); got exit ' + res.code);
			assert.ok(/SURVIVED/.test(res.stdout), 'child must print SURVIVED marker; stdout=' + JSON.stringify(res.stdout));
		});
	});

	it('sandbox that DOES .catch still receives the sanitized, sandbox-realm rejection', function () {
		const vm = new VM({sandbox: {hostReject: () => Promise.reject(new Error('host-boom'))}});
		const out = vm.run(`
			hostReject().catch(function (e) {
				return {
					message: String(e && e.message),
					// The delivered error must be a sandbox-realm Error, not a raw
					// host Error — its constructor is the sandbox's own Error.
					isSandboxError: e instanceof Error,
					ctorIsSandbox: e && e.constructor === Error
				};
			});
		`);
		return out.then(function (info) {
			assert.strictEqual(info.message, 'host-boom', 'sandbox .catch must observe the rejection value');
			assert.strictEqual(info.isSandboxError, true, 'delivered error must be an Error in the sandbox realm');
			assert.strictEqual(info.ctorIsSandbox, true, 'delivered error constructor must be the sandbox Error (sanitized)');
		});
	});

	it('host fn returning a FULFILLED promise still resolves normally to the sandbox', function () {
		const vm = new VM({sandbox: {hostResolve: () => Promise.resolve(42)}});
		const out = vm.run(`hostResolve().then(function (v) { return v + 1; });`);
		return out.then(function (v) {
			assert.strictEqual(v, 43, 'fulfilled host promise must resolve unchanged');
		});
	});

	it('benign handler does not swallow a rejection the sandbox never catches vs. one it does (both delivered)', function () {
		// Attaching the bridge no-op must not stop a later sandbox handler from
		// seeing the rejection, even one attached after a microtask turn.
		const vm = new VM({sandbox: {hostReject: () => Promise.reject(new Error('late-boom'))}});
		const out = vm.run(`
			var p = hostReject();
			// Attach the handler a turn later — still must observe the rejection.
			Promise.resolve().then(function () {}).then(function () {
				return p.catch(function (e) { return String(e && e.message); });
			});
		`);
		return out.then(function (msg) {
			assert.strictEqual(msg, 'late-boom', 'late sandbox .catch must still observe the rejection');
		});
	});
});
