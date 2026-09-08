'use strict';

/**
 * GHSA-2v2p-6j97-cjg9 — child helper.
 *
 * Runs one scenario in its OWN process so the test can observe whether a host
 * promise delivered into the sandbox and then ignored aborts the host. Prints
 * the marker `ALIVE` and exits 0 only if the process was NOT torn down by
 * Node's unhandledRejection policy.
 *
 * IMPORTANT: this helper deliberately installs NO process-level
 * `unhandledRejection` handler — doing so would mask the very crash we are
 * testing for. The only thing that may keep the process alive is the bridge
 * attaching a benign reaction to the underlying host promise at the boundary.
 *
 * Node 8 compatible.
 */

var path = require('path');

// Only execute when forked/run directly. The test runner (`mocha test
// --recursive`) also `require`s this file; without this guard it would run the
// scenario logic with mocha's argv and exit the whole test process.
if (require.main !== module) return;

var VM = require(path.join(__dirname, '..', '..', '..', 'lib', 'main.js')).VM;

// Host constructor whose body RETURNS a rejected host promise. `new` on it
// therefore evaluates to that promise, which the bridge construct trap hands
// to the sandbox.
function HostRejectCtor() {
	return Promise.reject(new Error('ctor-boom'));
}

// Same, but the rejection happens a tick LATER — the promise is already in the
// sandbox by the time it rejects.
function HostLateCtor() {
	return new Promise(function (_resolve, reject) {
		setTimeout(function () {
			reject(new Error('late-boom'));
		}, 10);
	});
}

// Class form: an explicit object return from a constructor overrides `this`.
class HostRejectClass {
	constructor() {
		return Promise.reject(new Error('class-boom'));
	}
}

// A host promise whose prototype chain the HOST detached before returning it.
// The delivery-side brand check cannot recognize it, so this case is carried
// solely by the unconditional mark in the construct trap.
function HostDetachedCtor() {
	var p = Promise.reject(new Error('detached-boom'));
	Object.setPrototypeOf(p, null);
	return p;
}

// Host accessor handing a FRESH rejected host promise to the sandbox on read.
var hostAccessorObject = {};
Object.defineProperty(hostAccessorObject, 'p', {
	get: function () {
		return Promise.reject(new Error('getter-boom'));
	},
	enumerable: true,
	configurable: true
});

// Host function that passes a rejected host promise as an ARGUMENT to a
// sandbox callback — a host->sandbox delivery that is neither a call nor a
// construct return.
function hostCallsBack(cb) {
	cb(Promise.reject(new Error('callback-boom')));
}

var scenario = process.argv[2];

var sandbox = {
	HostRejectCtor: HostRejectCtor,
	HostLateCtor: HostLateCtor,
	HostRejectClass: HostRejectClass,
	HostDetachedCtor: HostDetachedCtor,
	hostAccessorObject: hostAccessorObject,
	hostCallsBack: hostCallsBack
};

// Cross-realm host promises: minted in a SECOND host realm, so their prototype
// chain ends at THAT realm's `Promise.prototype` / `Object.prototype` and can
// never match the identities the bridge cached from this realm. Built only for
// the scenarios that use them: the data-property object holds an
// already-rejected cross-realm promise from the moment it is created, and a
// rejection the sandbox is never handed is the embedder's own problem, not this
// advisory's.
if (scenario === 'xrealm-getter' || scenario === 'xrealm-data' || scenario === 'xrealm-callback') {
	var nodeVm = require('vm');
	// A cross-realm factory: calling it returns a promise of the OTHER realm.
	var makeForeignReject = nodeVm.runInNewContext(
		'(function (msg) { return Promise.reject(new Error(msg)); })', {});

	var xrealmAccessorObject = {};
	Object.defineProperty(xrealmAccessorObject, 'p', {
		get: function () {
			return makeForeignReject('xrealm-getter-boom');
		},
		enumerable: true,
		configurable: true
	});
	sandbox.xrealmAccessorObject = xrealmAccessorObject;

	sandbox.xrealmCallsBack = function (cb) {
		cb(makeForeignReject('xrealm-callback-boom'));
	};

	// A cross-realm OBJECT carrying the promise as a plain data property. Built
	// only for its own scenario: unlike the two lazy shapes above, its promise is
	// rejected the moment the object exists, so in a run that never delivers it
	// the rejection is the embedder's own and would abort the child for an
	// unrelated reason.
	if (scenario === 'xrealm-data') {
		sandbox.xrealmDataObject = nodeVm.runInNewContext(
			'({p: Promise.reject(new Error("xrealm-data-boom"))})', {});
	}
}

var vm = new VM({sandbox: sandbox});

var codes = {
	// The sandbox constructs and simply drops the result.
	construct: 'new HostRejectCtor(); 1',
	'construct-late': 'new HostLateCtor(); 1',
	'class-new': 'new HostRejectClass(); 1',
	'class-reflect': 'Reflect.construct(HostRejectClass, []); 1',
	'construct-detached': 'new HostDetachedCtor(); 1',
	// Delivery through the `get` trap.
	getter: 'hostAccessorObject.p; 1',
	// Delivery as a callback argument.
	'callback-arg': 'hostCallsBack(function (p) { return p; }); 1',
	// Same three delivery routes, but the promise belongs to a second host realm.
	'xrealm-getter': 'xrealmAccessorObject.p; 1',
	'xrealm-data': 'xrealmDataObject.p; 1',
	'xrealm-callback': 'xrealmCallsBack(function (p) { return p; }); 1'
};

var code = codes[scenario];
if (!code) {
	console.error('unknown scenario: ' + scenario);
	process.exit(2);
}

vm.run(code);

// If the ignored host rejection is going to abort the process, Node does it
// while draining microtasks — well before this timer fires. Reaching here and
// printing the marker means the host survived. The timeout also outlives the
// 10 ms late rejection above.
setTimeout(function () {
	console.log('ALIVE');
	process.exit(0);
}, 300);
