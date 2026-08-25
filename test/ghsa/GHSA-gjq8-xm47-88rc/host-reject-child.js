'use strict';

/**
 * GHSA-gjq8-xm47-88rc — child helper.
 *
 * Runs one scenario in its OWN process so the test can observe whether an
 * ignored host-promise rejection aborts the host. Prints the marker
 * `SURVIVED` and exits 0 only if the process was NOT torn down by Node's
 * default unhandledRejection policy.
 *
 * IMPORTANT: this helper deliberately installs NO process-level
 * `unhandledRejection` handler — doing so would mask the very crash we are
 * testing for. The only thing that may keep the process alive is the bridge
 * fix attaching a benign reaction to the underlying host promise.
 *
 * Node 8 compatible.
 */

var path = require('path');

// Only execute when forked/run directly. The test runner (`mocha test
// --recursive`) also `require`s this file; without this guard it would run the
// scenario logic with mocha's argv and exit the whole test process.
if (require.main !== module) return;

var VM = require(path.join(__dirname, '..', '..', '..', 'lib', 'main.js')).VM;

var events = require('events');
var EventEmitter = events.EventEmitter;
var once = events.once; // undefined before Node 11.13

var scenario = process.argv[2];

var sandbox = {
	// Host function returning a rejected host promise (the canonical PoC).
	hostReject: function () {
		return Promise.reject(new Error('host-boom'));
	},
	// Host async function whose rejection is a host-realm value.
	hostAsync: function () {
		return (async function () {
			throw new Error('host-async-boom');
		})();
	},
	// events.once(...) returns a host promise that rejects when 'error' fires.
	onceReject: function () {
		if (typeof once !== 'function') return Promise.reject(new Error('once-unavailable'));
		var e = new EventEmitter();
		var p = once(e, 'never');
		process.nextTick(function () {
			e.emit('error', new Error('once-boom'));
		});
		return p;
	}
};

var vm = new VM({sandbox: sandbox});

var code;
if (scenario === 'hostfn') {
	code = 'hostReject(); 1';
} else if (scenario === 'async') {
	code = 'hostAsync(); 1';
} else if (scenario === 'once') {
	code = 'onceReject(); 1';
} else {
	console.error('unknown scenario: ' + scenario);
	process.exit(2);
}

vm.run(code);

// If the ignored host rejection is going to abort the process, Node does it
// while draining microtasks — well before this timer fires. Reaching here and
// printing the marker means the host survived.
setTimeout(function () {
	console.log('SURVIVED');
	process.exit(0);
}, 300);
