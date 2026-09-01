'use strict';

// Applies test/bun-skips.js when running under Bun.
//
// Loaded via `--require` so it runs BEFORE any spec file. That ordering is the
// whole point: test/ghsa loads first and test/vm.js last, so wiring installed
// from inside a spec file could never reach the ghsa suites, where most
// skipped tests live.
//
// Two globals are wrapped:
//
//   describe -- to maintain the suite-name stack, because skip patterns match
//               the FULL title and an `it` wrapper alone sees only the test's
//               own name. This is what lets one entry quarantine a whole file.
//   it       -- to register a pending test when the full title matches.
//
// mocha installs both on the global once per spec file, so the assignment is
// intercepted with an accessor rather than wrapping a value that does not yet
// exist at --require time.

const {IS_BUN} = require('./engine');
const {skipReason} = require('./bun-skips');

// On Node this module does nothing at all.
if (IS_BUN) {
	const suiteStack = [];

	function fullTitle(name) {
		return suiteStack.length ? suiteStack.join(' ') + ' ' + name : name;
	}

	function intercept(prop, wrap) {
		let current;
		Object.defineProperty(global, prop, {
			configurable: true,
			get: function () {
				return current;
			},
			set: function (incoming) {
				if (typeof incoming !== 'function' || incoming.__vm2BunWrapped) {
					current = incoming;
					return;
				}
				const wrapped = wrap(incoming);
				// Carry mocha's own attachments (skip, only, aliases).
				Object.keys(incoming).forEach(function (k) {
					wrapped[k] = incoming[k];
				});
				wrapped.skip = incoming.skip;
				wrapped.only = incoming.only;
				wrapped.__vm2BunWrapped = true;
				current = wrapped;
			},
		});
	}

	intercept('describe', function (original) {
		return function (name, fn) {
			// Forward ALL arguments: describe.skip passes a third internally.
			if (typeof fn !== 'function') return original.apply(this, arguments);
			const args = Array.prototype.slice.call(arguments);
			args[1] = function () {
				suiteStack.push(name);
				try {
					return fn.apply(this, arguments);
				} finally {
					suiteStack.pop();
				}
			};
			return original.apply(this, args);
		};
	});

	// Report each skip this registry actually applies, as its own TAP comment.
	// CI counts these rather than every `# SKIP` record, because that also
	// sweeps in ordinary version/capability pending tests which have nothing to
	// do with Bun and would roughly double the apparent backlog.
	//
	// Emitted at registration rather than from a `process.on('exit')` handler:
	// an exit listener is observable from inside the suite, and
	// test/nodevm.js's "process events" case asserts the host has exactly one.
	// A `#`-prefixed line is a TAP comment, so this is inert to consumers.
	function noteSkip(title) {
		process.stdout.write('# vm2-bun-skip: ' + title + '\n');
	}

	intercept('it', function (original) {
		return function (name, fn) {
			// Register the skip by calling the original with NO callback, which
			// is how mocha marks a test pending. Do NOT call original.skip():
			// mocha's it.skip delegates to context.it, which is this wrapper,
			// and recurses until the stack overflows.
			if (typeof name === 'string' && skipReason(fullTitle(name))) {
				noteSkip(fullTitle(name));
				return original(name);
			}
			return original.apply(this, arguments);
		};
	});
}
