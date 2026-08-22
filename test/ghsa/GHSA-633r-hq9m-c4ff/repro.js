/**
 * GHSA-633r-hq9m-c4ff — vm.freeze() read-only bypass via accessor setter leak
 *
 * ## Vulnerability
 * `vm.freeze(hostObject, name)` is documented to give the sandbox a READ-ONLY
 * view of a host object. `ReadOnlyHandler` makes the `set` / `defineProperty` /
 * `deleteProperty` proxy traps inert, so `cfg.level = x` and
 * `Object.defineProperty(cfg, ...)` are correctly blocked.
 *
 * But when the host object exposes an ACCESSOR property (getter/setter), the
 * sandbox can read the accessor's `set` off the frozen proxy and call it:
 *
 *     const d = Object.getOwnPropertyDescriptor(cfg, 'level');
 *     d.set.call(cfg, 'PWNED');                          // runs host setter
 *     cfg.__lookupSetter__('level').call(cfg, 'PWNED2'); // same via lookupSetter
 *
 * `BaseHandler.getOwnPropertyDescriptor` wraps the host setter into a live,
 * bridged function. `ReadOnlyHandler` did not neutralize it, so the wrapped
 * setter's call lands in `BaseHandler.apply` and runs the raw host setter on
 * the unwrapped host object — mutating host state through a read-only view.
 * `Reflect.getOwnPropertyDescriptor` and `Object.getOwnPropertyDescriptors`
 * are the same channel.
 *
 * ## Fix
 * `ReadOnlyHandler.getOwnPropertyDescriptorDesc` strips the `set` accessor from
 * every descriptor before it is wrapped, so no descriptor/__lookupSetter__ path
 * yields an operative host setter. The getter (a read) is left intact, honoring
 * the read-only contract (reads work, all writes are inert).
 *
 * Sound oracle: the host-side backing field `_level`. It must stay 'safe'.
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

function makeHostConfig() {
	const cfg = {
		_level: 'safe',
		get level() {
			return this._level;
		},
		set level(v) {
			this._level = v;
		}
	};
	return cfg;
}

describe('GHSA-633r-hq9m-c4ff — vm.freeze accessor setter leak', () => {
	it('descriptor / __lookupSetter__ / Reflect / getOwnPropertyDescriptors cannot mutate host', () => {
		const cfg = makeHostConfig();
		const vm = new VM();
		vm.freeze(cfg, 'cfg');

		// Every known read-only write channel, each swallowing its own throw so a
		// blocked path does not mask a later one. The oracle is host-side _level.
		const observed = vm.run(`
			const attempts = {};
			function attempt(name, fn) {
				try { fn(); attempts[name] = 'ran'; }
				catch (e) { attempts[name] = 'threw'; }
			}

			attempt('getOwnPropertyDescriptor.set', () => {
				const d = Object.getOwnPropertyDescriptor(cfg, 'level');
				d.set.call(cfg, 'PWNED-gopd');
			});
			attempt('__lookupSetter__', () => {
				cfg.__lookupSetter__('level').call(cfg, 'PWNED-lookup');
			});
			attempt('Reflect.getOwnPropertyDescriptor.set', () => {
				const d = Reflect.getOwnPropertyDescriptor(cfg, 'level');
				d.set.call(cfg, 'PWNED-reflect');
			});
			attempt('getOwnPropertyDescriptors.set', () => {
				const all = Object.getOwnPropertyDescriptors(cfg);
				all.level.set.call(cfg, 'PWNED-all');
			});

			// Reads via the getter MUST still work (no over-blocking).
			const readViaGetter = cfg.level;
			const readViaProp = cfg.level;
			const lookupGetter = cfg.__lookupGetter__('level');
			const readViaLookupGetter = lookupGetter ? lookupGetter.call(cfg) : undefined;

			// A descriptor that reports set:undefined but keeps a callable get.
			const d = Object.getOwnPropertyDescriptor(cfg, 'level');
			({
				attempts,
				setIsUndefined: d.set === undefined,
				getIsFunction: typeof d.get === 'function',
				readViaGetter,
				readViaProp,
				readViaLookupGetter
			});
		`);

		// The host must be untouched by every write channel.
		assert.strictEqual(cfg._level, 'safe',
			'host _level was mutated through the read-only view');

		// Reads via getter still function (contract preserved, no over-block).
		assert.strictEqual(observed.readViaGetter, 'safe');
		assert.strictEqual(observed.readViaProp, 'safe');
		assert.strictEqual(observed.readViaLookupGetter, 'safe');
		assert.strictEqual(observed.getIsFunction, true,
			'getter should remain callable under read-only view');
		assert.strictEqual(observed.setIsUndefined, true,
			'setter should be stripped from the read-only descriptor');
	});

	it('preventExtensions / isExtensible / Object.freeze on a frozen host object with a non-configurable accessor does not throw a proxy-invariant error (regression)', () => {
		// Follow-up regression: the set-stripping fix lives in
		// ReadOnlyHandler.getOwnPropertyDescriptorDesc, but doPreventExtensions
		// copied descriptors onto the proxy target WITHOUT routing through that
		// hook. For a NON-configurable accessor it therefore planted a live `set`
		// on the target while the trap reported `set: undefined`, so V8's proxy
		// invariant check threw a TypeError on the next descriptor read triggered
		// by Object.isExtensible / preventExtensions / Object.freeze. The fix
		// routes the copy through the hook so the target matches the trap.
		const cfg = { _level: 'safe' };
		Object.defineProperty(cfg, 'level', {
			configurable: false,
			enumerable: true,
			get() { return this._level; },
			set(v) { this._level = v; }
		});
		const vm = new VM();
		vm.freeze(cfg, 'cfg');

		const observed = vm.run(`
			function attempt(fn) {
				try { return { ok: true, value: fn() }; }
				catch (e) { return { ok: false, error: String(e) }; }
			}
			({
				isExtensible: attempt(() => Object.isExtensible(cfg)),
				preventExtensions: attempt(() => { Object.preventExtensions(cfg); return true; }),
				// This descriptor read is where the pre-fix proxy-invariant TypeError fired.
				descAfter: attempt(() => {
					const d = Object.getOwnPropertyDescriptor(cfg, 'level');
					return { setIsUndefined: d.set === undefined, getIsFunction: typeof d.get === 'function' };
				}),
				// Object.freeze internally reads every descriptor (the invariant-error
				// site) before attempting an (inert) defineProperty.
				freeze: attempt(() => { Object.freeze(cfg); return true; }),
				setStillInert: attempt(() => {
					const d = Object.getOwnPropertyDescriptor(cfg, 'level');
					if (d.set) d.set.call(cfg, 'PWNED-nonconfig');
					return d.set === undefined ? 'no-setter' : 'has-setter';
				}),
				readViaGetter: attempt(() => cfg.level)
			});
		`);

		// No write channel touched the host.
		assert.strictEqual(cfg._level, 'safe', 'host _level was mutated through the read-only view');
		// None of the extensibility operations throw a proxy-invariant error.
		assert.strictEqual(observed.isExtensible.ok, true, 'isExtensible threw: ' + observed.isExtensible.error);
		assert.strictEqual(observed.isExtensible.value, false);
		assert.strictEqual(observed.preventExtensions.ok, true, 'preventExtensions threw: ' + observed.preventExtensions.error);
		assert.strictEqual(observed.descAfter.ok, true, 'descriptor read threw a proxy-invariant error: ' + observed.descAfter.error);
		// Object.freeze on a read-only proxy is inherently a throw — defineProperty
		// is inert, so V8 reports "trap returned falsish". That is pre-existing
		// read-only behavior, unchanged by this fix. What must NOT reappear is the
		// proxy-invariant "incompatible" descriptor TypeError from the set mismatch,
		// which fires at Object.freeze's internal getOwnPropertyDescriptor step.
		assert.strictEqual(
			observed.freeze.ok || /returned falsish/.test(observed.freeze.error || ''), true,
			'Object.freeze produced an unexpected error: ' + observed.freeze.error);
		assert.strictEqual(
			/incompatible/.test(observed.freeze.error || ''), false,
			'Object.freeze threw the proxy-invariant incompatible-descriptor error: ' + observed.freeze.error);
		// The read-only contract still holds on the non-configurable accessor.
		assert.strictEqual(observed.descAfter.value.setIsUndefined, true, 'setter must stay stripped on a non-configurable accessor');
		assert.strictEqual(observed.descAfter.value.getIsFunction, true, 'getter should remain callable');
		assert.strictEqual(observed.setStillInert.value, 'no-setter', 'setter leaked on a non-configurable accessor');
		assert.strictEqual(observed.readViaGetter.value, 'safe');
	});

	it('does NOT over-block a normal (non-frozen) exposed host object', () => {
		// A plain sandboxed host object with an accessor keeps its setter working;
		// the tightening is ReadOnly-specific.
		const cfg = makeHostConfig();
		const vm = new VM({ sandbox: { cfg } });

		const out = vm.run(`
			const d = Object.getOwnPropertyDescriptor(cfg, 'level');
			d.set.call(cfg, 'changed');
			({ setType: typeof d.set, level: cfg.level });
		`);

		assert.strictEqual(out.setType, 'function',
			'non-frozen host accessor should still expose an operative setter');
		assert.strictEqual(cfg._level, 'changed',
			'non-frozen host accessor setter should mutate as before the fix');
	});
});
