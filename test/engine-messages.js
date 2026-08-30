'use strict';

// Expected error-message patterns, keyed by engine.
//
// Many security tests assert on the exact wording a rejection produces. That
// wording is engine-specific, and widening each pattern until it matches both
// V8 and JSC would permanently weaken the assertion on Node -- the runtime
// that actually carries the guarantee. So the patterns stay exactly as tight
// as they are today and are selected by engine instead.
//
// Adding a third engine is a column, not a rewrite.

const {ENGINE} = require('./engine');

const MESSAGES = {
	NOT_A_CONSTRUCTOR: {
		v8: /Proxy is not a constructor/,
		jsc: /undefined is not a constructor/,
	},
	PROXY_DEFINE_FALSISH_TOSTRING: {
		v8: /'defineProperty' on proxy: trap returned falsish for property 'toString'/,
		jsc: /Proxy's 'defineProperty' trap returned falsy value for property 'toString'/,
	},
	PROXY_DEFINE_FALSISH_TEST: {
		v8: /^'defineProperty' on proxy: trap returned falsish for property 'test'$/,
		jsc: /^Proxy's 'defineProperty' trap returned falsy value for property 'test'$/,
	},
	PROXY_SET_FALSISH: {
		v8: /'set' on proxy: trap returned falsish for property 'a'/,
		jsc: /Proxy object's 'set' trap returned falsy value for property 'a'/,
	},
	PROXY_SET_FALSISH_B: {
		v8: /'set' on proxy: trap returned falsish for property 'b'/,
		jsc: /Proxy object's 'set' trap returned falsy value for property 'b'/,
	},
	PROXY_SET_FALSISH_D: {
		v8: /'set' on proxy: trap returned falsish for property 'd'/,
		jsc: /Proxy object's 'set' trap returned falsy value for property 'd'/,
	},
	PROXY_DELETE_FALSISH_READFILESYNC: {
		v8: /^'deleteProperty' on proxy: trap returned falsish for property 'readFileSync'$/,
		// JSC's message for a failed strict-mode delete carries no property
		// name at all -- this is the engine's own wording, not a widening on
		// our part. The v8 side above stays exactly as strict as it was.
		jsc: /^Unable to delete property\.$/,
	},
	READ_MAINMODULE_OF_UNDEFINED: {
		v8: /Cannot read propert.*mainModule/,
		jsc: /undefined is not an object \(evaluating '.*mainModule'\)/,
	},
	READ_TOSTRING_OF_NULL: {
		v8: /Cannot read propert.*toString/,
		jsc: /null is not an object \(evaluating '.*toString'\)/,
	},
	SUPPRESSED_ERROR_ACCESS: {
		v8: /process is not defined|properties of null/,
		jsc: /null is not an object \(evaluating 'e\.(suppressed|error)'\)/,
	},
	PREPARE_STACK_TRACE_GETTHIS: {
		v8: /TypeError: Cannot read propert.*constructor/,
		jsc: /undefined is not an object \(evaluating 'sst\[0\]\.getThis\(\)\.constructor'\)/,
	},
};

function msg(key) {
	const entry = MESSAGES[key];
	if (!entry) throw new Error('unknown message key: ' + key);
	return entry[ENGINE];
}

module.exports = {MESSAGES, msg, ENGINE};
