CONTEXT_MINIMAL = [
	'String', 'Array', 'Boolean', 'Date', 'Function', 'Number', 'RegExp', 'Object',
	'Proxy', 'Reflect', 'Map', 'WeakMap', 'Set', 'WeakSet', 'Promise', 'Symbol',
	'Error', 'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError',
	'Infinity', 'JSON', 'Math', 'NaN', 'undefined',
	'decodeURI', 'decodeURIComponent', 'encodeURI', 'encodeURIComponent', 'escape', 'unescape',
	'eval', 'isFinite', 'isNaN', 'parseFloat', 'parseInt'
]

class Script {
	constructor(code, options) {
		this._code = code;
	}

	runInContext(context, options) {
		return context.eval(this._code);
	}
}

exports.Script = Script;
exports.createContext = function(sandbox, type = CONTEXT_MINIMAL) {
	const iframe = document.createElement('iframe');
	iframe.classList.add('vm2-context');
	iframe.style.display = 'none';
	document.body.appendChild(iframe);

	if (sandbox) {
		Object.keys(sandbox).forEach((key) => {
			iframe.contentWindow[key] = sandbox[key];
		})
	}

	// Remove unwanted window properties
	Object.getOwnPropertyNames(iframe.contentWindow).forEach((key) => {
		if (type.indexOf(key) === -1) {
			delete iframe.contentWindow[key]
		}
	})

	return iframe.contentWindow;
}
exports.disposeContext = (context) => {
	document.body.removeChild(context);
}
exports.runInContext = (code, context, options) => {
	return new Script(code).runInContext(context, options);
}