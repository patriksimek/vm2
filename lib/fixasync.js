'use strict';

// eslint-disable-next-line no-invalid-this, no-shadow
const {GeneratorFunction, AsyncFunction, AsyncGeneratorFunction, global, Contextify, host} = this;
// eslint-disable-next-line no-shadow
const {Function, eval: eval_, Promise, Object, Reflect, RegExp, VMError} = global;
const {setPrototypeOf, getOwnPropertyDescriptor, defineProperty} = Object;
const {apply: rApply, construct: rConstruct} = Reflect;
const {test} = RegExp.prototype;

function rejectAsync() {
	throw new VMError('Async not available');
}

const testAsync = setPrototypeOf(/\basync\b/, null);

function checkAsync(source) {
	// Filter async functions, await can only be in them.
	if (rApply(test, testAsync, [source])) {
		throw rejectAsync();
	}
	return source;
}

const AsyncCheckHandler = {
	__proto__: null,
	apply(target, thiz, args) {
		let i;
		for (i=0; i<args.length; i++) {
			// We want a exception here if args[i] is a Symbol
			// since Function does the same thing
			args[i] = checkAsync('' + args[i]);
		}
		return rApply(target, undefined, args);
	},
	construct(target, args, newTarget) {
		let i;
		for (i=0; i<args.length; i++) {
			// We want a exception here if args[i] is a Symbol
			// since Function does the same thing
			args[i] = checkAsync('' + args[i]);
		}
		return rConstruct(target, args);
	}
};

const AsyncEvalHandler = {
	__proto__: null,
	apply(target, thiz, args) {
		if (args.length === 0) return undefined;
		const script = args[0];
		if (typeof script !== 'string') {
			// Eval does the same thing
			return script;
		}
		checkAsync(script);
		return eval_(script);
	}
};

function override(obj, prop, value) {
	const desc = getOwnPropertyDescriptor(obj, prop);
	desc.value = value;
	defineProperty(obj, prop, desc);
}

const proxiedFunction = new host.Proxy(Function, AsyncCheckHandler);
override(Function.prototype, 'constructor', proxiedFunction);
if (GeneratorFunction) {
	Object.setPrototypeOf(GeneratorFunction, proxiedFunction);
	override(GeneratorFunction.prototype, 'constructor', new host.Proxy(GeneratorFunction, AsyncCheckHandler));
}
if (AsyncFunction || AsyncGeneratorFunction) {
	const AsyncFunctionRejectHandler = {
		__proto__: null,
		apply: rejectAsync,
		construct: rejectAsync
	};
	if (AsyncFunction) {
		Object.setPrototypeOf(AsyncFunction, proxiedFunction);
		override(AsyncFunction.prototype, 'constructor', new host.Proxy(AsyncFunction, AsyncFunctionRejectHandler));
	}
	if (AsyncGeneratorFunction) {
		Object.setPrototypeOf(AsyncGeneratorFunction, proxiedFunction);
		override(AsyncGeneratorFunction.prototype, 'constructor', new host.Proxy(AsyncGeneratorFunction, AsyncFunctionRejectHandler));
	}
}

global.Function = Function.prototype.constructor;
global.eval = new host.Proxy(eval_, AsyncEvalHandler);

if (Promise) {
	const AsyncRejectHandler = {
		__proto__: null,
		apply: rejectAsync
	};

	Promise.prototype.then = new host.Proxy(Promise.prototype.then, AsyncRejectHandler);
	Contextify.connect(host.Promise.prototype.then, Promise.prototype.then);

	if (Promise.prototype.finally) {
		Promise.prototype.finally = new host.Proxy(Promise.prototype.finally, AsyncRejectHandler);
		Contextify.connect(host.Promise.prototype.finally, Promise.prototype.finally);
	}
	if (Promise.prototype.catch) {
		Promise.prototype.catch = new host.Proxy(Promise.prototype.catch, AsyncRejectHandler);
		Contextify.connect(host.Promise.prototype.catch, Promise.prototype.catch);
	}

}
