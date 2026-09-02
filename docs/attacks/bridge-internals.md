# Bridge Internals

Attacks on the bridge's own machinery rather than on the objects it wraps: proxy trap handlers, handler exposure through `util.inspect`, monkey-patched `call`/`apply`/`defineProperty`, bridge-internal containers reachable through sandbox prototypes, the internal state object, and the read-only view.

Defense invariants enforced by fixes in this family: 8, 11 (see [Defense Invariants](../ATTACKS.md#defense-invariants)).

Categories in this file: [6](bridge-internals.md#attack-category-6-proxy-trap-exploitation), [9](bridge-internals.md#attack-category-9-proxy-handler-exposure-via-utilinspect), [11](bridge-internals.md#attack-category-11-monkey-patching-bridge-internals), [14](bridge-internals.md#attack-category-14-objectprototype-trap-pollution-via-in-operator), [27](bridge-internals.md#attack-category-27-internal-state-probe-via-computed-property-access-on-globalthis), [28](bridge-internals.md#attack-category-28-bridge-internal-state-leak-via-sandbox-realm-array-setter), [44](bridge-internals.md#attack-category-44-vmfreeze-read-only-bypass-via-accessor-setter-leak).

---

## Attack Category 6: Proxy Trap Exploitation

**Advisories**: none

**Tests**: none linked

### Description

The `Proxy` constructor allows intercepting fundamental operations on objects. Attackers create Proxies with trap handlers that execute when the bridge processes values, allowing them to inject code at points where the bridge may pass unsanitized references. See also [Category 2: Prototype Chain Manipulation](host-reference-primitives.md#attack-category-2-prototype-chain-manipulation) for combining proxy traps with prototype pollution.

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

## Attack Category 9: Proxy Handler Exposure via util.inspect

**Advisories**: GHSA-v37h-5mfm-c47c, GHSA-qcp4-v2jj-fjx8

**Tests**: test/ghsa/GHSA-v37h-5mfm-c47c/, test/ghsa/GHSA-qcp4-v2jj-fjx8/

### Description

When Node.js's `util.inspect` is called with `showProxy: true`, it exposes the internal target and handler of Proxy objects. If proxy handlers store references to raw host objects in accessible locations, attackers can retrieve these references. This technique relies on [Category 8: Cross-Realm Symbol Extraction](host-reference-primitives.md#attack-category-8-cross-realm-symbol-extraction-from-host-objects) to obtain the real inspect symbol, and the handler methods become vectors for [Category 1: Constructor Chain Traversal](host-reference-primitives.md#attack-category-1-constructor-chain-traversal).

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

## Attack Category 11: Monkey-Patching Bridge Internals

**Advisories**: none

**Tests**: none linked

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

## Attack Category 14: Object.prototype Trap Pollution via `in` Operator

**Advisories**: none

**Tests**: none linked

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

## Attack Category 27: Internal State Probe via Computed Property Access on `globalThis`

**Advisories**: GHSA-wp5r-2gw5-m7q7, GHSA-2cm2-m3w5-gp2f

**Tests**: test/ghsa/GHSA-wp5r-2gw5-m7q7/, test/ghsa/GHSA-2cm2-m3w5-gp2f/

**Uses**: [Category 12](transformer-and-modules.md#attack-category-12-code-transformation-bypass) (the transformer is a syntactic gate; computed keys are invisible to it).

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

Restores [Defense Invariant 10](../ATTACKS.md#defense-invariants) ("Dynamic code compilation paths cannot reach an unwrapped host realm") for the implicit dependency of every transformer-instrumented `catch` / `with` / `import()` rewrite on the canonical identifier — the binding it resolves to is now a sandbox-controlled lexical record entry rather than an attacker-reflectable global property.

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

**Advisories**: GHSA-9qj6-qjgg-37qq, GHSA-q3fm-4wcw-g57x, GHSA-grj5-jjm8-h35p

**Tests**: test/ghsa/GHSA-9qj6-qjgg-37qq/, test/ghsa/GHSA-q3fm-4wcw-g57x/, test/ghsa/GHSA-grj5-jjm8-h35p/

**Uses**: [Category 2: Prototype Chain Manipulation](host-reference-primitives.md#attack-category-2-prototype-chain-manipulation), [Category 4: Error Object Exploitation](error-sanitization.md#attack-category-4-error-object-exploitation), [Category 18: Array Species Self-Return via Constructor Manipulation](host-reference-primitives.md#attack-category-18-array-species-self-return-via-constructor-manipulation)

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

The bridge's existing pattern in `thisFromOtherArguments` already uses `thisReflectDefineProperty` to install argument indices precisely because index assignment via `[i] =` triggers prototype-chain setters. The two sites covered here were outliers — Variant A introduced when the species defense (GHSA-grj5-jjm8-h35p) replaced its earlier no-restore variant with a `saved`-list design; Variant B introduced under the post-#563 hardening for [Category 19](promise-async.md#attack-category-19-host-preparestacktrace-fallback-via-arrayfromasync-promise-bypass) when `defaultSandboxPrepareStackTrace` was added to keep V8 off Node's host-side formatter.

### Mitigation

**Variant A**: `neutralizeArraySpeciesBatch` now installs every entry with `thisReflectDefineProperty(saved, savedLen, { value, writable: true, enumerable: true, configurable: true })` in `lib/bridge.js`. `Reflect.defineProperty` creates an own data property and bypasses the prototype-chain setter completely, so a sandbox-installed setter on `Array.prototype[N]` is never invoked while the bridge holds raw saved state. `restoreArraySpeciesBatch` is symmetric without code change: indexed reads on `savedList[i]` now land on own data slots installed by the neutralize pass, so a sandbox-installed **getter** on `Array.prototype[N]` cannot intercept, substitute, or mutate the saved-state record between neutralize and restore either. The defense is index-agnostic — it holds for index 0, any positive integer index, and any shape of argument list (context-only, args-only, or both).

**Variant B**: `defaultSandboxPrepareStackTrace` no longer materialises an array. The formatter folds each frame directly into a string accumulator via primitive concatenation (`result += '\n' + frame`), removing every reachable `Array.prototype` slot at once — index setters, the final `.join`, and any hypothetical future enrichment of the bridge-internal container. String concatenation routes through primitive `[[Get]]` of `callSites[i]` (a sandbox-realm `CallSite` wrapper whose `toString` returns the safe `'CallSite {}'` literal) and primitive string-plus, neither of which dispatch through `Array.prototype` or `Object.prototype`. `makeCallSiteGetters` (same file) is converted for symmetry to install each entry via `localReflectDefineProperty(callSiteGetters, idx, { value, ... })`; this loop runs at sandbox init before user code can install setters, so it is safe today, but the consistent pattern prevents future regressions and keeps the indexed reads at `applyCallSiteGetters` immune to later sandbox-installed getters on `Array.prototype[N]`.

Together these fixes restore [Defense Invariant #11: Bridge-Internal Containers Must Not Invoke Sandbox Code](../ATTACKS.md#defense-invariants): any list, set, or map allocated for the bridge's exclusive use must read and write through identity-stable, prototype-bypassing primitives — never operators that fall through to `Array.prototype` / `Object.prototype` / `Map.prototype.{get,set}`. The same invariant explains why the bridge already uses `thisReflectApply(thisWeakMapSet, mapping, [k, v])` rather than `mapping.set(k, v)` everywhere. The chokepoint is now uniform across `lib/bridge.js` and `lib/setup-sandbox.js`.

**Supersedes**: this category retroactively hardens the [Category 18](host-reference-primitives.md#attack-category-18-array-species-self-return-via-constructor-manipulation) species defense by closing the saved-list write path the attacker would otherwise use to extract the very state the species fix produces. Variant B closes the audit gap from Variant A's original mitigation, which was scoped to `lib/bridge.js`.

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

## Attack Category 44: `vm.freeze()` Read-Only Bypass via Accessor Setter Leak

**Advisories**: none

**Tests**: none linked

**Uses**: [Category 6: Proxy Trap Exploitation](bridge-internals.md#attack-category-6-proxy-trap-exploitation), [Category 15: Property Descriptor Value Extraction](host-reference-primitives.md#attack-category-15-property-descriptor-value-extraction)

### Description

`vm.freeze(hostObject, name)` is documented to expose a **read-only** view of a host object to the sandbox. `ReadOnlyHandler` makes the write traps inert: `cfg.level = x` throws `'set' on proxy: trap returned falsish`, and `Object.defineProperty(cfg, ...)` / `delete cfg.level` return `false`.

But when the host object carries an **accessor** property (`get` / `set`), the descriptor-read path leaks an operative setter. `BaseHandler.getOwnPropertyDescriptor` wraps both `desc.get` and `desc.set` into live, bridged functions. `ReadOnlyHandler` overrode the write *traps* but not the *descriptor read*, so the sandbox could pull the wrapped setter off the frozen proxy and call it:

```javascript
const d = Object.getOwnPropertyDescriptor(cfg, 'level');
d.set.call(cfg, 'PWNED');                 // wrapped setter → BaseHandler.apply → raw host setter
cfg.__lookupSetter__('level').call(cfg, 'PWNED-2');   // same descriptor, different reader
```

The wrapped setter's call lands in `BaseHandler.apply`, which unwraps `context` (the proxy) back to the raw host object and invokes the host setter on it — mutating host state through a view the embedder declared read-only. This is a **read-only contract violation / host-state write**, not (by itself) a full realm escape, but it is a capability the embedder explicitly withheld: `vm.freeze` is the API embedders reach for precisely to hand the sandbox observable-but-immutable config, and any host setter (cache invalidation, privilege flags, path allow-lists, feature toggles) becomes sandbox-writable.

### Attack Flow

1. Embedder exposes a host object with an accessor property via `vm.freeze(cfg, 'cfg')`, intending read-only access.
2. Sandbox reads the property descriptor through any channel that reaches the `getOwnPropertyDescriptor` trap: `Object.getOwnPropertyDescriptor`, `Reflect.getOwnPropertyDescriptor`, `Object.getOwnPropertyDescriptors`, or `Object.prototype.__lookupSetter__`.
3. The returned descriptor's `set` is a live bridge-wrapped function whose target is the raw host setter.
4. Sandbox calls `desc.set.call(cfg, value)`. The apply trap forwards to the host setter with `this` = the unwrapped host object.
5. Host state mutates; every inert write trap was bypassed because no write trap was on the path.

### Canonical Examples

```javascript
const cfg = {
    _level: 'safe',
    get level() { return this._level; },
    set level(v) { this._level = v; },
};
const vm = new VM();
vm.freeze(cfg, 'cfg');

vm.run(`
    // Channel 1 — Object.getOwnPropertyDescriptor
    Object.getOwnPropertyDescriptor(cfg, 'level').set.call(cfg, 'PWNED-a');
    // Channel 2 — __lookupSetter__ (reads the same descriptor)
    cfg.__lookupSetter__('level').call(cfg, 'PWNED-b');
    // Channel 3 — Reflect.getOwnPropertyDescriptor
    Reflect.getOwnPropertyDescriptor(cfg, 'level').set.call(cfg, 'PWNED-c');
    // Channel 4 — Object.getOwnPropertyDescriptors (bulk)
    Object.getOwnPropertyDescriptors(cfg).level.set.call(cfg, 'PWNED-d');
`);
// Before the fix: cfg._level === 'PWNED-d'. Direct cfg.level = x stayed blocked,
// masking the leak from write-trap-only tests.
```

### Why It Works

`ReadOnlyHandler` inherited `BaseHandler.getOwnPropertyDescriptor` unchanged. That method's job is realm-crossing fidelity, not policy: it faithfully wraps whatever `get` / `set` the host descriptor has so the sandbox sees a working accessor. Read-only policy lived only in the `set` / `defineProperty` / `deleteProperty` traps — the *direct* write paths. The descriptor-read path is an *indirect* write path: it hands the sandbox a callable that, when invoked, routes through `apply` (an unguarded-for-read-only trap) to the host setter. `__lookupSetter__`, `Reflect.getOwnPropertyDescriptor`, and `Object.getOwnPropertyDescriptors` are all readers of the same descriptor, so all four share the single leak.

The getter side (`desc.get`, `__lookupGetter__`) is **not** a violation — reads are permitted under the read-only contract — so the fix must be asymmetric: neutralize `set`, preserve `get`.

### Mitigation

`ReadOnlyHandler.getOwnPropertyDescriptorDesc` (the descriptor hook `BaseHandler.getOwnPropertyDescriptor` invokes *before* wrapping `get` / `set`) is overridden to drop the `set` accessor from every host-side descriptor on the sandbox→host direction (`!isHost`). With `desc.set` removed before wrapping, the descriptor the sandbox receives is a getter-only accessor: `desc.get` still works, `desc.set === undefined`. Because all four extraction channels funnel through the same `getOwnPropertyDescriptor` trap → same hook, one override closes every channel simultaneously. A setter-only accessor collapses to `{ value: undefined, writable: false }`, which carries no write capability and reads as `undefined` — consistent with read-only semantics.

The tightening is `ReadOnly`-specific: `BaseHandler` (non-frozen exposed host objects) is untouched, so an accessor on an ordinary `sandbox: { cfg }` object still exposes an operative setter, exactly as before.

The same hook must also govern the *other* writer of the proxy target. `doPreventExtensions` copies own descriptors onto the proxy target so V8's non-configurable-property invariant can be checked, and it originally wrapped `get` / `set` directly instead of going through the hook. That left a live `set` on the target while the trap reported `set: undefined`, so the first `isExtensible` / `preventExtensions` / `Object.keys` on a frozen object holding a **non-configurable** accessor tripped V8's "trap returned descriptor ... incompatible with the existing property" `TypeError` and poisoned spread, `Object.assign` and `JSON.stringify` on that object. `doPreventExtensions` now routes each copied descriptor through `handler.getOwnPropertyDescriptorDesc(...)` before defining it, so target and trap agree for every handler variant (`BaseHandler` leaves `set` intact and is unaffected). The non-configurable accessor branch rebuilds a clean accessor-only descriptor, because the hook can leave a stray `value` on function `caller` / `arguments` / `callee` and `defineProperty` rejects a descriptor carrying both an accessor and a value.

Note that `Object.freeze` on a read-only proxy still throws ("trap returned falsish"): `defineProperty` is inert on a read-only view. That is pre-existing read-only behavior for any frozen object with properties, not a consequence of this fix.

### Detection Rules

- **`Object.getOwnPropertyDescriptor(frozen, k).set` / `.__lookupSetter__(k)` returning a callable inside the sandbox** — a read-only view must never yield an operative setter.
- **`desc.set.call(frozen, v)` / `setter.call(frozen, v)` pattern in sandbox code** — indirect write through a leaked accessor setter.
- **`Object.getOwnPropertyDescriptors(frozen)` / `Reflect.getOwnPropertyDescriptor(frozen, k)` feeding a later `.set(...)` call** — bulk / Reflect variants of the same leak.
- **Any new read-only handler that overrides write *traps* but inherits `getOwnPropertyDescriptor`** — descriptor reads are an indirect write path and must be neutralized alongside the direct traps.

### Considered Variants

- **Getter side (`desc.get`, `__lookupGetter__`)** — intentionally left operative; reads are permitted under the read-only contract. Over-blocking here would break the documented `vm.freeze` read behavior.
- **Data-property `writable` flag** — a data descriptor's `writable: true` is cosmetic under ReadOnly, not a channel: writing `frozen.k = v` still routes through the inert `set` trap. Only the *callable* `set` accessor is a real write primitive, so only it is stripped.
- **`ReadOnlyMockHandler`** — extends `ReadOnlyHandler`, so it inherits the override; the `readonly` API is covered by the same fix.
