# Host Resources

Host memory, heap and process lifetime: unbounded allocation, unhandled rejections that kill the host process, shared buffer pool disclosure, and callbacks that outlive `timeout`. No defense invariant covers this family yet; each guarantee is stated inside its Mitigation section (see the design spec, section 8).

Categories in this file: [22](host-resources.md#attack-category-22-promise-executor-unhandled-rejection--host-process-dos), [23](host-resources.md#attack-category-23-unbounded-bufferallocn--host-heap-dos), [36](host-resources.md#attack-category-36-bufferalloclimit-bypass-via-arraybuffer--typedarray--webassemblymemory), [41](host-resources.md#attack-category-41-shared-buffer-pool-discloses--corrupts-host-memory), [42](host-resources.md#attack-category-42-finalizationregistry-cleanup-callback--timeout-protection-mechanism-failure).

---

## Attack Category 22: Promise Executor Unhandled Rejection — Host Process DoS

**Advisories**: GHSA-hw58-p9xv-2mjh, GHSA-gjq8-xm47-88rc, GHSA-2v2p-6j97-cjg9

**Tests**: test/ghsa/GHSA-hw58-p9xv-2mjh/, test/ghsa/GHSA-gjq8-xm47-88rc/, test/ghsa/GHSA-2v2p-6j97-cjg9/

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
- **`allowAsync: false`** combined with any Promise construction — this mode blocks the sandbox-side `.catch`, which would otherwise guarantee an unhandled rejection; `localPromise`'s swallow tail consumes the rejection regardless, so both modes are equally safe.
- Hostile patterns: `new Promise(() => { throw hostError; })`, `Promise.reject(hostError)` without `.catch()`, async function bodies that throw without try/catch.

### Known Residual — async function / async generator / `await using`

**Status: open as of v3.12.0 on Node v26.7.0, under the default `allowAsync: true`, for any async function or async generator whose body rejects.** Variants 1b, 1c and 2 below each terminate the host process: `run()` returns normally, then `unhandledRejection` fires with a sandbox-realm `Error`. Under `allowAsync: false` none of the async payloads run — the transformer flags async syntax (`hasAsync`) and `checkAsync` throws `VMError('Async not available')` before execution. The two `await using` payloads are inert in every mode, but for two different reasons. Payload 3 is rejected by **V8**, which does not allow top-level `await` in a script (`at new Script (node:vm:118:7)`); the transformer never even parses it, because the keyword fast path returns any source without `catch`/`import`/`async`/`with` unchanged. Payload 3b is the one the parser pin holds shut: it contains `async`, so acorn at the pinned `ecmaVersion: 2022` parses it and fails on the `using` declaration, while V8 and acorn at `latest` both accept it — so raising that parser version puts **3b** back in scope, not 3. Variant 1 as originally written does not reject at all: reading `.stack` on a Symbol-named error does not throw inside the sandbox, so the body completes normally.

```javascript
// 1. async function with Symbol-named Error.stack — does not reject on Node v26.7.0
new VM({ allowAsync: true }).run(`(async function(){
  var e = new Error(); e.name = Symbol(); e.stack;
})();`);

// 1b. OPEN — any async function body that rejects kills the host
new VM({ allowAsync: true }).run(`(async function(){
  throw new Error('boom');
})();`);

// 1c. OPEN — same, carrying the Symbol-named error as the rejection reason
new VM({ allowAsync: true }).run(`(async function(){
  var e = new Error(); e.name = Symbol(); e.stack; throw e;
})();`);

// 2. OPEN — async generator throw on .next()
new VM({ allowAsync: true }).run(`(async function*(){
  throw new Error('boom');
})().next();`);

// 3. AsyncDisposableStack with throwing Symbol.asyncDispose — SyntaxError from
//    V8: top-level `await` is not allowed in a script. The transformer never
//    parses this source at all (no catch/import/async/with keyword => fast path).
new VM({ allowAsync: true }).run(`
  await using x = { [Symbol.asyncDispose]() { throw Symbol() } };
`);

// 3b. the same inside an async function, so top-level await is not the blocker.
//     V8 accepts this; the SyntaxError comes from the transformer's acorn pin
//     (ecmaVersion 2022), which cannot parse the `using` declaration.
new VM({ allowAsync: true }).run(`(async function(){
  await using x = { [Symbol.asyncDispose]() { throw Symbol() } };
})();`);
```

V8 creates the rejection promises for `async function`, `async function*`, and `await using` machinery **via the realm's intrinsic Promise (`globalPromise`)** — *not* via `localPromise`. The `localPromise extends globalPromise` constructor and its swallow tail are therefore bypassed entirely. Closing this from inside vm2 requires either (a) a process-level `unhandledRejection` handler scoped to sandbox-realm errors, or (b) rebinding the realm's `%Promise%` intrinsic. Both approaches change observable host behaviour and are still deferred as of v3.12.0.

**Recommended mitigation for embedders**: install a host-side `process.on('unhandledRejection', ...)` handler that filters or swallows sandbox-originated rejections. See README "Hardening recommendations" for code patterns.

An `it.skip`-marked block in `test/ghsa/GHSA-hw58-p9xv-2mjh/repro.js` pins the three originally-reported variants (1, 2, 3) so the gap stays visible to maintainers. Those pins are stale on two counts: each specifies `allowAsync: false`, under which no payload runs, and of the three only the async-generator variant still reproduces — the async-function pin uses the non-rejecting form 1 rather than 1b/1c, and the `await using` pin (payload 3) never reaches the sandbox because V8 rejects top-level `await` in a script. They need rewriting against the forms above, as forked-child tests, before any of them can be un-skipped.

Re-verified 2026-09-02 on Node v26.7.0.

### Considered Attack Surfaces

- **`Promise.reject(hostError)` directly**: routes through `localPromise` (because `Promise.reject` delegates to `new this(...)`) and gains the swallow tail. Covered.
- **Silent-failure trade-off**: sandbox developers cannot use Node's host-side `unhandledRejection` log to surface their own debug rejections. They must explicitly attach `.catch()` for visibility. Acceptable trade-off given the DoS severity; documented for users.

### Sibling — ignored host-promise rejection (host→sandbox direction) — GHSA-gjq8-xm47-88rc, GHSA-2v2p-6j97-cjg9

Category 22 and its parent GHSA-hw58 close the **sandbox→host** direction: a promise *constructed in the sandbox* that rejects with no handler. Before GHSA-gjq8-xm47-88rc the mirror-image direction was open; `markHostPromiseHandled` now closes it. When an embedder-exposed host function — or a host builtin such as `events.once(emitter, name)` — returns a **host-realm** rejected `Promise`, the bridge `apply` trap wraps it and hands the sandbox a proxied promise, but the **underlying host promise** has no rejection reaction of its own. If sandbox code merely calls the function and ignores the result, Node's default `unhandledRejection` policy (Node 15+) sees the raw host promise reject with no handler and **terminates the host process**:

```js
const vm = new VM({ sandbox: { hostReject: () => Promise.reject(new Error('boom')) } });
vm.run('hostReject(); 1');   // host process aborts on Node 15+
```

Why the Category 22 defenses do not cover it: the swallow tail lives on `localPromise` (the *sandbox* Promise). A host promise returned across the bridge is never constructed through `localPromise`, so it never gains a tail. The GHSA-55hx apply-trap sanitizer only fires when the sandbox *actively calls* `.then`/`.catch`/`.finally` on the host promise — the PoC calls neither. The host promise's rejection therefore reaches V8's microtask queue with no reaction attached.

**Mitigation (fix):** in the bridge `apply` trap, whenever a host function invoked from the sandbox (`isHost === false`) returns a value, `markHostPromiseHandled(ret)` attaches a benign no-op reaction — `otherReflectApply(otherPromiseThen, ret, [noop, noop])` — to the underlying host promise on the host side, using the *cached* host `Promise.prototype.then`. This marks the host promise "handled" for Node's bookkeeping. Key properties:

- **No suppression for the sandbox.** Promises multicast: the sandbox's own `.then`/`.catch` reaction (routed through the GHSA-55hx sanitizer) still fires and still observes the sanitized, sandbox-realm rejection value independently of the no-op.
- **No new unhandled rejection.** The no-op `onRejected` returns `undefined`, so the derived promise from `.then(noop, noop)` *fulfills* — it never itself becomes unhandled.
- **No leak.** The no-op never touches the rejection value; no raw host error or host promise reaches the sandbox through this path. Sanitization is still owned by GHSA-55hx / `handleException`.
- **Non-promises are inert.** The built-in `then` requires the `[[PromiseState]]` internal slot and throws on anything else; the call is wrapped in try/catch, so fulfilled promises and non-promise return values are untouched.

**Detection rule:** a host function crossing the bridge that returns a promise the sandbox does not chain on.

Regression coverage: `test/ghsa/GHSA-gjq8-xm47-88rc/` (forked-child survival for `hostReject` / host async fn / `events.once`; in-process delivery of the sanitized rejection and of fulfilled promises).

#### Every other delivery route — GHSA-2v2p-6j97-cjg9

The `apply` return value is only one of the ways a host promise reaches the sandbox. Before GHSA-2v2p-6j97-cjg9 the other routes were all still bare, and each one kills the host exactly as the parent PoC does:

- **`construct` trap.** A host constructor's body may `return` an object, which overrides `this`. `BaseHandler.construct` wrapped that value with `thisFromOtherWithFactory` and never marked it. Reached through `new` and through `Reflect.construct`, and equally with a promise that rejects on a later tick.
- **`get` trap.** A host accessor that mints a fresh rejected promise per read: the sandbox reads the property once and drops the value.
- **Callback arguments.** A host function that hands a rejected host promise to a sandbox callback — the promise is an argument, so it never transits an `apply` *return*.

```javascript
// (advisory GHSA-2v2p-6j97-cjg9)
function HostRejectCtor() { return Promise.reject(new Error('ctor-boom')); }
new VM({ sandbox: { HostRejectCtor } }).run('new HostRejectCtor(); 1');
// Host process aborts on the next microtask drain — the sandbox never touched
// the value. Same outcome for `Reflect.construct(HostRejectCtor, [])`, for a
// host getter returning `Promise.reject(...)`, and for a rejected host promise
// passed as an argument to a sandbox callback.
```

**Why it works:** GHSA-gjq8's mitigation is bound to one trap. Marking per return path is a *specific* fix: it closes the route in the PoC and leaves every sibling route open, because the property that actually matters is about **delivery**, not about calls.

**Mitigation:** the mark moves to the host→sandbox delivery chokepoint. `thisProxyOther` in `lib/bridge.js` is the single function that gives a host object its sandbox proxy — `apply` and `construct` returns, `get`/descriptor values, callback arguments and iterator yields all funnel through it via `thisFromOtherWithFactory` / `thisEnsureThis` / `thisFromOtherForThrow`. Its `!isHost` delivery block (which already marks host prototypes for GHSA-88hf-g992-jg85) now also calls `markHostPromiseHandled(other)` when `isOtherPromise(other)` holds. This restores the invariant **every host promise delivered into the sandbox carries a benign rejection reaction before sandbox code can ignore it** — the host→sandbox half of [Defense Invariant #2](../ATTACKS.md#defense-invariants) ("paths that bypass JS-level `catch` instrumentation … host-realm `Promise.then` rejection … are closed at the bridge"). Properties:

- **One mark per host object.** `thisProxyOther` runs on the first crossing only; later deliveries hit the `mappingOtherToThis` cache, already marked. A promise that rejects long after it crossed is covered, because the reaction is attached at crossing time.
- **No throw/catch per delivered object.** `isOtherPromise` is a brand check: it walks the *other* realm's prototype chain to the cached host `Promise.prototype` (`otherPromisePrototype`, captured at bridge init next to `otherPromiseThen`). Nothing is invoked on the value, so a non-promise host object costs a short prototype walk instead of a thrown `TypeError`. `Object.prototype.toString` is deliberately not used as the brand: it reads `Symbol.toStringTag`, which fires host `get` traps — a host `Proxy` whose `get` trap mints a fresh rejected promise would be crashed by the brand check itself. The walk is capped at 100 links so an embedder-authored `Proxy` chain that regenerates its own prototype cannot spin it.
- **Second host realms are covered.** A promise minted in another host realm (`vm.runInNewContext`, nested contextify) matches no cached identity, so a chain that terminates at a non-null object which is *not* the cached host `Object.prototype` is treated as a possible promise and handed to `markHostPromiseHandled`. The built-in `Promise.prototype.then` brand-checks the `[[PromiseState]]` slot, which is realm-independent, so a foreign-realm promise gets marked and a foreign-realm non-promise or thenable never has its own `then` invoked. Same-realm and null-prototype objects terminate before that branch, so the hot path keeps its no-throw property.
- **The call traps keep their unconditional mark.** `apply` keeps the GHSA-gjq8 call and `construct` gains the matching one, both after `stripDangerousSymbolsFromHostResult`. They are not redundant: a host promise whose prototype chain the host detached (`Object.setPrototypeOf(p, null)`) is invisible to the brand check but still tracked by V8, and `markHostPromiseHandled`'s `[[PromiseState]]`-slot try/catch handles it. Once per call, this costs nothing on the hot delivery path.
- **Nothing else changes.** As with GHSA-gjq8: promises multicast, so a sandbox `.then`/`.catch` still observes the sanitized rejection; the no-op `onRejected` returns `undefined`, so the derived promise fulfills; fulfilled promises, non-promise constructor returns, and prototype-carrying host instances are untouched.

**Detection rules:**

- Any host→sandbox delivery path — a constructor return, an accessor, a callback argument, an iterator yield — that can carry a host promise the sandbox is free to ignore.
- A fix expressed per trap rather than at `thisProxyOther`: assume the sibling traps are open until each is covered.
- Embedder shapes that hand promises out without a call: `Object.defineProperty(hostObj, 'ready', {get() { return doAsync(); }})`, factory constructors returning `fetch`-style promises, host emitters passing a pending promise to a sandbox listener.

**Known residual:** the brand check depends on the walk reaching a recognisable terminus, so *any* host-side chain manipulation that stops it early defeats it — a detached prototype (`Object.setPrototypeOf(Promise.reject(x), null)`), a `Proxy` prototype whose `getPrototypeOf` throws, a chain longer than the 100-link cap. Delivered through a non-call route, such a promise is recognized by neither layer (through a call it still is, because `apply` / `construct` mark unconditionally). The sandbox has no lever on any of this: there is no `Proxy` in the sandbox realm, so no `getPrototypeOf` trap can be mounted, and `Object.setPrototypeOf` / `__proto__ =` / `Reflect.setPrototypeOf` on a host object are all refused with `VMError`. Every one of these shapes has to be built by the embedder.

Regression coverage: `test/ghsa/GHSA-2v2p-6j97-cjg9/` (forked-child survival under `--unhandled-rejections=strict` for the constructor, late-rejecting, `class` + `new`, `class` + `Reflect.construct`, prototype-detached, getter and callback-argument routes, plus a cross-realm promise through a getter, a data property and a callback argument; in-process controls for the sanitized rejection through the construct and getter routes, non-promise and fulfilled constructor returns, prototype methods, and a late `.catch`).

---

## Attack Category 23: Unbounded `Buffer.alloc(N)` — Host Heap DoS

**Advisories**: GHSA-6785-pvv7-mvg7, GHSA-gmc2-2x9w-cgh9, GHSA-v836-6xw4-9cx3

**Tests**: test/ghsa/GHSA-6785-pvv7-mvg7/, test/ghsa/GHSA-gmc2-2x9w-cgh9/, test/ghsa/GHSA-v836-6xw4-9cx3/

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

- **`new Uint8Array(N)`, `new ArrayBuffer(N)`, `new SharedArrayBuffer(N)` and other typed-array constructors**: same primitive class — synchronous native allocation by attacker-controlled size. [Category 36](host-resources.md#attack-category-36-bufferalloclimit-bypass-via-arraybuffer--typedarray--webassemblymemory) (GHSA-v836-6xw4-9cx3) caps these: it wraps every `ArrayBuffer` / `SharedArrayBuffer` / TypedArray / `WebAssembly.Memory` constructor with the same `bufferAllocLimit` cap when a finite limit is configured.
- **`String.prototype.repeat(N)`**: produces a sandbox-realm string of size `len * N` bytes, similar primitive. Not capped here.
- **Repeated allocations under the cap** (e.g., 32 × `Buffer.alloc(32 MiB)`): an aggregate per-run budget would close this but would require tracking allocation totals across the bridge. Out of scope for the canonical advisory.
- **WebAssembly `memory.grow`**: governed by wasm `maximum` declaration at instantiation; not currently wrapped.

The fix closes the canonical reported DoS (Buffer.alloc family + concat + from + copyBytesFrom) and the fail-closed gate ensures future Buffer.* additions are caught at sandbox-init time rather than only by the next reported advisory.

---

## Attack Category 36: `bufferAllocLimit` Bypass via ArrayBuffer / TypedArray / WebAssembly.Memory

**Advisories**: GHSA-6785-pvv7-mvg7, GHSA-v836-6xw4-9cx3

**Tests**: test/ghsa/GHSA-6785-pvv7-mvg7/, test/ghsa/GHSA-v836-6xw4-9cx3/ (`GHSA-v836-6xw4-9cx3/repro.js` — 40 cases: per-constructor caps, constructor-walk recovery, resizable/growable, WebAssembly.Memory, coercion variants (string / `valueOf` / `Symbol.toPrimitive` / array-like), TOCTOU canonicalization, the documented residual, NodeVM forwarding, and non-breaking default behaviour)

**Supersedes**: completes the "tracked for follow-up" residual of [Category 23: Unbounded `Buffer.alloc(N)` — Host Heap DoS](host-resources.md#attack-category-23-unbounded-bufferallocn--host-heap-dos).

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

---

## Attack Category 41: Shared Buffer Pool Discloses / Corrupts Host Memory

**Advisories**: GHSA-fcqc-726x-5wfc, GHSA-489w-w794-jq94

**Tests**: test/ghsa/GHSA-fcqc-726x-5wfc/, test/ghsa/GHSA-489w-w794-jq94/

**Uses**: [Category 15: Property Descriptor Value Extraction](host-reference-primitives.md#attack-category-15-property-descriptor-value-extraction) (in spirit — a getter, `Uint8Array.prototype.buffer`, hands back more than the sandbox should see)

CWE-200 (Information Exposure) + CWE-787 (Out-of-bounds Write). This is a **confidentiality + integrity** escape, not a DoS — distinct from the `bufferAllocLimit` DoS categories (23, 36) that share the `Buffer.*` chokepoint. The category has two halves: buffers the SANDBOX allocates (GHSA-fcqc-726x-5wfc) and buffers the HOST allocates and hands in (GHSA-489w-w794-jq94).

### Description

Node serves small `Buffer.from(...)`, `Buffer.concat(...)`, `Buffer.of(...)`, `Buffer.copyBytesFrom(...)` and `Buffer.allocUnsafe(...)` allocations out of **one shared backing `ArrayBuffer`** of `Buffer.poolSize` bytes (64 KiB on modern Node; 8 KiB on Node 8). Many small buffers are packed into that single pool at different `byteOffset`s. A pooled buffer's `.buffer` getter (`Uint8Array.prototype.buffer`) returns the **whole pool** — not just the buffer's own slice. Any host-realm buffer that happens to share the pool (`Buffer.from(secret)`, DB rows, session tokens, decrypted material) is therefore both **readable and writable** from inside the sandbox:

```javascript
const ab = Buffer.from([0]).buffer;                 // the ENTIRE 64 KiB pool ArrayBuffer
const view = Buffer.from(ab, 0, ab.byteLength);     // a Buffer over every pooled byte
view.toString('latin1');                            // DISCLOSE neighbouring host buffers
view.fill(0x41);                                    // CORRUPT them
```

`Buffer.from([0]).buffer.byteLength === 65536` inside the sandbox proved the leak: the returned ArrayBuffer is 64 KiB while the buffer is 1 byte. The `.buffer` reference never crosses a capability check — it is an ordinary getter on a bridge-proxied Uint8Array — so the bridge's realm isolation does not help: the bytes it exposes are genuinely the sandbox's to touch *and* everyone else's that landed in the same pool.

### Attack Flow

1. Host code (embedder or a Node-internal on the same tick) creates a small buffer holding a secret; Node places it in the shared pool.
2. Sandbox allocates any small buffer via a pooling factory (`Buffer.from([0])`).
3. Sandbox reads `.buffer` → the full pool ArrayBuffer.
4. Sandbox builds a full-width view with the `Buffer.from(arrayBuffer, 0, byteLength)` overload (which legitimately shares the passed ArrayBuffer).
5. Sandbox reads the view (disclosure) or writes it (corruption), reaching every byte of every buffer currently pooled.

### Canonical Examples

```javascript
// Disclosure
const secret = Buffer.from('SESSION=deadbeef');   // host, lands in pool
new VM().run(`
    const pool = Buffer.from([0]).buffer;
    Buffer.from(pool, 0, pool.byteLength).toString('latin1');  // contains SESSION=deadbeef
`);

// Corruption
new VM().run(`
    const pool = Buffer.from([0]).buffer;
    Buffer.from(pool, 0, pool.byteLength).fill(0x41);          // overwrites host buffers
`);
```

### Why It Works

`Buffer.from(array | string | typedarray | arrayLike)`, `Buffer.concat`, `Buffer.of`, and `Buffer.copyBytesFrom` return **pool-backed** buffers (`byteOffset !== 0` and/or `buffer.byteLength === poolSize`). The `bufferAllocLimit` chokepoint (Categories 23/36) only guarded *how many bytes* these factories allocate; it never constrained *which backing store* they return. `Buffer.alloc` / `allocUnsafe` / `allocUnsafeSlow` were already safe here only incidentally — the sandbox wrappers route them to the non-pooled `LocalBuffer.alloc`.

### Mitigation

`lib/setup-sandbox.js` enforces a **backing-store ownership invariant**: a buffer handed to the sandbox must own its entire backing store — `byteOffset === 0` **and** `buffer.byteLength === length`. Then `.buffer` can reveal nothing beyond the buffer's own bytes.

- `depoolBuffer(buf)` returns `buf` when it already owns an exact-size backing store, otherwise copies it into a standalone `LocalBuffer.alloc(n)` (non-pooled, zero-filled, byteOffset 0) via the raw host `Buffer.prototype.copy` primitive.
- Applied at every sandbox-facing pooling factory: `bufferFrom` (the non-ArrayBuffer overloads), `concat`, `copyBytesFrom`, a new `bufferOf` wrapper, and the deprecated `Buffer(...)` / `new Buffer(...)` call forms (`BufferHandler` now routes its non-numeric path through `bufferFrom`).
- The `Buffer.from(arrayBuffer | sharedArrayBuffer, byteOffset, length)` **sharing** overload is preserved (copying it would break the documented shared-memory contract). It is detected by a spoof-proof brand test — `apply`ing the captured `ArrayBuffer.prototype`/`SharedArrayBuffer.prototype` `byteLength` getter, whose internal-slot check a sandbox cannot fake. This is safe because small allocations do not pool, so the only ArrayBuffer a sandbox can pass is one it already owns, and every sandbox buffer's `.buffer` is now exact-size — so the shared view can only ever span the sandbox's own bytes.

Views derived from a depooled buffer (`slice`, `subarray`, `map`, `filter`, species-constructed results) are safe: they either view the parent's now-exact-size, sandbox-owned backing store, or are freshly constructed through the Category-36-capped TypedArray constructors. No copy is needed for them.

### Variant: Host-Allocated Buffers Crossing The Bridge (GHSA-489w-w794-jq94)

The `depoolBuffer` rule above only reaches buffers a **sandbox-facing factory** produced. A buffer the **host** allocated and then handed to the sandbox never passes through any of those wrappers, so its `.buffer` still delivers the whole pool. Every ordinary NodeVM configuration produces such buffers: `require: { builtin: ['zlib'] }` and `zlib.deflateSync('hello')` returns a 13-byte host `Buffer` sitting at some offset inside Node's 64 KiB pool. The same holds for an embedder-supplied `sandbox: { b: Buffer.from('hello') }`, for a host `Buffer` passed as a callback argument, and for `fs.readFileSync` results.

#### Attack Flow

1. Host code (a builtin, the embedder, or a Node internal on the same tick) allocates small buffers holding secrets; Node packs them into the shared pool.
2. Sandbox obtains any host-allocated `Buffer` — a builtin's return value, a sandbox-injected buffer, a callback argument.
3. Sandbox reads the buffer's backing store — `.buffer`, or its legacy twin `.parent` (DEP0004), both of which return the **same** `ArrayBuffer`. The bridge `get` trap forwards the raw host accessor and wraps its result, which is the **whole pool**.
4. Sandbox builds a full-width view with `Buffer.from(ab, 0, ab.byteLength)` — the sharing overload, which delegates to host `Buffer.from` and therefore views the raw pool.
5. Sandbox reads it (disclosure) or writes it (corruption), reaching every byte of every host buffer currently pooled.

#### Canonical Examples

```javascript
// Host-builtin return value (NodeVM with the zlib builtin)
new NodeVM({ require: { builtin: ['zlib'] } }).run(`
    const r  = require('zlib').deflateSync('hello');   // 13-byte host Buffer
    const ab = r.buffer;                               // the ENTIRE 64 KiB pool
    const view = Buffer.from(ab, 0, ab.byteLength);
    view.toString('latin1');                           // DISCLOSE host buffers
    view.fill(0x41);                                   // CORRUPT them
`, 'attack.js');

// Embedder-supplied host Buffer
new VM({ sandbox: { b: Buffer.from('hello') } }).run(`
    const ab = b.buffer;                               // the ENTIRE 64 KiB pool
    Buffer.from(ab, 0, ab.byteLength).fill(0x41);
`);

// The SAME store under its legacy name. `Buffer.prototype.parent` (DEP0004) is
// still live, so a defense that keys on the property name `buffer` alone leaves
// the whole escape open through this one accessor.
new VM({ sandbox: { b: Buffer.from('hello') } }).run(`
    const p = b.parent;                                // the ENTIRE 64 KiB pool
    Buffer.from(p, 0, p.byteLength).fill(0x41);
`);

// Getter-extraction shape: pull the raw host %TypedArray%.prototype.buffer (or
// Buffer.prototype.parent) getter out through a host-bound __lookupGetter__
// primitive (Category 30/37) and invoke it with the host Buffer as receiver,
// sidestepping the `get` trap.
new VM({ sandbox: { b: Buffer.from('hello') } }).run(`
    const g = Buffer.call.call({}.__lookupGetter__, b, 'buffer');
    g.call(b).byteLength;                              // 65536 before the fix
`);
```

#### Why It Works

The backing store is reached through accessors that read a V8 internal slot — `%TypedArray%.prototype.buffer`, `DataView.prototype.buffer`, and the legacy `Buffer.prototype.parent`, all of which hand back the *same* `ArrayBuffer`. The bridge invokes it on the raw host object and wraps whatever comes back, so the pool ArrayBuffer crosses as an ordinary value — no capability check is involved. The sandbox-side `Buffer.from(arrayBuffer, byteOffset, length)` ownership rule cannot catch it either: a **full-width view of the pool owns its whole backing store** (`byteOffset === 0`, `byteLength === buffer.byteLength`), so it satisfies the ownership test exactly and is passed through unchanged. The rule has to be applied to the *host view being read*, not to the sandbox buffer being built — and keyed on the identity of the value being delivered, not on a list of property names, or a sibling accessor re-opens it.

#### Mitigation

`lib/bridge.js` restores the **backing-store ownership invariant** stated in the Mitigation above — a buffer visible to the sandbox may expose no byte beyond its own — in the **host→sandbox** direction, where no sandbox-side factory can enforce it. The references it needs are captured at bridge init, per [Defense Invariant #8](../ATTACKS.md#defense-invariants). The rule is keyed on **identity, not on a property name**: when a value read off a host `ArrayBufferView` **is** that view's backing store and the view does not own the whole store (`byteOffset !== 0 || byteLength !== store.byteLength`), the sandbox receives a **bounded copy** — a host-side `ArrayBuffer.prototype.slice(byteOffset, byteOffset + byteLength)` of exactly the view's own bytes — never the shared store. `.buffer`, `.parent` and any future alias are covered by that one rule.

- `otherBoundedViewStore(view, value)` is the chokepoint. It classifies the view (`%TypedArray%.prototype` vs `DataView.prototype`) and the store (`ArrayBuffer.prototype` vs `SharedArrayBuffer.prototype`) by prototype-chain identity against references cached at bridge init, reads the view's store and extent through the matching cached intrinsic getters, and copies with the realm-correct `slice`.
- Applied in `BaseHandler.get` for every object-valued read off a host view and, defensively, in `BaseHandler.getOwnPropertyDescriptor` for a shadowing own data descriptor. The hot-path gate is the cached host `ArrayBuffer.isView`, an internal-slot check that cannot be faked or throw; everything else runs only for genuine host views.
- **Fail closed, where the bridge can tell.** If `view` carries the `ArrayBufferView` internal slot but the bridge cannot read its extent — a realm exposing `%TypedArray%.prototype` without its `buffer` / `byteOffset` / `byteLength` accessors, a detached view on an engine whose getters throw, or a `slice` that throws — an `ArrayBuffer` coming off that view is refused with `VMError` rather than delivered. Silently substituting an empty store would corrupt legitimate data flows with no diagnosable signal; delivering the store is the vulnerability itself. Values that are *not* backing stores still cross normally, so ordinary property reads on such a view keep working. This says nothing about a store the bridge cannot **classify** — see the Known Residual.
- **The brand check itself must be reachable.** `ArrayBuffer.isView` is resolved from the OTHER realm's global `ArrayBuffer` first, with `ArrayBuffer.prototype.constructor` only as a fallback: hanging it off `constructor` alone let a host app disable the entire defense by shadowing that one property before vm2 loaded. If neither route yields it in a realm that has view prototypes at all, `otherIsView` falls back to a prototype-chain walk and `otherBoundedViewStore` refuses outright, so a missing brand check can never mean "bounding off".
- **A foreign store on a host view is refused.** A backing store read off a host view that is *not* that view's own store can only have been planted by the embedder (an own data property or accessor shadowing `buffer` / `parent` with some other `ArrayBuffer`). There is no extent to bound it to and it is very likely another pooled store, so it is refused with `VMError` — one identity compare on a path already taken.
- `SharedArrayBuffer`-backed views are bounded the same way: `SharedArrayBuffer.prototype.slice` yields a fresh, smaller `SharedArrayBuffer`, so the wider shared store — and any host-realm view onto it — stops at the bridge.
- The raw host `%TypedArray%.prototype.buffer`, `DataView.prototype.buffer` and `Buffer.prototype.parent` getters — and the matching offset getters `%TypedArray%.prototype.byteOffset`, `DataView.prototype.byteOffset` and `Buffer.prototype.offset`, so an extracted getter cannot contradict the bounded store by reporting the view's true offset inside the pool — are registered as **undeliverable** raw host accessors (the same identity set and chokepoints the raw prototype readers of [Category 37](host-prototype-mutation.md) use), so the getter-extraction shape collapses to a non-callable sentinel and every invocation shape — direct, `Function.prototype.call`/`.apply`/`.bind`, `Reflect.apply`/`construct` — is refused. Ordinary property reads are unaffected: they never travel through the `apply` trap. Host `Buffer` is not a JS intrinsic and is exposed on Node's global through a lazy getter, so it is resolved off the OTHER realm's global at bridge init, through both descriptor shapes, and skipped entirely on a host without `Buffer`.
- **The triple stays consistent.** Once a view's store is delivered bounded, that view's `byteOffset` — and the legacy numeric `offset` — read as `0` from the same `get` trap, because the store the sandbox holds now starts at the view's own first byte. Without this the standard Node re-view idiom `Buffer.from(v.buffer, v.byteOffset, v.length)` would throw `RangeError: "offset" is outside of buffer bounds`.
- `bufferOwnsExactBackingStore` in `lib/setup-sandbox.js` no longer tries to *observe* ownership — bounding makes `byteOffset === 0` and `buffer.byteLength === length` read identically for a pooled buffer and an owning one, and each `.buffer` read of a non-owning view costs a copy. It decides by construction instead, from Node's own pooling rule (`allocate()` uses the shared pool only when `size < (Buffer.poolSize >>> 1)`): anything smaller is copied unconditionally, anything larger already owns its store. Over-copying is always safe; the bridge-side bounding is the backstop if Node's rule ever changes. The `Buffer.from(arrayBuffer, byteOffset, length)` **sharing** overload is preserved for a host-realm `ArrayBuffer` too — the sandbox-side internal-slot brand test cannot recognize a bridge proxy, so `bufferFrom` additionally accepts the result when its own backing store **is** the argument, an identity no sandbox look-alike can forge.

**Observable behaviour.** For a host view that does not own its whole backing store:

- `.buffer` / `.parent` is a **bounded copy**: `hostBuf.buffer !== hostBuf.buffer` (a fresh copy per read) and writes through it are not host-visible.
- `byteOffset` and the legacy numeric `offset` read as **0**.
- Sub-views the sandbox itself creates from a host-backed `Buffer` (`hostBuf.subarray(4, 8).buffer`) lose `.buffer` aliasing with their parent as well — they are bounded to their own bytes. Index writes on such a sub-view still alias the parent and are still host-visible; only the *store* is decoupled. This is accepted, not engineered around: a sub-view that could widen back to its parent's store is the same escape one hop away.
- Every `.buffer` / `.parent` read of a non-owning host view is a **fresh host-side copy**, so reading one in a loop amplifies allocation and copying proportionally to the view's size times the number of reads. It is bounded by the sandbox `timeout` like any other sandbox-driven work, and by the view's own length — not by the pool's — but a large sub-view read repeatedly is measurably more expensive than it was.
- `Buffer.from(hostArrayBuffer, byteOffset, length)` over a **strict sub-range** of a host-realm `ArrayBuffer` **below `Buffer.poolSize / 2`** returns a copy rather than a live view, for the same reason. Larger sub-ranges stay live views: such stores are never pooled, so `depoolBuffer` leaves them alone. The full-range form — the documented re-view idiom — always shares.
- The `Buffer.from(arrayBuffer, …)` sharing overload discussed here is about **host-realm** `ArrayBuffer`s, which reach the sandbox as bridge proxies. A **sandbox-realm** `ArrayBuffer` passed to a host `Buffer` API is rejected by Node's own internal-slot check, exactly as before this fix — pre-existing behaviour, unchanged.
- A `SharedArrayBuffer`-backed view is delivered as a **copy**, so an embedder that wants live cross-realm sharing must hand the sandbox a view that spans the whole store.

A host buffer that owns its whole store (`Buffer.alloc(n)`, anything at or above `Buffer.poolSize / 2`) is untouched: same object, identity-stable, still write-through — the only case where writing through `.buffer` ever had defined host-visible meaning.

**Known Residual.** The bridge can only bound a store it can tie to a *view*, and can only recognise a store whose prototype chain it can classify. Two embedder-authored shapes remain:

- **A bare `ArrayBuffer` handed over directly** — a host object property whose value *is* a pooled `ArrayBuffer` (`{ pool: Buffer.from('x').buffer }`), or a host function that returns one (`function leak() { return Buffer.from('x').buffer; }`). No view is in the picture at all, so there is no extent to measure against and the store is delivered as-is. Planting such a store *on a view*, as an own `buffer` / `parent` property or accessor, is no longer a residual — it is refused; see the Mitigation.
- **A store the bridge cannot classify** — for example a host view over an `ArrayBuffer` from a *different host realm* (another `vm` context, a worker), whose prototype is not the cached `ArrayBuffer.prototype`. `otherBackingStoreInfo` returns null and the value is delivered raw rather than refused. Such a store is not Node's shared pool but an embedder-constructed cross-realm one, and refusing it would break legitimate multi-realm embedders, so it is documented rather than closed.

Both require the embedder to deliberately hand over a raw or cross-realm `ArrayBuffer`. The rule for embedders is: hand the sandbox the `Buffer` (or a full-store view) and let the bridge bound it — never its raw backing store.

### Detection Rules

- `Buffer.from([0]).buffer.byteLength !== 1` inside a sandbox → pooling leak is open.
- `hostBuffer.buffer.byteLength > hostBuffer.length` for any host-allocated buffer reachable from the sandbox (a builtin's return value, an injected `sandbox` buffer, a callback argument) → the host→sandbox half is open.
- `hostBuffer.parent.byteLength > hostBuffer.length` → the same half is open through the legacy `parent` accessor. More generally: **any** own accessor on a host binary-data prototype that returns the backing `ArrayBuffer` must be bounded or denied, not just `buffer`. Enumerate them per engine — on Node 26 they are `%TypedArray%.prototype.buffer`, `DataView.prototype.buffer` and `Buffer.prototype.parent` — and prefer a rule keyed on the identity of the delivered value over a list of names.
- Any new host→sandbox read path that can surface a host `ArrayBuffer` without passing through `otherBoundedViewStore`.
- Sandbox code that reaches for a raw host backing-store getter (`__lookupGetter__`, `getOwnPropertyDescriptor` on a host prototype) rather than reading the property.
- Any sandbox-facing `Buffer`/typed-array factory whose result has `byteOffset !== 0` or `buffer.byteLength !== length`.
- Reading `.buffer` on a pooled buffer and passing it to the `Buffer.from(ab, off, len)` overload.
- New `Buffer.*` factories in future Node versions must be checked for pool-backing, not just alloc-size (the `BUFFER_STATIC_CLASSIFIED` fail-closed gate from Category 23 catches *unclassified* methods, but a method classified SAFE for alloc-size could still return a pooled buffer — reclassify with pooling in mind).

---

## Attack Category 42: `FinalizationRegistry` Cleanup Callback — `timeout` Protection-Mechanism Failure

**Advisories**: GHSA-r4fx-v8hh-22mv

**Tests**: test/ghsa/GHSA-r4fx-v8hh-22mv/

### Description

The `timeout` option only bounds the **synchronous body** of `run()`. It is implemented with V8's `TerminateExecution`, an interrupt watchdog that unblocks the single in-flight `run()` call and nothing else — as the README states, *"Timeout is only effective on synchronous code that you run through `run`."* A `FinalizationRegistry` cleanup callback is invoked by the garbage collector at an unpredictable later time, **after `run()` has already returned**, so a busy-loop inside it executes sandbox code entirely outside any timeout accounting and blocks the host's single-threaded event loop for an arbitrary duration with no relationship to the configured `timeout`. This is in scope as a **protection-mechanism failure of the documented `timeout` control** — not as a general DoS-prevention claim. vm2 does not and never has claimed to prevent every form of resource exhaustion (see the README Hardening recommendations / Known Issues), and this is not a realm escape: sandbox code stays in its own realm throughout.

### Attack Flow

1. Sandbox registers a cleanup callback against an object it creates, then drops the only strong reference: `registry.register(target, x); target = null;`.
2. `run()` returns almost instantly (registration is O(1)), well inside `timeout` — vm2 believes execution completed safely.
3. At a later GC (forceable under memory pressure or `--expose-gc`), V8 invokes the cleanup callback on its own native callback path — not a new `run()` call, so `doWithTimeout` never wraps it.
4. The callback busy-loops; the entire host event loop is frozen for its duration.

### Canonical Example

```javascript
// (advisory GHSA-r4fx-v8hh-22mv)
const vm = new VM({ timeout: 200 });
vm.run(`
    let target = {};
    const registry = new FinalizationRegistry(() => {
        const s = Date.now(); while (Date.now() - s < 3000) {}   // block 3s
    });
    registry.register(target, 'x');
    target = null;                                               // GC-eligible
`);
// run() returns in ~0ms. A host setTimeout(10) does not fire for ~3000ms.
```

### Why It Works

`timeout` bounds only the synchronous `run()` body. Any execution the engine schedules to run *after* `run()` returns is outside that window. The other out-of-band schedulers are already handled: timers (`setTimeout`/`setInterval`/`setImmediate`) and `queueMicrotask` are not exposed to the `VM` sandbox at all, and `Promise` continuations (the same class) are closed by `allowAsync: false`. `FinalizationRegistry` was the one out-of-band executor still reachable in the default configuration — and, unlike Promise continuations, **`allowAsync: false` does not close it** because the GC, not the sandbox's async machinery, fires the callback.

### Mitigation

Remove `FinalizationRegistry` and `WeakRef` from the default sandbox globals in `lib/setup-sandbox.js` (`localReflectDeleteProperty(global, …)`), the same way timers are withheld. `NodeVM` inherits the removal (it extends `VM` and shares the bootstrap). Neither constructor has literal syntax, so once the global binding is deleted it cannot be reconstructed from within the sandbox — verified against `Function`/`GeneratorFunction`/`eval` (all resolve free identifiers against the sandbox global → `ReferenceError`), constructor-chain climbs off surviving weak collections (`WeakMap`/`Promise` → `undefined`), and `Reflect.get` / `getOwnPropertyDescriptor` on `globalThis`. `WeakRef` cannot itself schedule a callback (`deref` is synchronous) and is removed only for tidiness alongside its registry. Embedders who genuinely need these for trusted code can re-expose them explicitly through the `sandbox` option (mirrors the timers story). **Residual, by design:** an embedder that re-exposes `FinalizationRegistry` through `sandbox` re-opens this vector in full — the removal is the default-configuration defense, not a wrapper that re-times the callback. The general caveat still holds: `timeout` bounds only the synchronous `run()` body, so any future global that can invoke sandbox code after `run()` returns re-opens the class.

### Detection Rules

- **`new FinalizationRegistry(cb)`** in sandbox code where `cb` performs a busy-loop or any expensive synchronous work.
- Any sandbox use of a GC-scheduled callback (`FinalizationRegistry.prototype.register`) whose callback is attacker-controlled.
- More broadly, any newly-exposed global that can invoke sandbox code **after `run()` returns** (a new timer-like or GC-like primitive) re-opens this class and must be withheld or wrapped in a re-timed host dispatcher.

### Considered Attack Surfaces

- **`WeakRef` alone**: cannot schedule execution — `deref()` is synchronous and returns within the `run()` timeout window. Removed only as the pair to `FinalizationRegistry`; keeping it would be safe.
- **`Promise` continuations** (`Promise.resolve().then(busyLoop)`): same after-`run()` class, but already closed by `allowAsync: false`, which the README pairs with `timeout`. `Promise` cannot be removed (fundamental primitive).
- **`Atomics.wait(ta, i, v)` on a `SharedArrayBuffer`**: parks the thread synchronously *inside* `run()`, so V8's `TerminateExecution` **does** interrupt it — verified it throws `Script execution timed out` at the configured limit. Bounded; not in this class.
- **Buffer/TypedArray/`WebAssembly.Memory` allocation**: synchronous native work, a different DoS class already capped by `bufferAllocLimit` — see [Category 23](host-resources.md#attack-category-23-unbounded-bufferallocn--host-heap-dos) and [Category 36](host-resources.md#attack-category-36-bufferalloclimit-bypass-via-arraybuffer--typedarray--webassemblymemory).
- **Objects returned from `run()` with sandbox `valueOf`/`toString`/`Symbol.toPrimitive`**: run sandbox code when the *host* later touches them — already documented in the README `timeout` warning ("operating on returned objects can run arbitrary code and circumvent the timeout"). Out of band via the host, not the GC.
