# Host Resources

Host memory, heap and process lifetime: unbounded allocation, unhandled rejections that kill the host process, shared buffer pool disclosure, and callbacks that outlive `timeout`. No defense invariant covers this family yet; each guarantee is stated inside its Mitigation section (see the design spec, section 8).

Categories in this file: [22](host-resources.md#attack-category-22-promise-executor-unhandled-rejection--host-process-dos), [23](host-resources.md#attack-category-23-unbounded-bufferallocn--host-heap-dos), [36](host-resources.md#attack-category-36-bufferalloclimit-bypass-via-arraybuffer--typedarray--webassemblymemory), [41](host-resources.md#attack-category-41-shared-buffer-pool-discloses--corrupts-host-memory), [42](host-resources.md#attack-category-42-finalizationregistry-cleanup-callback--timeout-protection-mechanism-failure).

---

## Attack Category 22: Promise Executor Unhandled Rejection — Host Process DoS

**Advisories**: GHSA-hw58-p9xv-2mjh, GHSA-gjq8-xm47-88rc

**Tests**: test/ghsa/GHSA-hw58-p9xv-2mjh/, test/ghsa/GHSA-gjq8-xm47-88rc/

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

### Sibling — ignored host-promise rejection (host→sandbox direction) — GHSA-gjq8-xm47-88rc

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

**Detection rule:** a host function crossing the bridge that returns a promise the sandbox does not chain on. Structurally, any new host→sandbox return path that can carry a promise must pass through `markHostPromiseHandled` (the `apply` trap already does; `get`/`construct` return non-promise-or-benign values today — see residuals).

Regression coverage: `test/ghsa/GHSA-gjq8-xm47-88rc/` (forked-child survival for `hostReject` / host async fn / `events.once`; in-process delivery of the sanitized rejection and of fulfilled promises).

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

**Advisories**: GHSA-fcqc-726x-5wfc

**Tests**: test/ghsa/GHSA-fcqc-726x-5wfc/

**Uses**: [Category 15: Property Descriptor Value Extraction](host-reference-primitives.md#attack-category-15-property-descriptor-value-extraction) (in spirit — a getter, `Uint8Array.prototype.buffer`, hands back more than the sandbox should see)

Advisory: GHSA-fcqc-726x-5wfc. CWE-200 (Information Exposure) + CWE-787 (Out-of-bounds Write). This is a **confidentiality + integrity** escape, not a DoS — distinct from the `bufferAllocLimit` DoS categories (23, 36) that share the `Buffer.*` chokepoint.

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

### Detection Rules

- `Buffer.from([0]).buffer.byteLength !== 1` inside a sandbox → pooling leak is open.
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
