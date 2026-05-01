# Changelog

## [3.11.1]

Single advisory closed plus prominent documentation of an existing escape hatch. Patch release — no API changes for valid configurations.

### Security fix

- **GHSA-8hg8-63c5-gwmx** — `nesting: true` bypassed `require: false`, allowing sandbox-to-host RCE via inner NodeVM construction. The contradictory option pair `{ nesting: true, require: false }` now throws `VMError` at `new NodeVM(...)` time citing the advisory. Same shape as the GHSA-cp6g eager FileSystem-contract probe — surface contradictory configuration at the API surface, not silently produce an unsandboxed sandbox. ATTACKS.md Category 25.

### Documentation

- New README section **"`nesting: true` is an escape hatch"** under Hardening recommendations. Explains that `nesting: true` lets sandbox code `require('vm2')` and construct nested NodeVMs whose `require` config is chosen by the sandbox (not constrained by the outer config — by design of nesting). **Do not enable `nesting: true` for untrusted code.**
- JSDoc on the `nesting` option (`lib/nodevm.js`) upgraded to spell out the escape-hatch semantics and the GHSA-8hg8 contradictory-pair rejection.
- ATTACKS.md gains Category 25 documenting the configuration trap and a matching row in the "How The Bridge Defends" table.

### Upgrade notes

- **If you set `{ nesting: true, require: false }`** anywhere in your codebase, `new NodeVM(...)` now throws. Either drop `nesting: true` (if you wanted deny-all), or replace `require: false` with an explicit `require` config (e.g. `require: { builtin: [] }`) to acknowledge that vm2 will be requireable. The error message is actionable and links to the README section.
- **No other configurations are affected.** Bare `new NodeVM({ nesting: true })` continues to work as documented; this is the documented escape hatch and is not closed by this patch (out of scope — would change `nesting: true` semantics substantially).

### What this fix does NOT close

`nesting: true` itself remains an escape hatch for any non-trivial `require` config. The fix closes the **specific contradictory pair** flagged by the advisory; the broader recommendation is in the new README section: do not enable `nesting: true` when running untrusted code. Constraint propagation from outer to inner NodeVM (where the outer's `require` config would constrain inner construction) was considered and deferred — it would change the documented semantics of `nesting: true` and is a major-version-shaped change.

## [3.11.0]

Coordinated security release closing 13 advisories, plus a new `bufferAllocLimit` option and a `realpath()` method on the FileSystem adapter contract. Minor version bump because of the new public option and the FileSystem contract addition; no incompatible changes to the existing public API surface. Embedders running untrusted code in memory-constrained environments should review the new `bufferAllocLimit` option and the README's [Hardening recommendations](README.md#hardening-recommendations) section.

### Upgrade notes

- **Custom `fs` adapters with `require.root`** must implement `realpathSync` (or `realpath()` on a fully custom `FileSystem` class). Without it, `new NodeVM({require: {root, fs: customAdapter}})` now throws a `VMError` at construction, citing GHSA-cp6g-6699-wx9c. The eager probe converts what was previously silent deny-by-default at every later `require()` into a single, clearly-labelled construction-time error. Default `fs` users are unaffected — `DefaultFileSystem` and `VMFileSystem` ship `realpath()` out of the box.
- **Embedders running untrusted async code** should install a host-side `unhandledRejection` handler. The GHSA-hw58 fix closes synchronous executor throws but cannot reach async-function / async-generator / `await using` rejection paths (V8 creates rejection promises via the realm's intrinsic `Promise`). See README's Hardening recommendations and ATTACKS.md Category 22.
- **Embedders running untrusted code in memory-constrained environments** should opt into a finite `bufferAllocLimit` (e.g. `32 * 1024 * 1024`) as part of layered DoS defense. Default remains `Infinity` for backwards compatibility.

### Security fixes

- **GHSA-grj5-jjm8-h35p** — Array species self-return sandbox escape. Bridge `apply` and `construct` traps now neutralise host-array `constructor` and `Symbol.species` before every host call (and restore in a `finally` block). Direct write, `Object.assign`, non-configurable defineProperty, and prototype-level constructor variants all blocked.
- **GHSA-v37h-5mfm-c47c** — Handler reconstruction via `util.inspect` leak. Three-layer defense: closure-scoped construction token, `getHandlerObject` WeakMap guard, and `.constructor` sentinel rebind on every handler-class prototype (including `BufferHandler`).
- **GHSA-qcp4-v2jj-fjx8** — Trap method on leaked handler with forged target. New `handlerToTarget` WeakMap pairs every handler with its canonical proxy target at construction; `validateHandlerTarget(this, target)` at the entry of every trap method rejects forged-`this` and forged-`target` invocations with `VMError(OPNA)`.
- **GHSA-47x8-96vw-5wg6** — Cross-realm symbol extraction from host objects. Two-layer defense: dangerous cross-realm symbols (`nodejs.util.inspect.custom`, `nodejs.rejection`, `nodejs.util.promisify.custom`) are filtered at the bridge boundary; structural identity collapse pre-populates the bridge identity caches for every built-in intrinsic prototype + constructor pair so prototype walks land on sandbox primordials.
- **GHSA-55hx-c926-fr95** — Promise structural-leak / SuppressedError / AggregateError sanitisation. `handleException` now recurses into `AggregateError.errors[]` (in addition to `SuppressedError.error`/`.suppressed`); the bridge-level `apply`-trap recognises calls to host `Promise.prototype.{then,catch,finally}` by cached identity and pipes every sandbox callback through the same sanitiser.
- **GHSA-vwrp-x96c-mhwq** — Host intrinsic prototype pollution via bridge write traps. Closure-scoped `protectedHostObjects` WeakMap is populated at bridge init with every entry in `globalsList` + `errorsList` (including `AggregateError`) plus each prototype's `.constructor`. The four write traps (`set`, `defineProperty`, `deleteProperty`, `preventExtensions`) reject with `VMError(OPNA)` when targeting a protected intrinsic.
- **GHSA-947f-4v7f-x2v8** — NodeVM builtin allowlist bypass via host-passthrough builtins. `DANGEROUS_BUILTINS = ['module', 'worker_threads', 'cluster', 'vm', 'repl', 'inspector', 'trace_events', 'wasi']`. Two-layer enforcement: filtered from `BUILTIN_MODULES` (closes `'*'` wildcard expansion) AND rejected in `addDefaultBuiltin` (closes explicit-name + `makeBuiltins(...)` paths). `mock` / `override` escape hatches preserved.
- **GHSA-hw58-p9xv-2mjh** — Promise executor unhandled rejection host-process DoS. `localPromise` constructor wraps the user-supplied executor in try/catch (synchronous throws routed through `handleException` and rejected as sandbox-realm values) and attaches a benign swallow tail to every sandbox-constructed Promise so the host's `unhandledRejection` event never fires. **Known residual: async function / async generator / `await using` paths bypass the executor wrap (V8 creates rejection promises via the realm's intrinsic Promise). Documented in ATTACKS.md Category 22 — embedders should install a host-side `unhandledRejection` handler. See README's Hardening recommendations.**
- **GHSA-6785-pvv7-mvg7** — Unbounded `Buffer.alloc(N)` host-heap DoS. New `bufferAllocLimit` option (default `Infinity` — fully backwards-compatible) caps single allocations on `Buffer.alloc`, `Buffer.allocUnsafe`, `Buffer.allocUnsafeSlow`, deprecated `Buffer(N)`, and `new Buffer(N)`. Embedders running untrusted code should opt into a finite cap (e.g. `32 * 1024 * 1024`) as part of layered DoS defense, the same way they opt into `timeout`. Forwarded from `NodeVM` to its parent `VM` via `super(options)`.
- **GHSA-mpf8-4hx2-7cjg** — Host Promise `.then(onFulfilled)` / sanitiser-callback null-proto unwrapping. Sandbox-side `globalPromise.prototype.then` onFulfilled and the bridge-level host-Promise sanitiser now use `from()` (always wraps) instead of `ensureThis()` (proto-fallthrough on null-proto host objects). `handleException` also switched to `from()` for symmetry on the rejection path.
- **GHSA-v27g-jcqj-v8rw** — `CallSite` host-frame information disclosure via `prepareStackTrace`. `applyCallSiteGetters` redacts every metadata getter (`getFileName`, `getLineNumber`, `getColumnNumber`, `getFunctionName`, `getMethodName`, `getTypeName`, etc.) for host frames; `getEvalOrigin` redacts unconditionally because its return string can embed a host path. `Error.prepareStackTrace` is initialised to `defaultSandboxPrepareStackTrace` at sandbox bootstrap so V8 never falls through to Node's host-side formatter (which throws on Symbol-named errors and emits absolute host paths).
- **GHSA-wp5r-2gw5-m7q7** — Transformer fast-path bypass via `with`/`INTERNAL_STATE_NAME`/unicode-escape identifier. Fast-path bailout now triggers AST instrumentation for any source containing `catch`, `import`, `async`, `with`, the `INTERNAL_STATE_NAME` substring, or any `\u` escape (identifiers like `VM2_INTERNAL_STATE_…` are valid JS and would slip past a literal-string check).
- **GHSA-cp6g-6699-wx9c** — NodeVM `require.root` symlink bypass (path-check / use TOCTOU). Lexical prefix check on `path.resolve()`-resolved candidates was bypassed by symlinks inside the allowed root pointing outside it (Node's native `require()` follows symlinks; CWE-59). Especially severe with pnpm / npm-workspaces / `npm link` layouts where every `node_modules` entry is a symlink by design. Fixed by canonicalising candidate paths via `fs.realpathSync` before the prefix check and canonicalising `rootPaths` at construction time. `DefaultFileSystem` and `VMFileSystem` gain a `realpath()` method; if `realpath` throws at runtime (missing file, broken link) the check denies by default. An eager FileSystem-contract probe at `new NodeVM(...)` time throws `VMError` immediately if `require.root` is set and the adapter cannot dereference symlinks (missing `realpath()` method, or `VMFileSystem` wrapping an `fs` without `realpathSync`) — see Upgrade notes. ATTACKS.md Category 24.

### New options

- **`bufferAllocLimit`** (VM, NodeVM) — non-negative number or `Infinity`. Caps individual `Buffer.alloc` family requests from inside the sandbox. Default: `Infinity`. See README's "Hardening recommendations".

### Other security improvements

- **`trace_events` host-process abort DoS** — surfaced during pre-tag red-team. `trace_events.createTracing({categories: [Proxy<Array>]})` triggered a C++ `IsArray()` assertion failure that aborted the host process. Added to `DANGEROUS_BUILTINS`.
- **`wasi`** added to the denylist — experimental syscall surface (filesystem `preopens`, host clock/random, network) too broad for default `'*'` exposure.

### Documentation

- New README "Hardening recommendations" section covering `bufferAllocLimit` usage, `unhandledRejection` handler shape (mitigates async-fn residual above), `--max-old-space-size` complement, and `'*'` allowlist semantics.
- ATTACKS.md updated for Categories 4, 9, 12, 19, 20, 21, 22, 24 to reflect the deployed defenses, the v27g `getEvalOrigin`/Path A hardening, the qcp4 `validateHandlerTarget`, the wp5r unicode-escape hardening, the GHSA-hw58 async-fn known residual, and the new cp6g symlink-bypass mitigation.

### Test infrastructure

- `scripts/legacy-test-runner.js` now supports `this.skip()` for runtime-conditional skipping and Promise-returning async tests (length-0 `async function () {}`).
