# Changelog

## [3.10.6]

Coordinated security release closing 13 advisories. Fully backwards-compatible — no breaking public API changes. Embedders running untrusted code in memory-constrained environments should review the new `bufferAllocLimit` option and the README's [Hardening recommendations](README.md#hardening-recommendations) section.

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
- **GHSA-cp6g-6699-wx9c** — NodeVM `require.root` symlink bypass (path-check / use TOCTOU). Lexical prefix check on `path.resolve()`-resolved candidates was bypassed by symlinks inside the allowed root pointing outside it (Node's native `require()` follows symlinks; CWE-59). Especially severe with pnpm / npm-workspaces / `npm link` layouts where every `node_modules` entry is a symlink by design. Fixed by canonicalising candidate paths via `fs.realpathSync` before the prefix check and canonicalising `rootPaths` at construction time. `DefaultFileSystem` and `VMFileSystem` gain a `realpath()` method; if `realpath` throws (missing file, broken link, custom `fs` without `realpathSync`) the check denies by default. ATTACKS.md Category 24.

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

### Notes for embedders with custom filesystem adapters

- The cp6g fix touches the (undocumented) `VMFileSystem` adapter contract: a custom `fs` module that does not expose `realpathSync` will now hit deny-by-default behaviour for any `require.root`-restricted path. Add a `realpathSync` method to your adapter to restore loader behaviour. No public API surface changes.
