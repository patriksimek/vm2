# Attack catalog review findings

Date: 2026-09-02
Baseline: d03323423d5f8760bd84f95e638944e94ef864b4 (`docs: split ATTACKS.md into per-family files (pure move)`); the pre-split single-file catalog it is compared against is its parent, 7e3954ea718be8d41e4ffb452d50e7468e9542ed. Reviewed on Node v26.7.0, vm2 3.12.0.
Scope: the staleness review from docs/specs/2026-09-02-attacks-catalog-restructure-design.md, section 6.

Eight family files were reviewed independently (52 categories), then this pass reconciled the shared material in `docs/ATTACKS.md`. No reviewer found an unblocked PoC: every canonical example that was run was blocked, and no PoC reached a host PID, a host `process`, host `require`, or a host-realm error with a host stack path. The one open item below (Category 22) is a host DoS documented as a known residual, not a realm escape.

## Findings needing follow-up

### Security status — read these first

- **Category 22 (host-resources.md), Known Residual, re-measured on Node v26.7.0 / vm2 3.12.0.** Under the default `allowAsync: true`, **any** async function or async generator whose body rejects produces an `unhandledRejection` on the host after `run()` returns, which terminates a default Node process. The rejection reason is a *sandbox-realm* `Error` (`reason instanceof hostError === false`), confirming the rejection promise comes from the realm intrinsic `globalPromise` and never passes through `localPromise`'s swallow tail. Measured open: 1b (plain `throw` in an async function), 1c (Symbol-named error thrown), 2 (async generator rejecting on `.next()`). Under `allowAsync: false` the transformer refuses async syntax and no payload runs. `await using` at top level is rejected by V8 (top-level `await` in a script), and only inside an async function is it rejected by the acorn `ecmaVersion: 2022` pin — so for that one form the parser pin is load-bearing security today and raising the version reopens it. The three `it.skip` pins in `test/ghsa/GHSA-hw58-p9xv-2mjh/repro.js` all specify the stale `allowAsync: false`, under which nothing runs; they need rewriting against forms 1b/1c/2 as forked-child tests before they can be un-skipped. Embedder mitigation is unchanged: install a host-side `process.on('unhandledRejection', ...)` filter.
- **Category 12 (transformer-and-modules.md).** `eval()` source inherits the transformer's keyword fast-path bailout, so `using` declarations inside `eval()` are never parsed and run uninstrumented. No dedicated regression test exists for that blind spot — the only test that touches it (`test/vm.js "SuppressedError escape via using declaration"`) asserts the SuppressedError defense, not the transformer's blindness. Suggested action: an `it.cond` gated on `typeof DisposableStack === 'function'`.

### `lib/` comments that contradict the corrected catalog

`lib/` is out of scope for this plan; these are recorded for a follow-up that may touch it.

- `lib/setup-sandbox.js:601` says `WebAssembly.JSTag` is "(Node 25+)". Measured present on Node v22.23.2 / v24.19.0 / v25.9.0 / v26.7.0 and absent on v20.20.2, so the comment should read Node 22+ (Category 17; the entry was corrected to "present on Node 22 and later; absent on Node 20 and earlier").
- `lib/setup-sandbox.js:447` still names `wrapHostPromiseThenArgs` in a comment. That function does not exist; the live symbol is `normalizeHostPromiseCallbacks` (`lib/bridge.js:1471`), which the Category 26 entry now names. `wrapHostPromiseCatchArgs` has zero hits anywhere.
- `lib/builtin.js:206-212` comments that an explicit `builtin: ['_http_client']` opt-in still re-exposes underscored builtins. It does not: both the array and object-map branches of `makeBuiltinsFromLegacyOptions` iterate the pre-filtered `BUILTIN_MODULES` and admit only names present there, so both forms yield `Cannot find module '_http_client'`. Only the lower-level `makeBuiltins(['_http_client'])` and `mock`/`override` still work (Category 34; the entry and the `docs/ATTACKS.md` defense-table row were both corrected).
- `lib/setup-sandbox.js:650` attributes the existing `WebAssembly.JSTag` removal to `GHSA-9qj6-qjgg-37qq`. That advisory's repro (`test/ghsa/GHSA-9qj6-qjgg-37qq/repro.js`) is about `neutralizeArraySpeciesBatch` saved-state writes and never mentions JSTag; no repro in `test/ghsa/` names the JSTag mechanism as its own subject. The attribution looks wrong and is the reason Category 17 still carries `**Advisories**: none` (see "Silent-none sweep" under Edits made).

### Catalog items a maintainer should decide

- **Retrospective past tense that a grep does not catch (error-sanitization.md).** Category 16 (~"a related concern that *was* assumed safe"), Category 38 ("was satisfied" / "had a documented gap" / "went unaudited" / "The original recursive pattern was"), Category 39 ("were always covered"), Category 49 ("Storing `true` made a revisit resolve to the raw carrier"). These describe the genuinely pre-fix state, so mechanical conversion to present tense would change their meaning. The other seven family files were converted with the "Before GHSA-xxxx, X did Y. X now does Z." pattern, which `docs/ATTACKS.md`'s Category Entry Format now states explicitly. Suggested action: one deliberate editorial pass over this file with that pattern, rather than per-sentence fixes.
- **Section-name vocabulary is not uniform.** `### Fix shape` appears in Categories 39 and 48 and has been added to the Category Entry Format list. Still unlisted, each appearing once or twice: `### Delivery paths (why one chokepoint is insufficient)` (Cat 48), `### Supersedes` as an H3 rather than the `**Supersedes**:` metadata line (Cat 34 — the docs-catalog `meta` parser does not see it), `### Residual Risk` (Cats 45, 46), `### Accepted Residual` (Cat 47) and `### Composition with Category 45` (Cat 46) alongside the documented `### Known Residual`. Suggested action: pick one shape for residual sections and one for `Supersedes`, then normalise.
- **Compound Attack Patterns does not mirror every compound.** `docs/ATTACKS.md`'s own "After adding an entry" checklist says a compound gets an entry in **Summary → Compound Attack Patterns**, but 25 compounds have no dedicated numbered pattern (20, 21, 22, 23, 24, 25, 26, 27, 28, 32, 34, 35, 36, 37, 38, 39, 40, 41, 42, 46, 47, 48, 49, 50, 52); they appear only inside another pattern's bracketed list or in a defense-table row. This pass gave every one of them a `### How The Bridge Defends` row naming its category, which is what the coverage check requires. Suggested action: decide whether the Compound Attack Patterns section is meant to be exhaustive or a curated "most dangerous chains" list, and either backfill or soften the checklist wording.
- **Category 21 version claim is understated.** The entry says `process.getBuiltinModule(name)` is "Node 22+"; `nvm exec 20 node -e "typeof process.getBuiltinModule"` reports `function` on v20.20.2 (backported to 20.16.0), so a Node 20 embedder on an unpatched version is also exposed. Left unedited because no test gate backs the correction. Suggested action: change to "Node 20.16+ / 22.3+".
- **Category 45 percent-encoded residual leaks a host path through the embedder's own resolver.** The rejected specifier `left-pad/..%2fevil` reaches the embedder's `require.resolve`, which throws a host-realm `MODULE_NOT_FOUND` whose *message* embeds a host absolute path ("Require stack: - /private/tmp/.../cat-45-2.js"), and that message is visible to sandbox code. Not an escape: no module loads and no host object or host `require` crosses, and the documented "each fails as module-not-found" outcome holds. It is Category 48-class information disclosure through a channel Category 48 deliberately leaves open (host error *messages* are preserved; only stack frames are redacted). Worth an explicit decision because the leaked path originates in embedder-supplied resolver code rather than in vm2.
- **`test/ghsa/GHSA-2cm2-m3w5-gp2f/repro.js:126`** ("regression: import() in source is rewritten to throw") uses a bare `assert.throws(() => new VM().run("import('fs')"))` with no expected error — already flagged as SUSPECT in `docs/specs/2026-08-30-vacuity-sweep-findings.md:199`. The behaviour was confirmed by hand (`VMError: Dynamic Import not supported`), but the assertion does not prove it. Suggested action (owner of `test/`): add the `/Dynamic Import not supported/` matcher.
- **`GHSA-35vh-489p-v7cx` had never been tracked anywhere in the repo.** `test/ghsa/GHSA-55hx-c926-fr95/repro.js:6` records `Duplicates merged: GHSA-35vh-489p-v7cx` and `:16` says it "re-reported the same shape"; `lib/setup-sandbox.js:1886` names the pair. It has no test directory and no `CHANGELOG.md` line. It is now on Category 16 as `GHSA-35vh-489p-v7cx (dup of GHSA-55hx-c926-fr95)` per the controller's ruling. Suggested action: confirm the dup rule is "merged-duplicate IDs belong on Advisories lines with a `(dup of ...)` marker" and add the missing `CHANGELOG.md` dup line.

### Resolved during this pass (recorded for completeness)

- Every reviewer's "the `docs/ATTACKS.md` index row still reads X" finding (Categories 16, 38, 44, 45, 46, 49, 51, 52) is closed — see Edits made.
- Category 9's `fromOtherWithContext` has zero hits under `lib/`. Expected, not a defect: the entry describes it as a historical, now-removed method (the Mitigation says the conversion methods "moved to closure-scoped functions"), and it appears only in a historical subsection heading and a code-block comment, never as a currently-cited live defense. No edit.
- Category 13's `**Advisories**: none` is correct — no GHSA has ever been filed for it.

## Unverified

Every item below was left as written in the catalog; each names the Node version or flag that would settle it.

- Category 17, the exact `WebAssembly.JSTag` introduction version: no Node 21 or 23 installed, so the boundary is only bracketed as absent on v20.20.2 / present on v22.23.2. The `it.cond` gate at `test/vm.js:2810` is a feature check, not a version gate, so it neither confirms nor contradicts a version number.
- Category 38, canonical example 2 ("Indirect leak via Node-internal error chaining"): illustrative and self-annotated as carrying no powerful reference, so there is nothing to block and no test asserts it. Not run.
- Category 38, "Node ≤ 11 reports internal errors as `\"RangeError [ERR_INVALID_OPT_VALUE]\"`": needs a Node-internal error that still used that message shape on v8/v10; could not be constructed reliably.
- Category 48 has no fenced PoC block (its trigger is prose only), so there was nothing to run; the defense is covered by its three cited test files.
- Category 22 residual, the original "Confirmed exploitable on Node 15+" claim for `allowAsync: false`: only Node v26.7.0 was available, so Nodes 15–24 could not be re-checked. Git evidence (`checkAsync` dates from 2019–2020, commits ea856e8 / 918cde9) means the `allowAsync: false` framing was never reproducible, which matches what was measured here.
- Category 23's canonical block (`new VM({timeout: 5000}).run('Buffer.alloc(1024*1024*100).length')`) is the pre-fix demo at the default `bufferAllocLimit: Infinity`; not run as written (it would allocate 100 MB with nothing to assert). The mitigation is exercised instead by the capped-bypass block.
- Category 33 version claims ("behind `--experimental-wasm-jspi` on Node 24", "enabled by default on Node 26+", "no-op on Node ≤ 23"): only Node 26.7 available; the GHSA-6j2x repro uses feature detection, not a version cond, so nothing contradicts them.
- Category 51 / Category 33 canonical examples on other Nodes: the `Promise.try` (Node 24+) and `Array.fromAsync` (Node 22+) lower bounds could only be exercised on Node 26.7. `Promise.try` IS gated `NODE_VERSION >= 24` at `test/vm.js:2543` (consistent); `Array.fromAsync` uses a feature check, so its "22+" label is unverified but unchallenged.
- Categories 19, 29, 31: the recursion-depth-binary-search escape PoCs were not executed (slow and V8-timing sensitive); coverage relies on the committed GHSA repros that assert them blocked.
- Category 12, "Why It Works": the claim that the transformer "does not instrument their implicit catch semantics" for `using` is left as written. `using` inside `eval()` was verified to run uninstrumented, but no case was constructed proving a *host* value reaches the sandbox through `using`'s disposal path independently of the SuppressedError defense.
- Categories 21 / 35 detection rules that describe *pre-fix* reachability ("on an unpatched version this expands to include `module`/…") cannot be exercised without checking out an unpatched tree. The post-fix half of each claim was run and holds.
- Category 21, `trace_events.createTracing({categories: [...]})` host-process abort: not run — the documented effect is a V8 C++ assertion that aborts the whole host process. `trace_events` is denied at require time, so the primitive is unreachable; the abort itself is unverified.
- Category 21, `wasi` preview1 syscall surface: not run (would construct a WASI instance against the host CWD). Denial at require time is covered.
- Category 35, the actual exfiltration payloads (`dc.channel(...).subscribe`, `executionAsyncResource()`, `performance.getEntriesByType`, `v8.writeHeapSnapshot`, `os.setPriority`, `dns.setServers`): not run — each mutates host-process state or writes a heap dump to disk. Only the reachability gate was exercised, and every module is denied at require time.
- Category 40, the *native-load* half of `crypto.setEngine` and `node:sqlite` `loadExtension`: verified only that the guard throws before the native call, using a nonexistent `.so` path. No real shared library was loaded.
- Category 47, the `require.external`-without-`root` residual on a fixed future major: the entry defers deny-by-default to the next major, so there is nothing to verify today.
- Category 52, `util.getCallSites` behaviour on Node 22.9–25: verified present on v22.23.2 and v26.7.0 and absent on v20.20.2, consistent with the "Node >= 22.9" claim, but the exact 22.9 boundary was not bisected.
- Category 52, the `SAFE_UTIL_MEMBERS` "one list is correct Node 8→26" claim: the CI matrix in `.github/workflows/test.yml` is `[26, 25, 24, 22, 20, 18, 16, 14, 12, 10, 8]`, consistent with the claim, but the suite was not run on the old runtimes here.
- Category 6: sandbox `Proxy` is `undefined` on Node 10+, so the entry's examples cannot instantiate a Proxy inside the sandbox on any currently-tested runtime — they throw at `new Proxy(...)`. The Mitigation prose still describes the host-side `proxiedProxy` / `wrapProxyHandler` path that applies where `Proxy` is present (Node 8), which was not exercised.

## Coverage gaps

Advisories cited with no test directory: **none.** Every GHSA ID on an `**Advisories**:` line across all eight family files has a `test/ghsa/<id>/` directory, except the two marked duplicates, whose primaries do: `GHSA-59g5-pmg6-5gr4 (dup of GHSA-3vgf-8m4q-q4qr)` on Category 20, `GHSA-m3pp-qgq7-gwm6 (dup of GHSA-wjwh-qqvp-g4p4)` on Category 33, and the newly added `GHSA-35vh-489p-v7cx (dup of GHSA-55hx-c926-fr95)` on Category 16. `test/docs-catalog.js` enforces this.

Test-side gaps that are not missing directories:

- `test/ghsa/GHSA-hw58-p9xv-2mjh/repro.js`: the three `it.skip` pins for the Category 22 residual all specify `allowAsync: false`, under which no payload runs, so they document nothing as written. They need rewriting against the measured-open forms 1b/1c/2 as forked-child tests.
- Category 12's `using`-in-`eval()` blind spot has no dedicated regression test.
- `test/ghsa/GHSA-2cm2-m3w5-gp2f/repro.js:126` asserts with a matcher-free `assert.throws`.

## PoCs run

Every canonical example listed here was executed against the working tree on Node v26.7.0 and **blocked**. Harness paths are under the review scratchpad.

Host reference primitives:
- Cat 1 (constructor chain / `__proto__` / catch-error variants) — `ReferenceError: process is not defined` for all three.
- Cat 2 (`Object.prototype` "get" pollution; `Buffer.prototype.__defineGetter__`) — `ReferenceError: process is not defined`; `TypeError: 'defineProperty' on proxy trap returned falsish`.
- Cat 3 (`Symbol.hasInstance` bypass; `error.name = Symbol()`) — `ReferenceError: process is not defined`; `.name` returned a sandbox Symbol.
- Cat 5 (`arguments.callee.caller`; `fn.caller.constructor`) — returned `null`; `TypeError` reading `constructor` of `null`.
- Cat 8 (`getOwnPropertySymbols` extract; `Symbol.for` promisify; `Function.prototype.value` + WASM `compileStreaming`) — extraction `undefined`; sandbox-local `Symbol.for` surrogate; `compileStreaming` is not a function in the sandbox.
- Cat 10 (Buffer.apply chain; `Object.create` override; `Array` constructor override) — `TypeError: p.call is not a function` (GHSA-88hf denied-getter sentinel); no leak.
- Cat 15 (descriptor value extraction via chained entries) — `TypeError: p.call is not a function`.
- Cat 18 (call-with-unwrap array species self-return) — `TypeError: p.call is not a function`.

Error sanitization:
- Cat 4, three blocks (prepareStackTrace/CallSite `getThis`; stack-overflow `RangeError` chain; Error Generation Primitive via promise rejection) — `no-host-this`; `ReferenceError: process is not defined`; the promise fulfils with a sandbox string.
- Cat 16, three blocks (DisposableStack; `using` via eval; AsyncDisposableStack) — sandbox `TypeError` on `.suppressed` of `null`; `no ctor chain: null` twice.
- Cat 17 (wasm JSTag catch) — `JSTag deleted from sandbox` (host has `typeof WebAssembly.JSTag === 'object'`, sandbox sees `undefined`).
- Cat 38, all 8 documented variants plus 2 test-only ones — direct / frozen / accessor / TOCTOU / lying-Proxy `.cause` all read back `undefined`; nested `.cause.cause` stripped; `SuppressedError.error` accessor TOCTOU yields the benign snapshot; prototype-inherited and arbitrary own props `undefined`.
- Cat 39 (`.call` / `.apply` / stacked `.call.call` / `catch.call`) — all four shapes deliver a rebuilt sandbox error whose `.detail` is `undefined`; the `onRejected` callbacks do fire, so this is not a silent drop.
- Cat 49 (duplicate-in-array, self-cycle, mutual cycle, plain host error twice with a prototype leak) — every shape returns `leak gone: undefined`.

Promise and async:
- Cat 7 (`Symbol.species` + static-method stealing) — sandbox `'done'`, host `report()` never called.
- Cat 33 (canonical JSPI, Node 26.7 with JSPI default-on, no flag) — `TypeError: WebAssembly.Suspending is not a constructor`.
- Cat 43 (canonical `p.finally()` species) — `Error: Unsafe Promise species cannot be reset` from the finally wrapper's `resetPromiseSpecies`.
- Cat 51, all 10 documented entry points — 7 threw `VMError: Async not available` synchronously; the 3 constructor-resolve-capability paths returned without throwing but the guarded resolve refused the thenable, and a host-visible sink confirmed the thenable never executed late.

Host prototype mutation:
- Cat 20 (`__lookupGetter__` / `Buffer.apply` walk to host `Object.prototype`) — `TypeError: p.call is not a function`; host marker never set.
- Cat 26, two blocks (null-proto throw + `Buffer.prototype.inspect` in catch; the `Promise.resolve({__proto__:null}).then` variant) — `ReferenceError: process is not defined`.
- Cat 30 (WASM-streaming + `__proto__` setter severance) — delivery refused; pivot returned `no-process`.
- Cat 37, two blocks (stacked double-indirection severance; the GHSA-cfcw `bind` + host-side `map` laundering) — `TypeError` on `Function.prototype.call` against a non-function; the severed host error is neutralized by `isForeignSeveredHostValue` / `thisEnsureThis`.
- Cat 50 (NodeVM raw `__proto__` getter climb to `EventEmitter.prototype`) — reader delivery refused; host `EventEmitter.prototype.emit` untouched.

Bridge internals:
- Cat 6, all four canonical blocks — each throws `TypeError: Proxy is not a constructor` (sandbox `Proxy` is sealed to `undefined`).
- Cat 11 (targeted `Function.prototype.call` override) — `no-capture`; the bridge uses cached `Reflect.apply`.
- Cat 14 (`Object.prototype` `has` trap) — `process` stays undefined.
- Cat 27, five reflective probes — `globalThis[NAME]`, `Reflect.get`, `getOwnPropertyDescriptor`, `getOwnPropertyNames.find` all `undefined`; `NAME in globalThis` is `false`.
- Cat 28 Variant A (RCE, `process.pid` probe) and Variant B (observability) — the `Array.prototype[N]` setter never fires in either.
- Cat 44, all four descriptor channels against a `vm.freeze`d host object with an accessor — all four throw `TypeError` because `desc.set` is stripped; the host backing field is unchanged.

Transformer and modules:
- Cat 12, four harnesses (canonical block; eval/Function scoping; does eval reach the transformer; fast-path attribution) — internal-state identifiers rejected with `SyntaxError: Use of internal vm2 state variable` including from inside `eval()` and `new Function()` with a runtime-assembled name; `eval("{using …}")` runs (the documented blind spot, not an escape) while `new Function("{using …}")` and an eval'd string containing `catch` are both parsed and rejected.
- Cat 13 — `import(...)` throws `VMError: Dynamic Import not supported` (sync, and as a rejection inside an async function); root traversal and absolute paths throw `VMError: Cannot find module`, with a widened-`root` control proving the refusal is the `rootPaths` check.

NodeVM require and allowlists:
- Cat 21, six blocks (`module`, `process.getBuiltinModule`, `inspector/promises`, the `-node:child_process` deny token, the `fs`/`fs/promises` family gap, the `node:test` host-process launcher) — every spelling `VMError: Cannot find module`; no process spawned, no write attempted.
- Cat 24 (file- and directory-level symlink out of `require.root`) — `VMError: Cannot find module`.
- Cat 25 (`{nesting: true}` + inner NodeVM) — `VMError` at construction citing GHSA-m4wx-m65x-ghrr; all six shape classes rejected; the documented `{nesting: true, require: {}}` escape hatch still constructs.
- Cat 34, two harnesses — all underscored builtins denied under `['*','-http',…]`; the escape-hatch check drove the Mitigation correction (`makeBuiltins` and `mock` work; the legacy array and object-map forms do not).
- Cat 35 (`diagnostics_channel` subscribe; the `async_hooks`/`perf_hooks`/`v8` one-liners; the `os`/`dns` writes) — denied at the require gate for all eight spellings under `['*']`, under an explicit allowlist, and under the object-map form.
- Cat 40, three harnesses (`crypto.setEngine` / `tls.setDefaultCACertificates` incl. the `URLSearchParams.getAll()` host-array manufacture; `node:sqlite` extension loading; `http`/`https` `globalAgent`) — throwing stubs fire before the host call; `ERR_INVALID_STATE` from Node itself; the host-side `globalAgent` marker is `undefined` in the sandbox.
- Cat 45, three harnesses — only `left-pad` itself loads; all six hostile specifiers denied; `LEFT-PAD` denied (safe direction); the host-path-in-message observation is recorded above, not an escape.
- Cat 46, two harnesses — prefix-sharing siblings denied plain and scoped; `foo`'s own subfile still loads and `transitive: true` still permits the sibling, both as documented.
- Cat 47 — `require('vm2')` denied for all five spellings; the accepted residual is still open by design (arbitrary absolute host path loads, one-time `console.warn` fires); `lib/cli.js` confirmed to set `root: pa.dirname(script)` and `context: 'sandbox'`.
- Cat 52 — `util.getCallSites` is not a function in the sandbox; all six removed members read `undefined` via `util`, `sys` and `node:util`; the six kept members still work.

Host resources:
- Cat 22, canonical Promise-executor block, plus the residual variants v1/v1b/v1c/v2/v3/v3b across {default, `allowAsync:true`, `allowAsync:false`} as 18 forked child runs, plus a variant-2 mechanism diagnosis and an `await using` SyntaxError-origin experiment. The canonical block is blocked (child exit 0, host survives). The residual results are in "Findings needing follow-up" above: v1b, v1c and v2 kill the host under the default and `allowAsync: true`; everything is refused under `allowAsync: false`.
- Cat 23 (`Buffer.alloc` / `Buffer.concat` / `Buffer.from({length})`) with `bufferAllocLimit: 8 MiB` and a 16 MiB request — `RangeError: Buffer allocation size 16777216 exceeds bufferAllocLimit 8388608`.
- Cat 36 (`ArrayBuffer` / `Uint8Array` / `SharedArrayBuffer` / `WebAssembly.Memory` / string-coerced size) — same `RangeError`.
- Cat 41 (`Buffer.from([0]).buffer.byteLength`, `Buffer.alloc(1).buffer.byteLength`) — returns `1`, backing store depooled to exact size, not 65536.
- Cat 42 (canonical `FinalizationRegistry` block, run under `node --expose-gc` with `gc()` forced) — `typeof FinalizationRegistry` / `WeakRef` is `undefined` and the PoC throws `ReferenceError`, so no GC callback can register; deterministic, not inconclusive.

## Edits made

### Family files, by the eight family reviews

**host-reference-primitives.md (Categories 1, 2, 3, 5, 8, 10, 15, 18).** Filled the `**Tests**:` line for Categories 1, 2, 3, 5, 10, 15 and 18 and extended Category 8's from bare advisory directories to specific files plus the three symbol-extraction suites. Corrected two stale link texts ("[Category 10: Array Species Self-Return]" → Category 18; "[Category 8 / Category 20]" → "[Category 8]"), both targets already correct. Corrected Category 3's Mitigation from the removed `neutralizeArraySpecies` to the live `neutralizeArraySpeciesBatch` (via `neutralizeArraySpeciesOn`). Reframed one retrospective sentence in Category 8.

**error-sanitization.md (Categories 4, 16, 17, 38, 39, 48, 49).** Filled or normalised the `**Tests**:` line on all seven so every cited advisory appears as its `test/ghsa/<id>/` directory with file names in parentheses. Set `**Advisories**:` on Categories 16, 38 and 49 from their repro headers. Added variant lines under Canonical Examples for Categories 16, 38 and 49. Replaced Category 16's stale line-number citation with the live `wrappedPromiseThen` / `wrappedPromiseCatch` / `wrappedPromiseFinally` names. Corrected Category 17's version claim to "present on Node 22 and later; absent on Node 20 and earlier" (measured). Rewrote Category 48's `**Supersedes**` so its text agrees with a real target (Category 4), removing the misleading `../ATTACKS.md#defense-invariants` link.

**promise-async.md (Categories 7, 19, 29, 31, 33, 43, 51).** Filled Category 7's `**Tests**:` with 13 verified citations and Category 51's with its GHSA directory plus `test/vm.js ("async")`. Set Category 51's `**Advisories**:` to `GHSA-f8gf-w286-fmq2` from the repro header. Verified the file's preamble invariant note names only live symbols; no edit needed.

**host-prototype-mutation.md (Categories 20, 26, 30, 32, 37, 50).** Corrected three references to the non-existent `wrapHostPromiseThenArgs` / `wrapHostPromiseCatchArgs` to the live `normalizeHostPromiseCallbacks` (Category 26). Fixed two garbled link texts ("[Category 47x8]", "[Category 8 / Category 20 / GHSA-m5q2-4fm3-vfqp]"). Rewrote all six retrospective "historically" / "previously" sentences with the "Before GHSA-xxxx, … now …" pattern. No Advisories, Tests or heading line touched.

**bridge-internals.md (Categories 6, 9, 11, 14, 27, 28, 44).** Filled the `**Tests**:` line for Categories 6, 11, 14 and 44 and extended it for 9, 27 and 28. Retitled Category 9's three "Why X Was Dangerous (NOW FIXED)" subsections and deleted three inline markers from its code-block comments, keeping every code block. Set Category 44's `**Advisories**:` to `GHSA-633r-hq9m-c4ff`.

**transformer-and-modules.md (Categories 12, 13).** Filled both `**Tests**:` lines. Corrected the claim that `eval()` / `new Function()` are never seen by the transformer — both are proxied and their source *is* transformed; the blind spot is the keyword fast-path bailout, not `eval()` itself. Named the live `INTERNAL_STATE_NAME` rejection and repaired a garbled unicode-escape example. Category 13's Mitigation now names the `ImportExpression` rewrite, the `setup-sandbox.js` throw, and `isPathAllowed` / `rootPaths`, with two verified qualifications. Added variant lines to both entries.

**nodevm-require.md (Categories 21, 24, 25, 34, 35, 40, 45, 46, 47, 52).** Extended the `**Tests**:` line on Categories 21, 24, 25, 45 and 46. Corrected `**Advisories**:` on Categories 45 (`GHSA-c48m-32m9-vx93`), 46 (`GHSA-7q3f-wx44-378m` alone) and 52 (`GHSA-r273-hxvj-fxhp`; `GHSA-v27g-jcqj-v8rw` kept in the prose, where it is the superseded redaction). Corrected Category 34's Mitigation escape-hatch bullet (the legacy `builtin:` array and object-map opt-ins do not work; only `makeBuiltins` and `mock`/`override` do). Fixed two stale link texts and a dangling "see the Status section above". Rewrote five detection-rule bullets to present tense. Appended re-verification sentences to the Category 45, 46 and 47 residual sections.

**host-resources.md (Categories 22, 23, 36, 41, 42).** Rewrote Category 22's Known Residual status line and payload block against measurement: the payloads now run under `allowAsync: true` (they document nothing under `allowAsync: false`), variants 1b, 1c and 3b were added, every comment carries its measured outcome, and the two `await using` forms are attributed correctly (payload 3 to V8's top-level-`await` rule, payload 3b to the acorn pin). Rewrote the `it.skip` sentence to say the pins are stale. Rewrote the `allowAsync: false` detection bullet and Category 23's "Now capped" bullet to present tense. Merged Category 36's standalone `### Tests` H3 into its `**Tests**:` line.

### Shared files, this pass

**Index parity (step 2).** Reconciled nine rows in the `### Categories` table of `docs/ATTACKS.md` to their entries — never the reverse:

| Category | Index row was | Index row now |
|---|---|---|
| 16 | none | GHSA-55hx-c926-fr95, GHSA-35vh-489p-v7cx (dup of GHSA-55hx-c926-fr95) |
| 18 | none | GHSA-grj5-jjm8-h35p |
| 38 | none | GHSA-m283-3h24-438v |
| 44 | none | GHSA-633r-hq9m-c4ff |
| 45 | GHSA-cp6g-6699-wx9c | GHSA-c48m-32m9-vx93 |
| 46 | GHSA-c48m-32m9-vx93, GHSA-7q3f-wx44-378m | GHSA-7q3f-wx44-378m |
| 49 | none | GHSA-x965-fc75-jpqh |
| 51 | none | GHSA-f8gf-w286-fmq2 |
| 52 | GHSA-v27g-jcqj-v8rw | GHSA-r273-hxvj-fxhp |

**Merged duplicate.** Added `GHSA-35vh-489p-v7cx (dup of GHSA-55hx-c926-fr95)` to Category 16's `**Advisories**:` line and index row, on the evidence of `test/ghsa/GHSA-55hx-c926-fr95/repro.js:6` ("Duplicates merged: GHSA-35vh-489p-v7cx") and `:16` ("GHSA-35vh-489p-v7cx re-reported the same shape"), corroborated by `lib/setup-sandbox.js:1886`.

**Silent-none sweep.** The split script derived each entry's Advisories from GHSA IDs spelled in its prose, so an entry that never spelled its advisory got `none`. After reconciliation, the only categories numbered 16 or above still showing `none` were 17 and 18.

- **Category 18 (Array Species Self-Return via Constructor Manipulation) gained `GHSA-grj5-jjm8-h35p`.** Repro-header evidence: `test/ghsa/GHSA-grj5-jjm8-h35p/repro.js:2` reads `* GHSA-grj5-jjm8-h35p — Array species self-return sandbox escape`, verbatim the category's title and mechanism, and its `describe` at `:87` is `GHSA-grj5-jjm8-h35p (array species self-return escape)`. Corroborated by `lib/bridge.js:1619` (`// SECURITY (GHSA-grj5-jjm8-h35p): Array species self-return escape defense.`). The entry's `**Tests**:` line gained `test/ghsa/GHSA-grj5-jjm8-h35p/ (repro.js, descriptor-chain-history.js)` and the index row was set in the same edit.
- **Category 17 (WebAssembly JSTag Exception Catch) keeps `none`.** No repro header in `test/ghsa/` names the JSTag mechanism as its own subject. The only repro that mentions JSTag at all is `test/ghsa/GHSA-6j2x-vhqr-qr7q/repro.js:47`, whose header is about JSPI (Category 33) and cites JSTag only as the precedent it mirrors. `lib/setup-sandbox.js:650` attributes the JSTag removal to `GHSA-9qj6-qjgg-37qq`, whose repro is about `neutralizeArraySpeciesBatch` and never mentions JSTag — recorded above as a `lib/` comment to check.

**How to Use This Document (step 3).** Item 1 now says "matches the patterns in the family files", and the paragraph after the numbered list gained the split-layout sentence directing readers to the Category Index by number and the family table by mechanism.

**Retrospective markers (step 4).** Deleted 13 ` (NOW FIXED)` tokens from `### Compound Attack Patterns` (patterns 14–16 and 21–29). The Category Entry Format rule that forbade the marker quoted it literally, which kept the grep non-zero; it was rephrased to state the rule without the token and to give the "Before GHSA-xxxx, … now …" pattern the family reviews used. `grep -c "NOW FIXED"` is now 0 in every catalog file.

**Appendices (step 5).**
- `## Considered Attack Surfaces`: replaced the `**Error.cause**` bullet with the `**Error.cause on sandbox-created errors**` bullet that distinguishes the sandbox-realm case from the host-error case and links Categories 38 and 39.
- `## Future Risks`: deleted the `**WASM JSPI**` bullet (closed by Category 33) and added the generalised `**Any primitive that returns a sandbox-realm object with a host-realm prototype**` bullet in its place at the end of the list.
- Read every remaining bullet against the category titles. Nothing else was fully superseded, so five gained a "see Category N" pointer rather than being deleted: **SharedArrayBuffer / Atomics** → Category 36 (allocation-size surface); **TypedArray species** → Category 18 (the Array form of the same primitive); **Symbol.isConcatSpreadable** → Category 18, plus the dead `neutralizeArraySpecies` name corrected to `neutralizeArraySpeciesBatch`; **`nodejs.util.inspect.custom` on host-side proxy targets** → Category 9 (the handler-exposure surface `util.inspect` opened before); **Decorators / Symbol.metadata** → Category 8 (a new well-known symbol reaching the sandbox is that mechanism, so `isDangerousCrossRealmSymbol` must learn each one); **Transformer ecmaVersion upgrades** → Category 12 (the blind spot) and Category 22 (the `await using` form the pin holds shut). Left untouched, because no category covers them: structuredClone, private fields, iterator helpers, `Proxy.revocable`, WeakRef/FinalizationRegistry (already linked to Category 42), ShadowRealm, `Error.isError()`, Temporal.

**Summary coverage (step 6).** Before the pass, the coverage script reported no Summary mention of Categories 20, 23, 25, 27, 32, 34, 35, 36, 37, 39, 40, 41, 42 and 50. Twelve existing `### How The Bridge Defends` rows gained their category number in the attack cell (20, 25, 27, 32, 34, 35, 37, 39, 40, 41, 42, 50), and two rows were added from the entries' Mitigations — Category 23 (`bufferAllocLimit`, `checkBufferAllocLimit`, the `BUFFER_STATIC_CLASSIFIED` fail-closed gate) and Category 36 (`installAllocationCaps`, `coerceAllocMagnitude`, the pinned `prototype.constructor` back-references). The script now prints nothing. While correcting Category 34's row, the disproven "Explicit opt-in (`builtin: ['_http_client']`) … still work" sentence was replaced with what the harness measured. The dead `neutralizeArraySpecies` name was corrected to `neutralizeArraySpeciesBatch` in Defense Invariant 4 and in the two defense-table rows that carried it (test titles that contain the old name verbatim were left alone).

**Human decisions (step 7).** `### Fix shape` appears in two entries (Categories 39 and 48), so it was added to the `## Category Entry Format` section list; `### Delivery paths` and the H3 `### Supersedes` appear once each and were left as they are, with the vocabulary inconsistency recorded above. The deferred one-line doc-consistency edits were applied:

- transformer-and-modules.md: the `using`-in-`eval()` detection rule now attributes the bypass to the keyword fast-path bailout, matching the corrected Mitigation; two "`makeFunction` … proxied" references now name `FunctionHandler` (`lib/setup-sandbox.js:3077`), which calls `makeFunction`.
- host-resources.md: three "no longer …" phrasings rewritten in the present tense; "The mirror-image direction was still open" reframed as "Before GHSA-gjq8-xm47-88rc the mirror-image direction was open; `markHostPromiseHandled` now closes it"; "deferred past v3.10.6" changed to "still deferred as of v3.12.0" to match the entry's v3.12.0 status line; Category 36's merged Tests parenthetical now names `GHSA-v836-6xw4-9cx3/repro.js`.
- nodevm-require.md: `test/nodevm.js ("nesting" > "NodeVM")` normalised to `test/nodevm.js ("NodeVM")`.
- error-sanitization.md: Category 4's quoted-title repro citation normalised to the directory form `test/ghsa/GHSA-v27g-jcqj-v8rw/ (repro.js)`.
- host-prototype-mutation.md: one further `neutralizeArraySpecies` → `neutralizeArraySpeciesBatch` correction in Category 32's Considered Attack Surfaces.

### Verification

`npx mocha test/docs-catalog.js` — 8 passing. `verify-split.js` against `7e3954ea718be8d41e4ffb452d50e7468e9542ed --no-body` — `ok: 52 categories, 62 advisories, 168 fence lines` (no category, heading, advisory or code fence lost). `grep -rn "none linked" docs/attacks/` — no output. `grep -c "NOW FIXED"` — 0 in every catalog file. `npm run lint` — clean apart from the pre-existing parse error in `test/additional-modules/my-es-module/index.js`, which predates this work.
