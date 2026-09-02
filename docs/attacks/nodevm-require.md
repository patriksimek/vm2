# NodeVM require and Allowlists

`NodeVM`'s module boundary: the builtin allowlist and its wildcard, `require.root`, `nesting`, the external-package matcher, host-authority members of allowed builtins, and `util` passthrough.

Defense invariants enforced by fixes in this family: 13 (see [Defense Invariants](../ATTACKS.md#defense-invariants)).

Categories in this file: [21](nodevm-require.md#attack-category-21-nodevm-builtin-allowlist-bypass-via-host-passthrough-builtins), [24](nodevm-require.md#attack-category-24-nodevm-requireroot-symlink-bypass-path-checkuse-toctou), [25](nodevm-require.md#attack-category-25-nodevm-nesting-configuration-trap-nesting_override-only-resolver), [34](nodevm-require.md#attack-category-34-nodevm-wildcard-exposes-undocumented-underscored-builtins--network-capability-bypass), [35](nodevm-require.md#attack-category-35-nodevm-process-wide-observability-builtins-host-data-info-leak), [40](nodevm-require.md#attack-category-40-host-authority-builtin-members-survive-the-read-only-wrap), [45](nodevm-require.md#attack-category-45-nodevm-external-package-allowlist-bypass-via-unanchored-matcher-and--traversal), [46](nodevm-require.md#attack-category-46-nodevm-external-package-allowlist-bypass-via-unanchored-module-path-prefix), [47](nodevm-require.md#attack-category-47-sandbox-rebuilt-an-unrestricted-nodevm-by-requiring-vm2-from-disk-shipped-cli-ran-untrusted-scripts-with-no-effective-sandbox-boundary), [52](nodevm-require.md#attack-category-52-host-util-members-auto-forwarded-to-the-sandbox-utilgetcallsites-host-call-stack-leak).

---

## Attack Category 21: NodeVM Builtin Allowlist Bypass via Host-Passthrough Builtins

**Advisories**: GHSA-947f-4v7f-x2v8, GHSA-rp36-8xq3-r6c4, GHSA-8686-vhfx-7r3j, GHSA-6rh5-qq4q-97xh, GHSA-qhwx-74w5-xhxq, GHSA-m5w8-4gq2-6f8x

**Tests**: test/ghsa/GHSA-947f-4v7f-x2v8/, test/ghsa/GHSA-rp36-8xq3-r6c4/, test/ghsa/GHSA-8686-vhfx-7r3j/, test/ghsa/GHSA-6rh5-qq4q-97xh/, test/ghsa/GHSA-qhwx-74w5-xhxq/, test/ghsa/GHSA-m5w8-4gq2-6f8x/, test/nodevm.js ("disabled require"), test/nodevm.js ("enabled require for certain modules"), test/nodevm.js ("disable setters on builtin modules")

### Description

NodeVM's `require.builtin` allowlist defends sandbox code from reaching dangerous Node modules (`child_process`, `fs`, etc.). The allowlist is enforced by `lib/builtin.js` — when sandbox code calls `require(name)`, the resolver consults the allowlist and only loads modules the user opted in to. **However**, several Node builtins themselves expose primitives whose primary capability is "reach host code regardless of the sandbox boundary". When such a builtin is on the allowlist (or, more commonly, included by the `'*'` wildcard), it becomes a single-line allowlist bypass:

- `module` exposes `Module._load(name)`, `Module._resolveFilename`, `Module._cache`, `createRequire` — all of which load any host builtin or external module ignoring vm2's allowlist.
- `worker_threads` exposes `new Worker(src, {eval: true})` — runs arbitrary JS in a fresh thread that has no vm2 sandbox at all.
- `cluster` exposes `cluster.fork()` — spawns a host child process running attacker-controlled code.
- `vm` exposes `vm.runInThisContext` — evaluates code directly in the host realm, bypassing every bridge proxy.
- `repl` exposes `repl.start({eval, input, output})` — constructs an interactive evaluator attached to host streams.
- `inspector` (and `inspector/promises`, subpath family) exposes the inspector protocol — attaches a debugger to the host process and runs `Session().post('Runtime.evaluate', { expression })` against host JS.
- `process` exposes `process.getBuiltinModule(name)` (Node 22+) — reloads ANY core module regardless of the embedder's allow/deny list — plus `process.binding(...)`, `process.dlopen(...)`, `process._linkedBinding(...)`, and the raw host `process.env`. The sandbox global `process` is a sanitized shim defined in `setup-node-sandbox.js`; the raw host module is never safe to expose.
- `test` (and `test/reporters`, subpath family) exposes `test.run({ files, execArgv })` — the test runner's process-isolated mode spawns a SEPARATE host Node process and forwards `execArgv` to it verbatim, so `execArgv: ['--eval=<js>']` executes attacker JavaScript in an unsandboxed host process. Same class as `cluster.fork()`. It is easy to misread `test` as inert tooling, but its documented API is a host-process launcher with caller-controlled command-line flags.

### Attack Flow

1. **Allowlist includes a host-passthrough builtin** (most commonly because the user wrote `builtin: ['*', '-child_process']` and `'*'` expanded to include `'module'`).
2. **Sandbox calls `require('module')`**. NodeVM's resolver finds `'module'` in `BUILTIN_MODULES`, calls `addDefaultBuiltin` which loads it via `vm.readonly(hostRequire('module'))`. The `ReadOnlyHandler` proxy blocks mutation traps but *not* `apply`/`get` — calling methods on the proxy still forwards them to the host realm.
3. **Sandbox calls `Module._load('child_process')`**. The bridge `apply` trap forwards to host `Module._load`, which loads `child_process` natively in the host with no vm2 check.
4. **`child_process.execSync(...)`** → host RCE.

### Canonical Examples

```javascript
// (advisory GHSA-947f-4v7f-x2v8) — `module` bypass
const vm = new NodeVM({
  require: { builtin: ['*', '-child_process'], external: false }
});
vm.run(`
  const Module = require('module');
  const cp = Module._load('child_process');  // bypasses '-child_process' exclusion
  module.exports = cp.execSync('id').toString();
`, 'poc.js');
```

```javascript
// (advisory GHSA-rp36-8xq3-r6c4) — `process.getBuiltinModule` bypass
const vm = new NodeVM({
  require: { builtin: ['*', '-child_process', '-inspector'], external: false }
});
vm.run(`
  const cp = require('process').getBuiltinModule('child_process');
  module.exports = cp.execFileSync('/bin/sh', ['-c', 'id']).toString();
`, 'poc.js');
```

```javascript
// (advisory GHSA-rp36-8xq3-r6c4) — `inspector/promises` subpath bypass
const vm = new NodeVM({
  require: { builtin: ['*', '-child_process', '-inspector'], external: false }
});
vm.run(`
  const { Session } = require('inspector/promises');
  const s = new Session();
  s.connect();
  s.post('Runtime.evaluate', { expression: '/* runs in host realm */' });
`, 'poc.js');
```

```javascript
// (advisory GHSA-8686-vhfx-7r3j) — `node:`-spelled deny token is a no-op
const vm = new NodeVM({
  require: { builtin: ['*', '-node:child_process'] }
});
vm.run(`
  // Neither spelling was denied: the deny token never matched anything.
  const cp = require('child_process');        // also: require('node:child_process')
  module.exports = cp.execSync('id').toString();
`, 'poc.js');
```

```javascript
// (advisory GHSA-6rh5-qq4q-97xh) — deny token misses the subpath sibling
const vm = new NodeVM({
  require: { builtin: ['*', '-fs', '-child_process'] }
});
vm.run(`
  require('fs');                              // denied, as configured
  const fsp = require('fs/promises');         // NOT denied — a separate builtin
  module.exports = fsp.writeFile('/tmp/pwned', 'host write');
`, 'poc.js');
```

```javascript
// (advisory GHSA-qhwx-74w5-xhxq) — `node:test` spawns a host process for you
const vm = new NodeVM({
  require: { builtin: ['node:test'], external: false }
});
vm.run(`
  // fs / child_process / module / process are all denied in this config.
  const test = require('node:test');          // also reachable as 'node:node:test'
  // run() forwards execArgv to a freshly spawned, unsandboxed host Node process.
  test.run({ files: ['noop.js'], execArgv: ['--eval=require("fs").writeFileSync("/tmp/pwned","host rce")'] });
`, 'poc.js');
```

### Why It Works

The user's mental model of `['*', '-child_process']` is "every builtin except `child_process`". That model assumes every builtin is either fully sandboxed or fully blocked — but `module` (and its peers above) are neither. They're *meta-builtins* that load other builtins by name. The generic `vm.readonly()` wrapper cannot make them safe because the sandbox-bypass primitive is the very thing the user is calling.

A second, quieter failure of the same mental model is **spelling**. `require()` accepts a builtin under two names — `child_process` and `node:child_process` — and the resolver normalizes the `node:` prefix away before loading. The `'*'` wildcard expansion did not: it matched negative deny tokens against `BUILTIN_MODULES` by exact string, and `BUILTIN_MODULES` holds only canonical names. So `-node:child_process` matched nothing, denied nothing, and produced no warning — the embedder read their config as a denial while the sandbox got the full host module. A deny token that silently does nothing is worse than one that errors: the misconfiguration is invisible in review.

A third failure of the same mental model is **granularity**. `fs` and `fs/promises` are two independent entries in `nmod.builtinModules`, not one module with a submodule — and they expose the same host filesystem authority. Because the deny check compared against the full canonical name, `-fs` removed exactly the entry spelled `fs` and left `fs/promises` — with `writeFile`, `rm`, `rename`, `cp` — registered under the `'*'` expansion. Every subpath family had the same gap: `-path` left `path/posix` and `path/win32`, `-stream` left `stream/promises` / `stream/web` / `stream/consumers`, `-timers` left `timers/promises`, `-dns` left `dns/promises`. The embedder denies a capability; Node's module list hands the sandbox a second door to the same capability under a longer name. Note that `isDangerousBuiltin` had already learned this lesson for the *hard* denylist in [Category 21's rp36 fix](nodevm-require.md#attack-category-21-nodevm-builtin-allowlist-bypass-via-host-passthrough-builtins) (family-prefix matching for `inspector/promises`) — the user-supplied deny tokens simply never inherited it.

### Mitigation

Three-layer denylist enforcement in `lib/builtin.js` (restores **[Invariant 13 — The NodeVM builtin allowlist is a closed system](../ATTACKS.md#defense-invariants)**):

1. **`DANGEROUS_BUILTINS` Set** at module load — `['module', 'worker_threads', 'cluster', 'vm', 'repl', 'inspector', 'process', 'trace_events', 'wasi', 'diagnostics_channel', 'async_hooks', 'perf_hooks', 'v8', 'os', 'dns']`. The last six were added by [Category 35](nodevm-require.md#attack-category-35-nodevm-process-wide-observability-builtins-host-data-info-leak) for the process-wide observability info-leak class (`os` and `dns` via GHSA-m5w8-4gq2-6f8x, which additionally close the host-process *write* APIs `os.setPriority` / `dns.setServers` / `dns.setDefaultResultOrder`); they share the deny-by-default enforcement but a different threat model (data exposure / host-state mutation, not code execution).
2. **Family-prefix check** via `isDangerousBuiltin(key)` — any `<family>/...` whose family is in the denylist is also blocked (e.g. `inspector/promises`, future `inspector/foo`, hypothetical `process/foo`, `module/foo`). The check also strips the optional `node:` URL-style prefix so `node:process` and `node:inspector/promises` are caught.
3. **Filter from `BUILTIN_MODULES`** — closes the `'*'` wildcard expansion path. `'*'` will never auto-allow these names regardless of the user's exclusion list.
4. **Reject in `addDefaultBuiltin`** — closes the explicit-allowlist path (`builtin: ['module']`, `builtin: ['process']`, `builtin: ['inspector/promises']`) and the lower-level `makeBuiltins([...])` API used by custom resolvers. The `SPECIAL_MODULES` escape hatch is preserved: a future safe wrapper (e.g. a `module` shim that exposes only `builtinModules` metadata) can be registered there if a real consumer needs it.

5. **Deny-token `node:` normalization** (GHSA-8686-vhfx-7r3j) — the `'*'` wildcard's negative-token check in `makeBuiltinsFromLegacyOptions` now tests both `-${name}` and `-node:${name}`, so the two spellings of a deny token are equivalent and either one denies both spellings of the module. This is the deny-side mirror of the `node:`-prefix stripping the resolver and `isDangerousBuiltin` already do on the require side. It only ever *removes* a builtin the exact-match check itself admits, so no module that check already allows becomes unreachable.

6. **Deny-token family coverage** (GHSA-6rh5-qq4q-97xh) — the same negative-token check now treats `<family>/<sub>` as denied whenever `-<family>` is present, so `-fs` denies `fs/promises`, `-path` denies `path/posix` / `path/win32`, `-stream` denies `stream/promises` / `stream/web` / `stream/consumers`. This is the user-deny-token mirror of the family-prefix matching `isDangerousBuiltin` already applies to the hard `DANGEROUS_BUILTINS` denylist. Points 5 and 6 are composed in a single chokepoint, `isBuiltinDenied(builtins, name)`, which normalizes the `node:` prefix off *both* the module name and the token before matching and then applies the family split to the normalized name — so `-node:fs` denies all four of `fs`, `node:fs`, `fs/promises`, `node:fs/promises`. Coverage is strictly additive: a family with no deny token keeps every subpath, and the explicit (non-wildcard) allowlist branch is untouched, so `builtin: ['fs']` behaves exactly as before.

7. **`test` family denied** (GHSA-qhwx-74w5-xhxq) — `test` joins `DANGEROUS_BUILTINS`, which is the whole fix: no new code path is needed. Because `BUILTIN_MODULES` is built by filtering `nmod.builtinModules` through `isDangerousBuiltin`, the family disappears from the source list, so it is absent from `'*'` expansion *and* from the explicit-allowlist branch — `builtin: ['node:test']` now names a module that is not in the list, exactly as `builtin: ['cluster']` already behaved. (`child_process` is deliberately *not* on this denylist and remains grantable by explicit request; `test` is denylisted because, unlike `child_process`, no embedder reaches for it expecting process-spawning authority.) `addDefaultBuiltin` refuses it a second time for the low-level registration path. Subpath coverage (`test/reporters`) falls out of the existing family-prefix match added for `inspector/promises`; no special case was required. `isDangerousBuiltin` additionally strips *repeated* `node:` prefixes, so the doubled spelling `node:node:test` — which the resolver normalizes down to a single prefix before lookup — cannot survive as an unnormalized denylist miss. Note this is `isDangerousBuiltin` (the hard, non-configurable denylist), which is a separate chokepoint from `isBuiltinDenied` (points 5 and 6, user-supplied deny tokens); the two do not interact.

The fix does not affect the `mocks` / `overrides` escape hatches — users who genuinely need a stub for one of these names can register a sandbox-safe replacement.

`trace_events` and `wasi` were added during pre-tag red-team:

- **`trace_events.createTracing({categories: [...]})`** asserts `args[0]->IsArray()` in V8 C++. The array crosses the bridge as a Proxy, the `IsArray()` check fails, and the entire host process aborts. Reachable as ~150 bytes from sandbox under `builtin: ['*']` — not RCE, but a host-process-DoS primitive of the same severity class as Category 22.
- **`wasi`** exposes the WebAssembly System Interface preview1 syscall surface (filesystem `preopens`, host clock/random, network if preopened). The API is experimental and broad; even a misconfigured `preopens: {}` exposes the host CWD when sandbox code constructs a WASI module.

**Supersedes**: the previous GHSA-947f-4v7f-x2v8 mitigation, which used an exact-match denylist and missed `process` and subpath builtins such as `inspector/promises`. The family-prefix check subsumes the prior fix and forecloses every same-shape variant.

### Detection Rules

- **`builtin: ['*']` or `['*', '-X']`** in NodeVM config — on an unpatched version this expands to include `module`/`worker_threads`/`cluster`/`vm`/`repl`/`inspector`/`trace_events`/`wasi`; the shipped filter removes them. **Note: `'*'` still allows `child_process`, `fs`, `dgram`, `net`, `http`, `dns`, etc. — it is NOT a sandbox-safe default for untrusted code.**
- **`require('module')._load(...)`** — the canonical bypass primitive.
- **`new Worker(src, {eval:true})`** — out-of-band code execution.
- **`cluster.fork()`** — host process spawn.
- **`vm.runInThisContext(...)`** — host-realm `eval`.
- **`repl.start({eval, ...})`** — host-realm REPL evaluator.
- **`inspector.open()`** or **`new (require('inspector/promises').Session)()`** — debugger attachment / `Runtime.evaluate` host-realm code execution.
- **`require('process').getBuiltinModule(name)`** — reloads any core module bypassing the allow/deny list.
- **`require('process').binding('spawn_sync')` / `.dlopen(module, path)`** — raw C++ binding surface and native add-on loader.
- **`trace_events.createTracing({categories: [...]})`** — host process abort via C++ assertion failure.
- **`new (require('wasi').WASI)({...})`** — preview1 syscall surface.
- **`builtin: ['*', '-node:X']`** — a `node:`-prefixed deny token. On an unpatched version it is a silent no-op that denies nothing; here it is equivalent to `-X`. A config written this way against an unpatched version does not enforce what it appears to.
- **`require('test')` / `require('node:test')` / `require('node:node:test')` / `require('node:test/reporters')`** — the test runner is a host-process launcher, not inert tooling. Denied outright since GHSA-qhwx-74w5-xhxq.
- **`test.run({ execArgv: [...] })`, or any `execArgv` / `--eval` / `--require` / `--import` string reaching a builtin's process-spawning option bag** — caller-controlled Node command-line flags on a spawned host process are equivalent to host RCE.
- **`require('<family>/<sub>')` where the config denies `-<family>`** — `fs/promises`, `path/posix`, `stream/web`, `timers/promises`, `dns/promises`. Reachable despite the family deny token on an unpatched version; here denied with the family. A config relying on `-fs` for filesystem isolation on an unpatched version does not enforce it.

### Considered Attack Surfaces

- **`async_hooks`, `diagnostics_channel`, `perf_hooks`, `v8`** are now denied as process-wide observability primitives — see [Category 35](nodevm-require.md#attack-category-35-nodevm-process-wide-observability-builtins-host-data-info-leak). They expose host-process state rather than host-code-loading primitives, but are functionally identical from the embedder's perspective: any allowlist that includes them leaks per-request user data, auth tokens, and heap contents into the sandbox.
- **`child_process`** is NOT on the auto-denylist because users may legitimately want it for trusted scripts (e.g., dev tooling running known scripts in vm2 for hot-reload isolation). For untrusted code, `child_process` is a full-host-RCE primitive — embedders MUST exclude it explicitly (`['*', '-child_process']`, or equivalently `['*', '-node:child_process']` since GHSA-8686-vhfx-7r3j) or, better, use an explicit allowlist of just the modules they need. The README's "Hardening recommendations" section calls this out.
- **`fs`** is allowed under `'*'` because file-system access can be a legitimate sandbox capability for many use cases (e.g., user-script template engines reading templates). Users who want filesystem isolation use `VMFileSystem` or exclude `fs` explicitly. Since GHSA-6rh5-qq4q-97xh a `-fs` token also covers `fs/promises`; on earlier versions it did not, and `fs/promises` alone is a complete host filesystem read/write primitive. Same caveat as `child_process` — `'*'` is not sandbox-safe for untrusted code.
- **`dgram`, `net`, `http`, `https`, `dns`** are network-IO builtins, allowed under `'*'`. Any of them give untrusted code outbound network access from the host. Embedders should explicitly exclude or allowlist.

---

## Attack Category 24: NodeVM `require.root` Symlink Bypass (Path Check/Use TOCTOU)

**Advisories**: GHSA-cp6g-6699-wx9c

**Tests**: test/ghsa/GHSA-cp6g-6699-wx9c/, test/nodevm.js ("root path checking"), test/nodevm.js ("relative require not allowed to enter node modules")

### Description

`NodeVM`'s `require.root` option restricts sandbox `require()` to a configured filesystem root. The intended invariant is "no code runs from outside the allowed root". The check was implemented as a **lexical** prefix match — `isPathAllowed(filename)` in `lib/resolver-compat.js` verified `filename.startsWith(rootPath)` where `filename` came from `path.resolve()` (no symlink dereference). However, the actual loader is Node's native `require()`, which **does** follow symlinks. A symlink inside the allowed root pointing outside it passes the lexical prefix check, yet the loader follows it and runs code from the symlink's target. CWE-59 (Improper Link Resolution Before File Access).

This is especially severe because:
- pnpm uses symlinks for *every* `node_modules` entry (canonical `<root>/node_modules/<pkg> → <pnpm-store>/<pkg>` layout).
- npm workspaces and `npm link` create equivalent symlinks.
- With `context: 'host'`, the host loader runs the symlinked code with full host privileges — direct RCE.

### Attack Flow

1. **Symlink exists inside the allowed root** pointing outside it. This may be created by an attacker or pre-existing as a side-effect of pnpm/npm-workspaces/`npm link`.
2. **Sandbox calls `require('./link.js')`** (or `require('safe')` for a directory-level symlink).
3. **Resolver runs `path.resolve(...)`** producing a path that starts with `rootPath` and passes `isPathAllowed`.
4. **Loader runs `hostRequire(filename)`** which follows the symlink to outside-root code.
5. **In `context: 'host'`** the loaded module executes with host privileges → RCE.

### Canonical Example

```javascript
// (advisory GHSA-cp6g-6699-wx9c) — file-level symlink
const root = '/tmp/root';
fs.symlinkSync('/tmp/outside.js', '/tmp/root/link.js');
const vm = new NodeVM({ require: { external: true, root, context: 'host' } });
vm.run("require('./link.js')");
// /tmp/outside.js runs in HOST context.

// directory-level symlink variant (e.g. pnpm / npm-workspaces / `npm link`)
fs.symlinkSync(__dirname + '/vm2', '/tmp/root/node_modules/safe');
vm.run("require('safe')");
// vm2 itself runs in HOST context, then attacker uses it to escalate.
```

### Why It Works

The bridge proxy and the bridge's overall threat model are not involved here — this is a filesystem access-control check that runs purely on the host side, and the gap is between two host-side syscalls: `path.resolve()` (lexical) and the kernel's `stat`/`open` chain that follows symlinks. The check and the use operate on different canonical representations of the same path. Classic check/use TOCTOU.

### Mitigation

`fs.realpathSync` is used to canonicalize paths before the prefix check, so the boundary check operates on the same path the loader will follow. Enforces [Defense Invariant](../ATTACKS.md#defense-invariants) #1 at the filesystem-resolver layer: the resolver and the loader must operate on the same canonical path namespace.

1. **`DefaultFileSystem.realpath()` and `VMFileSystem.realpath()`** (in `lib/filesystem.js`) — new methods on the filesystem abstraction. The default delegates to host `fs.realpathSync`; `VMFileSystem` delegates to the user-supplied `fs.realpathSync`.
2. **`isPathAllowed` realpaths the candidate** (in `lib/resolver-compat.js`) before the prefix-vs-rootPaths check. If `realpath` throws (file doesn't exist, broken link) the check **denies by default**.
3. **`rootPaths` are canonicalized at construction time** so a symlinked root configuration (`root: '/tmp/myroot'` where `/tmp/myroot` is itself a symlink) compares the same canonical namespace as the candidate filenames.
4. **Eager FileSystem-contract probe at NodeVM construction** (in `lib/resolver-compat.js`, `makeResolverFromLegacyOptions`). If `require.root` is set, the resolver verifies that the FileSystem adapter implements `realpath()` and that calling it does not throw a `TypeError` (the signal that `VMFileSystem`'s underlying `fs.realpathSync` is missing). On contract violation it throws `VMError` immediately at `new NodeVM(...)` time citing GHSA-cp6g-6699-wx9c, instead of silently denying every later `require()`. Other `realpath` errors at construction (`ENOENT`, `EACCES`) are tolerated — the root may legitimately not exist yet, and runtime `isPathAllowed` will still realpath candidates and deny-by-default.

The race window between the canonicalization syscall and the subsequent loader syscalls is narrow but not eliminated; full mitigation would require atomic `openat`/`O_NOFOLLOW` APIs Node does not expose to user code. CWE-367 residual risk is documented but considered acceptable.

### Detection Rules

- **Symlink inside `require.root`** pointing outside (file-level or directory-level).
- **`fs.realpathSync` on the candidate ≠ `path.resolve` on the candidate** — the smoking gun for this class.
- **pnpm / npm-workspaces / `npm link` layouts** with NodeVM `require.root` configured.

### Considered Attack Surfaces

- **Custom `fs` adapters without `realpath`/`realpathSync`**: existing `VMFileSystem({ fs: customFs })` users whose `customFs` lacks `realpathSync`, and fully custom `FileSystem` adapters that omit `realpath()`, are surfaced at construction time by the eager probe (Mitigation #4). The probe converts what would otherwise be a silent deny-by-default at every later `require()` into a single, clearly-labelled `VMError` at `new NodeVM(...)` — strict security with an actionable error message.
- **Race between resolver-side realpath and loader-side `require`**: theoretically exploitable on a fast filesystem with attacker-controlled symlinks; not closed structurally because Node does not expose `openat`/`O_NOFOLLOW` to user code. Documented residual risk.
- **`mocks` / `overrides`** are unaffected — they don't go through the path resolver.

---

## Attack Category 25: NodeVM `nesting` Configuration Trap (NESTING_OVERRIDE-only resolver)

**Advisories**: GHSA-8hg8-63c5-gwmx, GHSA-m4wx-m65x-ghrr, GHSA-8hr7-r645-pc6w

**Tests**: test/ghsa/GHSA-8hg8-63c5-gwmx/, test/ghsa/GHSA-m4wx-m65x-ghrr/, test/ghsa/GHSA-8hr7-r645-pc6w/ (repro.js + adversarial.js), test/nodevm.js ("NodeVM")

**Supersedes**: GHSA-8hg8-63c5-gwmx's check on the raw `options.require === false` input, which only fired for one syntactic shape and missed every other configuration that collapses to the same insecure resolver — see GHSA-m4wx-m65x-ghrr.

### Description

`NodeVM`'s `nesting` option (when truthy) injects a `NESTING_OVERRIDE` builtin that exposes the `vm2` package to sandbox code regardless of any other `require` configuration. The override is unconditional — it survives `require: false`, narrow `builtin` allowlists, and every other restriction the user might set. With `vm2` reachable, the sandbox constructs an inner `NodeVM` whose `require` config is **chosen by the sandbox code, not constrained by the outer config** (this is by design of `nesting`). The inner NodeVM can be configured with `child_process`, `fs`, or any other host module → full host RCE.

The trap is **any** `NodeVM` configuration where a truthy `nesting` is combined with a `require` that isn't a real require-config object. Four input-shape classes all collapse to the same NESTING_OVERRIDE-only resolver:

- **Falsy / omitted `require`** — `{ nesting: true }`, `{ nesting: true, require: false / undefined / null / 0 / '' }`. `makeResolverFromLegacyOptions(falsy, NESTING_OVERRIDE, …)` hits its `if (!options)` branch.
- **Truthy non-object `require`** — `{ nesting: true, require: true / 1 / 'yes' / Symbol() / function(){} }`. `makeResolverFromLegacyOptions` destructures every primitive/function value to all-`undefined`, then calls `makeBuiltinsFromLegacyOptions(undefined, …, NESTING_OVERRIDE)` — the same call shape the `if (!options)` branch produces.
- **Truthy non-`true` `nesting`** — `{ nesting: 1 / 'yes' / {} / [] / function(){}, require: false }`. The override gate inside the constructor is `nesting && NESTING_OVERRIDE`, which fires for ANY truthy value.
- **`typeof`-object non-config `require`** (GHSA-8hr7-r645-pc6w) — `{ nesting: true, require: [] / new Array() / new Date() / /re/ / new Map() / new Set() / new Uint8Array() / new String() }`. An array or exotic/boxed object is `typeof === 'object'` and non-null, so it passed the GHSA-m4wx guard (`typeof requireOpts === 'object' && requireOpts !== null`), yet carries **no** require-config fields and destructures to all-`undefined` — the same insecure NESTING_OVERRIDE-only resolver. This is a fourth-shape bypass of the m4wx patch, distinct because m4wx's guard *did* reject the primitives/functions of the second class but treated every `typeof`-object as a "real config".

All shapes produce a resolver whose only builtin is `vm2` — a pure escape primitive with no legitimate use. The original GHSA-8hg8 patch tested only the literal `{ nesting: true, require: false }` shape with strict equality on the raw input; GHSA-m4wx generalized the guard to "truthy `nesting` needs a `typeof`-object `require`" but that predicate is itself too loose (arrays/exotics are `typeof`-object).

CWE-284 (Improper Access Control). CWE-697 (Incorrect Comparison) for the original GHSA-8hg8 check, which compared too narrowly against the set of values that reach the insecure resolver.

### Attack Flow

1. **Host configures `nesting: true`** *without* providing an explicit `require` config object — e.g. `new NodeVM({ nesting: true })`. The developer assumes the absence of `require` means "no host modules" (matching the rest of the API's default-deny stance).
2. **Sandbox code requires `vm2`**: succeeds because `NESTING_OVERRIDE` injected `vm2` into the builtin map even though the surrounding `require` config is empty/denied.
3. **Sandbox constructs inner NodeVM** with attacker-chosen `require` config: `new NVM({ require: { builtin: ['child_process'] } })`.
4. **Inner sandbox loads `child_process`** and runs arbitrary commands as the host process user.

### Canonical Example

```javascript
// GHSA-m4wx-m65x-ghrr PoC — patches the literal-PoC fix of GHSA-8hg8-63c5-gwmx.
const vm = new NodeVM({ nesting: true }); // `require` omitted; defaults to false post-destructure
vm.run(`
  const { NodeVM: NVM } = require('vm2');
  const inner = new NVM({ require: { builtin: ['child_process'] } });
  module.exports = inner.run(
    'module.exports = require("child_process").execSync("id").toString()'
  );
`);
// uid=1000(...) ...
```

- Every array/boxed/exotic `require` shape rejected at construction, and the `require: {}` escape hatch still granting host `vm2` only: see test/ghsa/GHSA-8hr7-r645-pc6w/adversarial.js.

### Why It Works

The bug lives in `lib/resolver-compat.js` `makeResolverFromLegacyOptions`:

```javascript
function makeResolverFromLegacyOptions(options, override, compiler) {
    if (!options) {
        if (!override) return DENY_RESOLVER;     // require:false alone → deny all
        // require:falsy + nesting:true → permissive resolver with vm2 loadable:
        const builtins = makeBuiltinsFromLegacyOptions(undefined, defaultRequire, undefined, override);
        return new Resolver(DEFAULT_FS, [], builtins);
    }
    ...
}
```

The GHSA-8hg8 patch tried to reject this configuration at the `NodeVM` constructor, but used `options.require === false` — strict equality against the raw input. The destructuring default (`require: requireOpts = false`) runs *after* the check, so omitting `require`, passing `undefined`, or any other path that doesn't write the literal `false` into `options.require` slipped past the guard and still produced `requireOpts = false`. The GHSA-m4wx bypass is purely the gap between "check the raw input shape" and "check the value actually used to build the resolver."

The "mental-model mismatch" framing applies at two levels: the *configuration* trap (developers think `nesting: true` is orthogonal to `require`) and the *check* trap (the original patch checked the user-facing option name instead of the destructured value).

### Mitigation

`NodeVM` constructor (`lib/nodevm.js`) destructures options first, then throws `VMError` when *any truthy `nesting`* is paired with a `requireOpts` that isn't a real require-config object (or a `Resolver` instance). The check lives on the value that actually drives `makeResolverFromLegacyOptions`, so every shape that collapses to the NESTING_OVERRIDE-only resolver collapses to the same rejection:

The predicate is a shared `isPlainConfigObject` (`lib/resolver-compat.js`), and it is enforced at **two coordinated layers** (GHSA-8hr7-r645-pc6w):

```javascript
// lib/resolver-compat.js — the shared "genuine require config" test.
function isPlainConfigObject(value) {
    if (value === null || typeof value !== 'object') return false;
    if (arrayIsArray(value)) return false;                       // arrays (also Proxy-around-array, via Array.isArray)
    const proto = objectGetPrototypeOf(value);
    return proto === objectPrototype || proto === null;          // plain {} or Object.create(null) only
}

// Layer 1 — lib/nodevm.js constructor guard (fails loudly with a good error):
const hasRealRequireConfig = requireOpts instanceof Resolver || isPlainConfigObject(requireOpts);
if (nesting && !hasRealRequireConfig) { throw new VMError('NodeVM `nesting` requires an explicit `require` config object. …'); }

// Layer 2 — lib/resolver-compat.js makeResolverFromLegacyOptions (fail-closed, any caller):
if (override && options && !isPlainConfigObject(options)) override = undefined;   // never inject NESTING_OVERRIDE for a non-config shape
```

The guard mirrors the actual reachability of the insecure resolver on two axes:

- **`nesting` checked as truthy**, matching the `nesting && NESTING_OVERRIDE` gate that decides whether `vm2` is exposed. Covers `nesting: true / 1 / 'yes' / {} / [] / function(){}` uniformly.
- **`requireOpts` must be a `Resolver` or a *plain* config object** — prototype `Object.prototype` or `null`, and not an array. This rejects primitives, functions (`typeof !== 'object'`), arrays (`Array.isArray`), and exotic/boxed instances (`Date`/`RegExp`/`Map`/`Uint8Array`/`new String()` — their prototype is not `Object.prototype`), all of which destructure to all-`undefined`. The GHSA-m4wx `typeof === 'object'` test admitted the last two groups; `isPlainConfigObject` closes them.

**Layer 2 is defense in depth:** even if an alternate caller reaches `makeResolverFromLegacyOptions` with a non-config `options` and an override (bypassing the constructor guard), the override is stripped, so `NESTING_OVERRIDE` (host `vm2`) is never injected for a non-plain shape. It is gated on `override`, so `{ nesting: false, require: [] }` (no override) is unaffected.

This establishes **Defense Invariant: `NESTING_OVERRIDE` (host `vm2` exposure) is injected only for a genuine require config — a `Resolver` or a plain config object — and every other shape fails loudly at construction.** The escape hatch (any truthy `nesting` + an explicit plain `require` config object, even `{}` or `Object.create(null)`) continues to work — the developer's "I accept the trade-off" signal is visible in the call site. A deliberately-constructed embedder Proxy that spoofs `getPrototypeOf` to `Object.prototype` while wrapping a `Date`/`Map` passes the predicate but grants nothing beyond the `{}`-profile (host `vm2` only, no `fs`/`child_process`) — it is `requireOpts` (embedder-supplied), never attacker-controlled, so this is an embedder footgun equivalent to writing `require: {}`, not an escalation.

### Detection Rules

- **`new NodeVM({ nesting: <truthy>, ... })`** with `require` set to anything other than a plain config object (or `Resolver`) — flagged at construction with `VMError` mentioning GHSA-m4wx-m65x-ghrr. Covers `require: false / undefined / null / 0 / '' / true / 1 / 'yes' / Symbol() / function(){}` (primitives/functions) **and** `require: [] / new Array() / new Date() / /re/ / new Map() / new Set() / new Uint8Array() / new String()` (arrays and exotic/boxed objects — the GHSA-8hr7-r645-pc6w shape class), and `nesting` values `true / 1 / 'yes' / {} / [] / function(){}`.
- **`new NodeVM({ nesting: true })`** with no `require` field at all — closed by GHSA-m4wx-m65x-ghrr (was the loophole the original GHSA-8hg8 fix left open).
- **Sandbox code containing `require('vm2')`** — only reachable when `nesting` is truthy *and* an explicit `require` config object was supplied; almost always indicates an escape attempt unless the embedder explicitly built a VM-spawning host integration.

### Considered Attack Surfaces

- **`{ nesting: true, require: { builtin: ['something'] } }`** — does NOT throw. The developer has explicitly opted into the documented escape hatch. README and JSDoc loudly state that `nesting: true` is unsafe for untrusted code; this is a documentation-level mitigation. Constraint propagation from outer to inner NodeVM is out of scope.
- **`{ nesting: true, require: {} }`** — also does NOT throw. An empty object is a truthy explicit signal; `makeResolverFromLegacyOptions` falls into the "options-provided" branch and builds a resolver where the only builtin is still `vm2` (via override), but the developer's intent is visible at the call site.
- **Sandbox-side `require('vm2')` when `nesting: false`** — already throws `EDENIED` because the override is not installed. Unaffected.
- **`mocks` / `overrides`** — bypass the resolver entirely; unaffected by this fix and unaffected by `nesting: true` (mocks don't carry the `vm2` package).

---

## Attack Category 34: NodeVM Wildcard Exposes Undocumented Underscored Builtins — Network Capability Bypass

**Advisories**: GHSA-r9pm-gxmw-wv6p

**Tests**: test/ghsa/GHSA-r9pm-gxmw-wv6p/

### Description

NodeVM's `'*'` wildcard expansion (in `lib/builtin.js`) sources the list of allowed builtins from `require('module').builtinModules` filtered by `s => !s.startsWith('internal/') && !DANGEROUS_BUILTINS.has(s)`. The filter removes Node's `internal/*` modules and the host-passthrough denylist from Category 21, but it does **not** remove the parallel family of underscored builtins:

```
_http_agent     _http_common     _http_outgoing    _tls_common      _stream_readable
_http_client    _http_incoming   _http_server      _tls_wrap        _stream_writable
                                                                    _stream_duplex
                                                                    _stream_transform
                                                                    _stream_wrap
                                                                    _stream_passthrough
```

These are Node's private implementation modules backing `http`, `https`, `tls`, and the streams subsystem. They are listed in `builtinModules` (so the wildcard expands to them) but they are not documented public API and they expose the network primitives directly:

- `require('_http_client').ClientRequest(opts)` — outbound HTTP request, **bypasses `http`/`https` blocking**.
- `require('_http_server').Server(handler).listen(0)` — listening HTTP socket, **bypasses `net` blocking**.
- `require('_tls_wrap').TLSSocket` / `_tls_common` — TLS primitives, **bypass `tls` blocking**.

### Attack Flow

1. Embedder writes the documented "allow everything except network" pattern:
   ```javascript
   new NodeVM({require: {builtin: ['*', '-http', '-https', '-net', '-dgram', '-tls', '-dns', '-dns/promises', '-http2']}})
   ```
2. The `'*'` wildcard expands to `BUILTIN_MODULES`, which (pre-fix) includes every `_http_*` and `_tls_*` sibling because none of them match `internal/` or `DANGEROUS_BUILTINS`.
3. Sandbox code calls `require('_http_client')`. The allowlist contains it, `addDefaultBuiltin` wraps the host module in `vm.readonly()`, and the proxy is handed to the sandbox.
4. Sandbox calls `new (require('_http_client').ClientRequest)({host: '127.0.0.1', port: 80, ...})` — outbound HTTP request from the host. Equivalent attack via `_http_server` opens a listening socket.

### Canonical Example

```javascript
// (advisory GHSA-r9pm-gxmw-wv6p)
const vm = new NodeVM({
  require: {
    builtin: ['*', '-http', '-https', '-net', '-dgram', '-tls', '-dns', '-dns/promises', '-http2'],
    external: false
  }
});
vm.run(`
  const {ClientRequest} = require('_http_client');
  const req = new ClientRequest({host: '169.254.169.254', port: 80, path: '/latest/meta-data/'});
  req.on('response', r => r.on('data', d => module.exports = d.toString()));
  req.end();
`, 'poc.js');
```

The user's mental model — "I excluded `http` and `net`, the sandbox cannot make HTTP requests" — is silently violated.

### Why It Works

`require('module').builtinModules` is Node's flat list of every builtin name, including private implementation siblings. The `'-name'` exclusion mechanism in vm2 is purely string-equality based — `'-http'` does not cascade to `_http_client`, `_http_server`, etc. The mismatch between the wildcard source (full builtin list) and the embedder's mental model (documented public modules) is the bug. An exclusion-based config can never name all the siblings because Node may introduce new underscored builtins between releases.

This is **not** RCE — the underscored siblings load like any other vetted builtin and the bridge proxy applies normally. The impact is capability bypass: the sandbox regains the very capability the embedder explicitly attempted to remove. CVSS 8.6 reflects the SSRF-class blast radius (cloud metadata endpoints, internal admin panels, localhost-only services).

### Mitigation

Filter modules whose name starts with `_` from the `BUILTIN_MODULES` source in `lib/builtin.js`:

```javascript
const BUILTIN_MODULES = (nmod.builtinModules || Object.getOwnPropertyNames(process.binding('natives')))
  .filter(s => !s.startsWith('internal/') && !s.startsWith('_') && !isDangerousBuiltin(s));
```

After the fix, the `'*'` wildcard expands only to documented public Node builtins. The `'-name'` exclusion mechanism is again coherent — excluding `http`/`net`/`tls` removes every reachable network builtin under the wildcard. Both bare-name (`require('_http_client')`) and `node:`-prefixed (`require('node:_http_client')`) forms are blocked because the builtins map is the single source of truth (`loadBuiltinModule` returns `undefined` for absent keys, so the sandbox-side `requireImpl` throws `ENOTFOUND`).

**Escape hatches preserved.** The fix is intentionally narrow:

- **Explicit opt-in** still works at the lower-level API. A power user who genuinely needs `_http_client` registers it with `makeBuiltins(['_http_client'])` — `addDefaultBuiltin` does not consult the `s.startsWith('_')` filter. The legacy `require.builtin` option is *not* such a route: both its array branch and its object-map branch iterate `BUILTIN_MODULES` and admit only names present there, so `builtin: ['_http_client']` and `builtin: {_http_client: true}` name a module that is not in the list and resolve to `Cannot find module '_http_client'`.
- **`mock` / `override`** registrations under underscored names continue to function — they bypass `addDefaultBuiltin` entirely.

### Defense Invariant Enforced

> **The `'*'` wildcard expands only to documented public Node builtins. Undocumented underscored siblings of network and stream modules MUST NOT be reachable from sandbox code under the wildcard expansion. Explicit opt-in remains the user's choice.**

This complements [Category 21](nodevm-require.md#attack-category-21-nodevm-builtin-allowlist-bypass-via-host-passthrough-builtins)'s `DANGEROUS_BUILTINS` invariant (and the [Defense Invariant #13](../ATTACKS.md#defense-invariants) it restores). Category 21 is "host-passthrough primitives are unreachable under any config"; Category 34 is "wildcard expansion follows the user's mental model of public APIs only".

### Detection Rules

- **`require('_http_client')` / `require('_http_server')` / `require('_tls_wrap')`** from sandbox code — canonical bypass primitives.
- **`require('node:_http_client')`** (etc.) — `node:` prefix path, equivalent reachability.
- **Embedder config `builtin: ['*', '-http', ...]`** — on an unpatched version this leaves every `_http_*`/`_tls_*` sibling reachable; here they are filtered out of the expansion.

### Considered Attack Surfaces

- **`require('module').builtinModules` published as `Module.builtinModules` inside the sandbox** (`lib/setup-node-sandbox.js:140`) — this is a static metadata list, not a loader. Sandbox code seeing `_http_client` in the list does not gain the ability to load it; the resolver gates by `this.builtins.has(x)`.
- **Custom resolvers building their own builtins map via `makeBuiltinsFromLegacyOptions`** — same source list (`BUILTIN_MODULES`), same filter, same protection.
- **`hostRequire` registered by `mock` / `override`** — out of scope. The user is explicitly handing the sandbox a module; trust is the user's responsibility.
- **Underscored siblings introduced by future Node versions** — the `s.startsWith('_')` filter is name-based and forward-compatible. Any new `_foo_bar` builtin Node adds is automatically excluded from the wildcard without requiring a vm2 release.

### Supersedes

None. This fix complements [Category 21](nodevm-require.md#attack-category-21-nodevm-builtin-allowlist-bypass-via-host-passthrough-builtins) (`DANGEROUS_BUILTINS`) — together they enforce: "no host-passthrough primitive AND no undocumented underscored sibling is reachable under `builtin: ['*']`."

---

## Attack Category 35: NodeVM Process-Wide Observability Builtins (Host-Data Info Leak)

**Advisories**: GHSA-m5w8-4gq2-6f8x, GHSA-9g8x-92q2-p28f, GHSA-rp36-8xq3-r6c4

**Tests**: test/ghsa/GHSA-m5w8-4gq2-6f8x/, test/ghsa/GHSA-9g8x-92q2-p28f/, test/ghsa/GHSA-rp36-8xq3-r6c4/

### Description

NodeVM's `require.builtin` allowlist defends sandbox code from reaching dangerous Node modules. [Category 21](nodevm-require.md#attack-category-21-nodevm-builtin-allowlist-bypass-via-host-passthrough-builtins) denied the host-code-loading primitives (`module`, `worker_threads`, `cluster`, `vm`, `repl`, `inspector`, `process`, `trace_events`, `wasi`). A second class of dangerous builtins exists with a different threat model: **process-wide observability modules** whose primary capability is reading state of the entire host Node process, not loading or executing code.

When such a builtin is reachable from the sandbox (via the `'*'` wildcard or an explicit allowlist), the sandbox can subscribe to or read host process state directly — no RCE chain needed. The data the embedder routes through these APIs in the same process (HTTP requests, async-context user IDs, performance marks, V8 heap) is by definition host data; reaching the host module *is* the escape.

CWE-668 (Exposure of Resource to Wrong Sphere). Info-leak class, not RCE class.

**Extended by GHSA-m5w8-4gq2-6f8x (`os`, `dns`)** — the same class contains two more builtins whose state belongs to the host process and which additionally expose *process-wide write* APIs. These are strictly worse than the read-only four above: `os.setPriority()` renices the host process, and `dns.setServers()` / `dns.setDefaultResultOrder()` mutate the host's process-wide DNS resolution from one synchronous line of sandbox code. CWE-200 + CWE-732 + CWE-285.

### Attack Flow

Each builtin gives a one-liner exfiltration primitive. Once the sandbox holds a readonly proxy over the host module, the proxy's `apply` trap forwards every method call back to the host realm:

- **`diagnostics_channel`** — `dc.channel('http.server.request.start').subscribe(cb)`. The sandbox callback receives raw host `IncomingMessage` objects for every HTTP request the embedder serves, with full `Authorization`, `Cookie`, `x-session-token` headers intact.
- **`async_hooks`** — `async_hooks.executionAsyncResource()` returns the current host `AsyncResource`. Embedders that use `AsyncLocalStorage` for per-request user/auth context (extremely common pattern: `express`, `fastify`, `next.js`) pin that state on the resource, and the sandbox reads it directly.
- **`perf_hooks`** — `perf_hooks.performance.getEntriesByType('mark')` reads every host-side `performance.mark(name)`. Production code routinely embeds request IDs, user IDs, route paths, or partial query strings into mark names for observability dashboards.
- **`v8`** — `v8.getHeapSnapshot()` returns a Readable stream of the entire host V8 heap (every string, every Buffer, every closure capture). `v8.writeHeapSnapshot(path)` writes the same to an arbitrary host filesystem path. `v8.queryObjects(Ctor)` (Node 20+) returns every host-realm instance of a constructor.
- **`os`** (GHSA-m5w8-4gq2-6f8x) — reads: `os.userInfo()` returns the host process owner (uid/gid/username/homedir/shell); `os.networkInterfaces()` returns the host's full network topology (container/VM veth pairs, IPs, MACs); `os.hostname()` / `os.loadavg()` / `os.uptime()` / `os.freemem()` are host-wide telemetry. Write: `os.setPriority([pid,] prio)` invokes `setpriority(2)` on the host process (pid 0 = host), persisting after the sandbox call returns.
- **`dns`** (GHSA-m5w8-4gq2-6f8x) — the strongest primitive in the class: `dns.setServers(['attacker:53'])` replaces the host's process-wide DNS resolver list, so every subsequent lookup the host makes (its own outbound HTTP, telemetry, npm registry, `fetch`, URL-based fs paths) flows through the attacker's resolver — a one-line DNS hijack with no rate limit, audit trail, or embedder notification. `dns.setDefaultResultOrder()` is a second process-wide write knob; `dns.getServers()` / `dns.lookup()` / `dns.resolve()` read and act from the host network identity. The `dns/promises` subpath shares the surface and is covered by the same denial via the family-prefix matcher.

### Canonical Example

```javascript
// (advisory GHSA-9g8x-92q2-p28f)
const vm = new NodeVM({ require: { builtin: ['*'], external: false } });
vm.run(`
  const dc = require('diagnostics_channel');
  const stolen = [];
  dc.channel('http.server.request.start').subscribe((req) => {
    stolen.push({
      url: req.url,
      authorization: req.headers.authorization,
      session: req.headers['x-session-token'],
    });
  });
  // ... wait for host HTTP traffic. Headers are read from inside the sandbox.
`, 'poc.js');
```

Equivalent one-liners for the other three:

```javascript
require('async_hooks').executionAsyncResource(); // -> host AsyncResource
require('perf_hooks').performance.getEntriesByType('mark'); // -> host marks
require('v8').writeHeapSnapshot('/tmp/host-heap.json'); // -> entire host heap on disk
```

The `os` / `dns` extension (GHSA-m5w8-4gq2-6f8x) — note the two host-process *writes*:

```javascript
// (advisory GHSA-m5w8-4gq2-6f8x)
const vm = new NodeVM({ require: { builtin: ['*'], external: false } });
vm.run(`
  const os = require('os');
  os.userInfo();              // -> host uid/gid/username/homedir/shell
  os.networkInterfaces();     // -> host network topology (IPs, MACs)
  os.setPriority(10);         // WRITE: renices the host process

  require('dns').setServers(['127.0.0.1:5353']); // WRITE: hijacks every
  // subsequent host DNS lookup -- outbound HTTP, telemetry, registry fetch.
`, 'poc.js');
// Both writes are observed from the host realm after vm.run() returns.
```

### Why It Works

The vm2 boundary is built around the assumption that "the sandbox observes its own realm, not the host's". Most Node builtins satisfy this implicitly: `path.join(...)`, `crypto.randomBytes(...)`, `url.parse(...)` all operate on inputs the sandbox passes in and return values the sandbox owns. The bridge's `ReadOnlyHandler` makes those builtins safe via uniform proxy semantics.

Process-wide observability builtins break the assumption because the data they surface *is* host data by spec — `executionAsyncResource()` returns "the resource currently executing" measured against the host's call stack, not the sandbox's. Wrapping the module in a proxy does not localize the data source. The bridge cannot usefully sanitize the values because they're real host objects (IncomingMessage, AsyncResource), and stripping them to primitives would defeat the embedder's reason for ever exposing the module in the first place.

The builtins in scope all share this property: they observe a process resource (HTTP request hook, async context, perf timeline, V8 heap) or — for `os` / `dns` — read host-kernel/host-process state and, worse, *write* it. `os.setPriority()` and `dns.setServers()` are not observations at all; they mutate global host-process state, so even a perfect read-side proxy is irrelevant. Mitigation must therefore be "deny by default", not "proxy more carefully".

### Mitigation

Extend `DANGEROUS_BUILTINS` in `lib/builtin.js` with the observability names — the original four (`diagnostics_channel`, `async_hooks`, `perf_hooks`, `v8`) plus `os` and `dns` (GHSA-m5w8-4gq2-6f8x). Reuses the same enforcement established by Category 21 (now four-layer after the `isDangerousBuiltin` family-prefix promotion):

1. **Filtered out of `BUILTIN_MODULES`** — closes the `'*'` wildcard expansion path. `builtin: ['*']` and `builtin: ['*', '-fs']` no longer auto-allow these names.
2. **Rejected in `addDefaultBuiltin`** via `isDangerousBuiltin(key)` — closes the explicit-allowlist path (`builtin: ['perf_hooks']`), the object-map form (`builtin: { v8: true }`), and the lower-level `makeBuiltins(['async_hooks'])` API used by custom resolvers.
3. **Family-prefix check** — any `<family>/...` whose family is in the denylist is also blocked (e.g. hypothetical `perf_hooks/foo`).
4. **`node:` prefix stripped before lookup** — `require('node:diagnostics_channel')` resolves identically to the bare name and is blocked by the same denial.

The `SPECIAL_MODULES`, `mocks`, and `overrides` escape hatches are preserved: an embedder who genuinely needs sandbox-local timing or async context can register a controlled wrapper under the same name (e.g., a `perf_hooks` shim that only exposes a sandbox-local clock). The denylist only rejects the *default host-passthrough loader*.

`v8` was added during this fix beyond the originally-named three. The class is "process-wide observability modules"; `v8.writeHeapSnapshot(path)` is strictly worse than `perf_hooks` against the same invariant (writes a full heap dump to an arbitrary host filesystem path), so excluding it would leave a wide bypass of the same class.

`os` and `dns` (GHSA-m5w8-4gq2-6f8x) were the two remaining members of the class. They satisfy the same description (host-process state the `vm.readonly()` proxy cannot localise) and additionally expose *write* primitives — `dns.setServers()` is a one-line process-wide DNS hijack, strictly worse than every read-only leak the original fix closed. Adding the two family names automatically covers `node:os`, `node:dns`, and the `dns/promises` subpath via `isDangerousBuiltin`'s `node:`-strip and family-prefix matching, with no per-API enumeration needed for future Node releases. Embedders who genuinely need a sandbox-local subset (`os.platform()`, `os.EOL`, `os.constants`) register a controlled wrapper via `mock` / `override`, exactly as for the original four.

The fix restores **[Defense Invariant #13](../ATTACKS.md#defense-invariants)** at a different layer — the NodeVM builtin allowlist is a closed system, regardless of whether the threat is code execution or data exposure. The bridge invariant still holds for these modules; the deny-list ensures the bridge is never asked to wrap them in the first place.

### Detection Rules

- **`builtin: ['*']` or `builtin: ['*', '-X']`** in NodeVM config — on an unpatched version this auto-allows `diagnostics_channel`, `async_hooks`, `perf_hooks`, `v8`; here they are filtered. Same caveat as Category 21: `'*'` still allows `fs`, `child_process` (if not excluded), `net`, `http`, `dns` — not a sandbox-safe default for untrusted code.
- **`require('diagnostics_channel').channel(...).subscribe(...)`** — host HTTP/DB/IPC observability subscription.
- **`require('async_hooks').executionAsyncResource()` / `.createHook({...}).enable()`** — host async context inspection.
- **`require('perf_hooks').performance.getEntriesByType('mark' | 'measure' | 'resource')`** — host performance timeline read.
- **`require('v8').getHeapSnapshot()` / `.writeHeapSnapshot(path)`** — full host heap exfiltration to memory or disk.
- **`require('v8').queryObjects(Ctor)`** (Node 20+) — enumeration of host-realm instances of a constructor.
- **Sandbox code that subscribes to channels named `http.server.request.*`, `http.client.request.*`, `dns.lookup.*`, `net.client.socket.*`** — these are the canonical diagnostic channels used by Node core and request-tracking libraries.

### Considered Attack Surfaces

- **`os`** exposes hostname, network interfaces, user info. The data is host environment, not per-request, and is generally considered configuration metadata rather than tenant data. Allowed under `'*'` for consistency with `process.env` exposure expectations. Embedders who consider hostname/`userInfo()` sensitive should exclude `os` explicitly.
- **`dns`** can resolve internal hostnames and exfiltrate via DNS lookup. Network-IO class, same as `http`/`net`. Not in this denylist — embedders who care about network isolation must allowlist explicitly. Documented in Category 21's "Considered Attack Surfaces".
- **`zlib`, `crypto`, `string_decoder`, `buffer`** — sandbox-local data transforms, no host-state observability. Safe under default proxy semantics.
- **`process`** — already denied via Category 21 (after GHSA-rp36-8xq3-r6c4 extended `DANGEROUS_BUILTINS`). The sandbox global `process` is a curated stub defined in `lib/setup-node-sandbox.js`.
- **`worker_threads.parentPort` and `worker_threads.workerData`** — would expose host worker IPC channel and initial data. Already denied by Category 21 (entire `worker_threads` module is denied; this category is a different threat model on top, not a subset).
- **`http`, `https`, `http2`, `net`, `tls`, `dgram`** — network-IO modules. These do *not* observe existing host state; they originate new connections. Different threat model (outbound network from host) — covered in Category 21's "Considered Attack Surfaces" and Category 34 (underscored siblings). Embedders who want network isolation must exclude or replace them.

---

## Attack Category 40: Host-Authority Builtin Members Survive the Read-Only Wrap

**Advisories**: GHSA-46pr-c5wc-xffx, GHSA-6w8r-xxw2-g3hx, GHSA-98xx-8mx4-x7cm, GHSA-h85j-hv3c-qfgq, GHSA-x3v6-43hc-82mc

**Tests**: test/ghsa/GHSA-46pr-c5wc-xffx/, test/ghsa/GHSA-6w8r-xxw2-g3hx/, test/ghsa/GHSA-98xx-8mx4-x7cm/, test/ghsa/GHSA-h85j-hv3c-qfgq/, test/ghsa/GHSA-x3v6-43hc-82mc/

### Description

`NodeVM` exposes an allowed host builtin through `lib/builtin.js`'s default loader: `builtins.set(key, vm => vm.readonly(hostRequire(key)))`. `vm.readonly()` makes the module proxy reject property *assignment*, but it forwards every *method call* to the underlying host function with full host-process authority. Read-only is therefore the wrong containment for a builtin whose danger is not "sandbox writes a property" but "sandbox *calls* a member that reaches host-process authority." Five members of otherwise-legitimate builtins fall into this class, each usable from a NodeVM that allows only that one builtin (no `fs`, `process`, `child_process`, `module`, nesting, or `'*'` required):

- **`crypto.setEngine(path)`** (GHSA-46pr-c5wc-xffx) — hands `path` to OpenSSL's ENGINE loader; the OS dynamic loader runs the shared library's constructor as native code *before* OpenSSL validates the file, so a bundled native library executes even though the call ultimately reports `ERR_CRYPTO_ENGINE_UNKNOWN`. **Native RCE.**
- **`node:sqlite` `DatabaseSync(':memory:', {allowExtension: true}).loadExtension(path)`** (GHSA-6w8r-xxw2-g3hx) — SQLite loads the named library into the host process and invokes its native extension entry point. **Native RCE.** (Same report noted a resolver-normalization quirk: `require('node:node:sqlite')` resolves because the resolver treats any `node:`-prefixed string as core and the runtime strips only one prefix.)
- **`crypto.setFips(bool)`** (GHSA-x3v6-43hc-82mc) — flips the FIPS mode of the entire host process, so trusted host code that later calls `crypto.getFips()` observes the sandbox-chosen value (guest `setFips(1)` → host `getFips()` returns `1`). No native code, but a process-wide crypto-configuration mutation across the isolation boundary. **Process-wide config mutation.**
- **`tls.setDefaultCACertificates(hostArray)`** (GHSA-98xx-8mx4-x7cm) — replaces the host thread's default CA trust store, so subsequent host TLS clients accept attacker-signed certificates. The native type check requiring a *host* array is satisfied by `url`'s `URLSearchParams.getAll()`, which the bridge unwraps back to a host array. **Process-wide trust mutation.**
- **`https.globalAgent` / `http.globalAgent`** (GHSA-h85j-hv3c-qfgq) — the exposed module hands back the *real shared host singleton*. `globalAgent.on('free', (socket, options) => …)` receives live host request options (Authorization tokens, private host/port) and the released `TLSSocket` whenever an unrelated host request completes. **Host credential / traffic exfiltration.**

### Why It Works

`vm.readonly()` was designed to expose data-shaped host objects (constants, config) that the sandbox should read but not mutate. It has no notion of "this callable, when invoked, performs a host-privileged side effect." For the members above the dangerous operation is a *call*, not a *write*, so the read-only proxy forwards it verbatim. `https.globalAgent` is worse still: it is not even a call — the sandbox merely reads a process-global `EventEmitter` singleton and subscribes to it, and the read-only proxy faithfully returns the host object.

### Mitigation

`lib/builtin.js` sanitizes the host module *before* the read-only wrap (`sanitizeBuiltinMembers(key, hostRequire(key))`), via a small per-module table (`BUILTIN_MEMBER_SANITIZERS`). The `node:` prefix is stripped before lookup so `node:crypto` and `crypto` share fate. Each sanitizer returns a shallow copy with just the dangerous member neutralized — the rest of the module (hashing, signing, TLS helpers, HTTPS requests, SQL queries) is untouched, so this is member-level neutralization, not module denial:

- **crypto** — `setEngine` replaced with a stub that throws instead of forwarding to host OpenSSL, so no library is ever loaded; `setFips` replaced with a throwing stub so guest code cannot flip the host process's FIPS mode (GHSA-x3v6-43hc-82mc). `setEngine` and `setFips` are the only `set*` members `crypto` exposes, so the class is closed; `getFips()` (read-only) is untouched. The deprecated `crypto.fips` accessor (DEP0093, setter backed by `setFips`) is non-enumerable, so the `Object.assign` copy never carries it, and the read-only wrap refuses the write regardless.
- **node:sqlite** — the `DatabaseSync` constructor is wrapped so `allowExtension` is forced off (for object- **and function-typed** options args — Node's `DatabaseSync` accepts a function as options, and functions carry own properties); Node itself then throws `ERR_INVALID_STATE` from both `loadExtension()` and `enableLoadExtension()`. The resolver is also hardened to collapse/reject repeated `node:` prefixes.
- **tls** — `setDefaultCACertificates` replaced with a throwing stub (parallels the existing `dns` denial for process-wide network-state mutation).
- **http / https** — `globalAgent` replaced with a fresh sandbox-dedicated `Agent`, so the sandbox can never reach the host's shared singleton; the module's own `request()`/`get()` continue to work.

This complements the existing whole-module `DANGEROUS_BUILTINS` denylist (`module`, `vm`, `worker_threads`, `dns`, `os`, `v8`, …): that list rejects builtins whose *entire purpose* is host reach; this table keeps a useful builtin but removes the one member that escapes.

### Detection Rules

- `crypto.setEngine(...)` from sandbox code.
- `crypto.setFips(...)` from sandbox code (process-wide FIPS-mode mutation; watch also for any future `crypto` `set*` member).
- `node:sqlite` `DatabaseSync(..., {allowExtension: true})` or `.loadExtension(...)` / `.enableLoadExtension(...)` from sandbox code; also any `require('node:node:...')` double-prefix spelling.
- `tls.setDefaultCACertificates(...)` from sandbox code (watch for `URLSearchParams.getAll()` used to manufacture a host array).
- Reads of `https.globalAgent` / `http.globalAgent`, especially `.on('free'|'keylog'|...)` subscriptions.

### Considered Attack Surfaces

- **Other native-loading members** — `process.dlopen` is already covered (the whole `process` builtin is denied). Any future builtin that gains a `loadExtension`-style native loader must be added to `BUILTIN_MEMBER_SANITIZERS` or `DANGEROUS_BUILTINS`.
- **`http`/`https` request pooling** — after the fix the sandbox still makes real requests through the module's internal (host) globalAgent; it simply can no longer *observe* it. Connection-pool sharing between host and sandbox requests is a separate, pre-existing consideration not addressed here.
- **`tls.createSecureContext` / per-request `ca` options** — these set connection-local trust, not process-wide, and are not neutralized; they do not affect other host TLS clients.

---

## Attack Category 45: NodeVM External-Package Allowlist Bypass via Unanchored Matcher and `..` Traversal

**Advisories**: GHSA-c48m-32m9-vx93

**Tests**: test/ghsa/GHSA-c48m-32m9-vx93/, test/nodevm.js ("module name glob escape"), test/nodevm.js ("strict module name checks"), test/nodevm.js ("module name globs"), test/nodevm.js ("whitelist check before custom resolver")

**Related**: [Category 21: NodeVM Builtin Allowlist Bypass via Host-Passthrough Builtins](nodevm-require.md#attack-category-21-nodevm-builtin-allowlist-bypass-via-host-passthrough-builtins) (the *builtin* allowlist; this category is the *external package* allowlist), [Category 24: NodeVM `require.root` Symlink Bypass (Path Check/Use TOCTOU)](nodevm-require.md#attack-category-24-nodevm-requireroot-symlink-bypass-path-checkuse-toctou) (the filename-side boundary check this specifier-side check composes with), [Category 46: NodeVM External-Package Allowlist Bypass via Unanchored Module-Path Prefix](nodevm-require.md#attack-category-46-nodevm-external-package-allowlist-bypass-via-unanchored-module-path-prefix) (the filename-space sibling of this specifier-space check)

### Description

`NodeVM`'s `require.external` option names the npm packages sandbox code may load. When it is combined with a custom resolver (`require.resolve`) — the common shape in plugin hosts, user-script platforms, and multi-tenant sandboxes, where the embedder points resolution at the application's own dependency directory — `LegacyResolver.customResolve` decides whether to consult that resolver by testing the **bare specifier** against `this.externalCache`.

Those regexes were built by `makeExternalMatcherRegex(pattern)` with **no anchors**. `external: ['left-pad']` compiled to `/left\-pad/`, which `.test()` matches anywhere in the string. Any specifier merely *containing* the allowlisted name therefore passed the pre-check. The resolver was then consulted, the returned path was pushed onto `this.externals` (making it permanently allowed), and with the default `context: 'host'` the package's top-level code was executed by the host `require()` — outside every sandbox restriction the embedder configured, including `builtin: []`.

Anchoring alone is not sufficient. The matcher must permit a subpath tail (`left-pad/utils` is a legitimate require), and a permitted tail can itself carry `..` segments that walk back out of the package directory under ordinary path semantics. `left-pad/../evil-package` satisfies `^left-pad[\\/].*$` yet resolves to a sibling package that was never allowlisted, restoring the original impact in full.

CWE-863 (Incorrect Authorization). CWE-706 (Use of Incorrectly-Resolved Name or Reference). CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

### Attack Flow

1. **Embedder configures a narrow allowlist plus a custom resolver** — `new NodeVM({ require: { external: ['left-pad'], resolve: id => require.resolve(id, {paths: [appDeps]}), builtin: [], context: 'host' } })`. The intended policy is "only `left-pad`".
2. **Sandbox requires a colliding or traversing specifier** — `require('evil-left-pad')` (substring collision) or `require('left-pad/../evil-package')` (traversal out of the package boundary).
3. **The unanchored / tail-permissive pre-check passes**, so `customResolve` calls the embedder's resolver with the attacker's specifier.
4. **The resolver locates a real file** — the colliding package is present in the application's dependency directory (plugin upload dir, private-registry mirror, user-controllable `node_modules`), or the traversal lands on any sibling package already installed there.
5. **`customResolve` pushes the resolved path onto `this.externals`** and calls `loadNodeModules`, so `isPathAllowedForModule` now approves it.
6. **Host `require()` executes the module's top-level code in host context** → host `child_process`, host `fs`, host env/secrets. Sandbox escape.

### Canonical Example

```javascript
// Embedder: allowlist is exactly one package, no builtins.
new NodeVM({require: {external: ['left-pad'], builtin: [], context: 'host',
                      resolve: id => require.resolve(id, {paths: [appDeps]})}});

// Sandbox — both reach an un-allowlisted host package:
require('evil-left-pad');            // substring collision: /left\-pad/ matches
require('left-pad/../evil-package'); // traversal: matches ^left-pad[\/].*$
```

- Wildcard allowlist entries (`@scope/*`) match by path segment rather than by substring, so `x@scope/pkg` and `@scope-evil/pkg` are denied: see test/ghsa/GHSA-c48m-32m9-vx93/repro.js.

### Why This Works

`externalCache` is a *pre-check* whose only job is to decide whether the embedder's resolver is trusted to speak for this specifier. It was written as a containment test rather than an identity test, so it answered "does the allowlist appear in this name" instead of "is this name the allowlisted package". Package names are an unstructured namespace an attacker can populate freely, so containment is not a boundary. The traversal variant is the same failure one level down: the pre-check treated everything after the first separator as opaque, but the loader interprets it as a path with `..` semantics — the classic check/use disagreement, here between a string matcher and `path.resolve`.

A regex-only fix does not close the traversal: a negative lookahead such as `(?:[/](?!\.\.).*)?$` only rejects `..` immediately after the *first* separator. `left-pad/sub/../evil` keeps `sub` in that position and passes.

### Mitigation

Two composed layers in `lib/resolver-compat.js`, restoring the external-allowlist boundary:

1. **Anchor the matcher** (`LegacyResolver` constructor) — `externalCache` entries are built as `^(?:<pattern>)(?:[\\/].*)?$`. A bare specifier must *equal* the allowlisted name, or be that name followed by a separator and a subpath. Wildcard semantics inside `<pattern>` are untouched (`*` → `[^/]*`, `**` → `.*`), so `@scope/*` still matches `@scope/pkg` and `@scope/pkg/sub` but no longer matches `x@scope/pkg` or `@scope-evil/pkg`. `this.externals` (the *filename*-side matcher, built by `makeExternalMatcher`) is deliberately not changed — it matches resolved absolute paths, a different namespace.
2. **Reject `..` path segments** (`LegacyResolver.customResolve`) — after the anchored check passes and only on the bare-specifier branch (`!pathIsAbsolute(x) && !pathIsRelative(x)`), the specifier is split on `[\\/]` and rejected if any segment is exactly `..`. Segment-splitting rather than substring search is what makes this depth-independent, and it deliberately does not reject names that merely *contain* dots (`lodash.merge`, `..foo` as a package name component is not a `..` segment).

**Ordering — the `..` check runs on the raw, un-canonicalized specifier, before the resolver and therefore long before any `realpath()`.** This is the only correct placement. Canonicalization *removes* `..` segments by definition, so a lexical `..` check placed after `realpath()` would be a guaranteed no-op. The two checks defend different things and must both exist: this one is a *specifier*-space check that keeps a request from ever escaping the allowlisted package's name boundary; `CustomResolver.isPathAllowed`'s `realpath()` (Category 24, GHSA-cp6g-6699-wx9c) is a *filename*-space check that keeps a resolved file from escaping `require.root` through a symlink, which no lexical inspection can see. Neither subsumes the other, and this fix adds no new path to `isPathAllowed`.

**Fail-safe fallback.** Rejection returns `undefined` from `customResolve`, which makes the resolver fall through to the standard `loadNodeModules` path. Because the rejected specifier's resolved path is never appended to `this.externals`, `isPathAllowedForModule` denies it and the sandbox observes an ordinary module-not-found error. There is no separate error channel to probe.

### Detection Rules

- Any allowlist/denylist matcher built with `new RegExp(pattern)` and consumed via `.test()` without `^`/`$` — containment where identity was intended.
- Any check that validates a *name* and then hands that name to something that interprets it as a *path*.
- Any subpath-permitting matcher (`.*` tail) that does not separately constrain the tail's segments.
- New code appending to `this.externals` — that array is the authorization record; anything reaching it is permanently allowed.

### Residual Risk

- **The embedder's resolver is still trusted for allowlisted names.** A `require.resolve` that itself maps `left-pad` to an arbitrary file is outside vm2's control by design; this fix constrains only which specifiers reach it.
- **Case-insensitive filesystems.** `LEFT-PAD` does not match the allowlist and is denied, which is the safe direction, but on macOS/Windows an embedder expecting case-insensitive matching gets a denial rather than a load.
- **Separator handling is platform-independent, deliberately.** The segment split is `[\\/]` on every platform, so `left-pad\\..\\evil` and `left-pad/..\\evil` are rejected on POSIX too — verified empirically on darwin. On POSIX a backslash is a legal filename character and `path.resolve` would *not* treat those as traversal, so this is a conservative over-rejection: the specifier is refused although it could not have escaped. That is the safe direction (the alternative — splitting only on `/` under POSIX — would leave the Windows traversal open in any cross-platform deployment), and the cost is that a package whose name genuinely contains a literal `..` between backslashes becomes unrequirable. No such package name is valid on npm.
- **Percent-encoded and dot-padded forms are *not* `..` segments and are not rejected by this check — they do not need to be.** `left-pad/..%2fevil`, `left-pad/%2e%2e/evil` and `left-pad/....//evil` reach the resolver, but `require()` performs no URL-decoding and `path.resolve` treats `....` as an ordinary directory name, so none of them traverses; each fails as module-not-found. Verified empirically. Were a future custom resolver to decode percent-escapes itself, that decoding would happen inside embedder code and outside this boundary — an embedder-side concern, noted here so the asymmetry is not mistaken for a gap.

Re-verified 2026-09-02 on Node v26.7.0.

---

## Attack Category 46: NodeVM External-Package Allowlist Bypass via Unanchored Module-Path Prefix

**Advisories**: GHSA-7q3f-wx44-378m

**Tests**: test/ghsa/GHSA-7q3f-wx44-378m/, test/nodevm.js ("relative require not allowed to enter node modules"), test/nodevm.js ("allows specific transitive external dependencies in sandbox context")

**Related**: [Category 45: NodeVM External-Package Allowlist Bypass via Unanchored Matcher and `..` Traversal](nodevm-require.md#attack-category-45-nodevm-external-package-allowlist-bypass-via-unanchored-matcher-and--traversal) (the *specifier*-space sibling of this check; see **Composition** below), [Category 24: NodeVM `require.root` Symlink Bypass (Path Check/Use TOCTOU)](nodevm-require.md#attack-category-24-nodevm-requireroot-symlink-bypass-path-checkuse-toctou) (the `realpath()` boundary this check delegates to first)

### Description

`LegacyResolver.isPathAllowedForModule(path, mod)` is the authorization decision for a `require()` **originating inside** an already-allowlisted external module `mod`. Under `transitive: false` the intent is "`mod` may load its own files, but not other packages". It implemented that as a raw prefix test:

```javascript
if (path.startsWith(mod.path)) {
    const rem = path.slice(mod.path.length);
    if (!/(?:^|[\\/])node_modules(?:$|[\\/])/.test(rem)) return true;
}
```

`startsWith` is a *containment* test on a string, not a *boundary* test on a path. For an allowlisted module at `.../node_modules/foo`, the sibling `.../node_modules/foo2/index.js` starts with `.../node_modules/foo`, so the test passed. The `node_modules` guard on the remainder did not catch it: that guard exists to stop a genuine *nested* dependency (`foo/node_modules/bar`), and a **sibling's** remainder (`2/index.js`) never contains a `node_modules` segment at all. The one check that would have caught it — requiring a separator after the prefix — was absent.

CWE-22 (Improper Limitation of a Pathname to a Restricted Directory). CWE-863 (Incorrect Authorization).

### Attack Flow

1. **Embedder allowlists one package, transitive loading off** — `new NodeVM({require: {external: {modules: ['foo'], transitive: false}, root: appDir}})`. Intended policy: "`foo` only, and `foo` may not pull in anything else".
2. **A prefix-sharing sibling exists in the same `node_modules`** — `foo2`, `foo-evil`, `foobar`. The attacker does not create this; they find a deployment where it already exists.
3. **An allowlisted package has a reachable relative-require path** — `foo/index.js` does `require('../foo2')` on some code path the sandbox can trigger.
4. **The prefix test approves the sibling** — `path.startsWith(mod.path)` is true, the remainder `2/index.js` has no `node_modules` segment, so `isPathAllowedForModule` returns `true`.
5. **The un-allowlisted sibling loads**, its top-level code runs, and its exports reach sandbox code — a package the embedder never authorized, with `transitive: false` explicitly set.

### Canonical Example

```javascript
// Embedder: exactly one external package, no transitive loading.
new NodeVM({require: {external: {modules: ['foo'], transitive: false},
                      context: 'sandbox', root: '/app'}});

// /app/node_modules/foo/index.js (allowlisted) contains:
//     exports.reach = n => require('../' + n);
// Sandbox:
require('foo').reach('foo2');   // loads un-allowlisted /app/node_modules/foo2
```

### Why This Works

The check compares two strings that both happen to be paths, using an operator that knows nothing about path structure. `foo` and `foo2` are unrelated packages, but `"foo2"` contains `"foo"` at offset 0, and `startsWith` reports only that. Package-name namespaces are attacker-populatable and prefix collisions are common in practice (`foo` / `foo2`, `lodash` / `lodash.merge`, `react` / `react-dom`), so containment at a path prefix is never a containment guarantee about *directories*. This is the same failure class as Category 45 one layer down, and the base `CustomResolver.isPathAllowed` already had the correct idiom a few lines above — it simply was not applied here.

**Scoped packages carry no separate semantics and were affected identically.** `@scope/pkg` vs `@scope/pkg-evil` is the same shape (`mod.path` = `.../node_modules/@scope/pkg`), and was likewise reachable via relative require before this fix — verified empirically. The scope prefix is just more path text; the boundary requirement is unchanged.

### Mitigation

`lib/resolver-compat.js` — `isPathAllowedForModule` now requires a **path boundary** after `mod.path`, exactly mirroring the idiom in the base `CustomResolver.isPathAllowed`: the path either equals `mod.path`, or `mod.path` already ends in a separator, or the character at `mod.path.length` is a separator.

```javascript
const len = mod.path.length;
if (path.startsWith(mod.path) &&
    (path.length === len || (len > 0 && this.fs.isSeparator(mod.path[len - 1])) || this.fs.isSeparator(path[len]))) {
```

Separator testing goes through `this.fs.isSeparator`, the same filesystem-aware predicate the rest of the resolver uses, so Windows backslash separators are handled by the `VMFileSystem` in force rather than by a hardcoded character. (Note that the obvious one-line form `path.startsWith(mod.path + path.sep)` is **wrong** in this function: the parameter `path` shadows the `path` module, so `path.sep` is `undefined` on a string and the comparison silently degrades.) The `node_modules` remainder test, the `mod.allowTransitive` short-circuit, and the `this.externals` fallback are unchanged — this fix only tightens the prefix into a boundary.

**Path space — the check is deliberately lexical on BOTH sides.** `isPathAllowedForModule` calls `super.isPathAllowed(path)` first, which is where Category 24's `realpath()` lives — but that call canonicalizes into a *local* variable purely to test against `rootPaths`; it neither returns nor rewrites `path`. So the `path` and `mod.path` this boundary check sees are both the resolver's lexically-resolved paths (verified empirically: on macOS the observed path is `/tmp/…`, not the canonical `/private/tmp/…`). That symmetry is the point. Both operands come from the same resolver in the same space, so the comparison is like-for-like; canonicalizing only one side would introduce a fresh mismatch — a legitimate subpath reached through a symlinked `node_modules` would stop matching its own `mod.path` and be over-blocked. Escape *through* a symlink is a filename-space concern and is already held by the `realpath()` gate against `require.root` (Category 24), which runs first and independently. Neither check subsumes the other.

### Composition with Category 45

The two external-allowlist defenses are orthogonal and operate in different value spaces at different times:

| | Category 45 (GHSA-c48m-32m9-vx93) | Category 46 (GHSA-7q3f-wx44-378m) |
|---|---|---|
| Function | `LegacyResolver.customResolve` | `LegacyResolver.isPathAllowedForModule` |
| Space | Specifier (bare module name as written) | Filename (resolved absolute path) |
| Timing | Before the custom resolver, before any `realpath()` | After resolution, at the authorization decision |
| Precondition | A custom `require.resolve` is configured | None — the ordinary loader path |
| Guards against | Lexical escape of the package *name* boundary | Escape of the package *directory* boundary |

Neither weakens the other: Category 45's rejection is a `return undefined` that makes resolution fall through without appending to `this.externals`, and Category 46 only narrows an existing `true`-returning branch. A request must satisfy both, plus Category 24's `realpath()` root check, to load.

### Detection Rules

- `startsWith` (or `indexOf(x) === 0`) applied to a filesystem path where directory containment is intended, without a following separator test.
- A containment guard on the *remainder* of a prefix strip (here, the `node_modules` test) being relied upon to catch cases the prefix test itself should have rejected — the remainder of a sibling match is not structurally distinguishable from the remainder of a legitimate subpath.
- Any authorization comparison where one operand is canonicalized and the other is not.

### Residual Risk

- **Case-insensitive filesystems.** `.../node_modules/FOO/index.js` does not match `mod.path` of `.../node_modules/foo` and is denied. Safe direction; an embedder relying on macOS/Windows case-insensitivity gets a denial rather than a load.
- **A genuinely nested `foo/foo2`** (a directory literally inside the allowlisted package) is still allowed, correctly — it is part of `foo`.
- **`transitive: true` is unaffected, by design.** That option sets `mod.allowTransitive`, which short-circuits `isPathAllowedForModule` *before* the prefix check, so an allowlisted package may still load sibling directories. This is what the option means — npm flattens `node_modules`, so a genuine transitive dependency *is* a sibling — and it is unchanged before and after this fix (verified against the pre-fix control). The advisory's configuration, and the only one this fix alters, is `transitive: false`.
- **The `this.externals` regex fallback is unchanged** and remains the authorization record for paths the resolver has already approved; this fix does not narrow it. A path appended there by Category 45's route stays allowed by design.

Re-verified 2026-09-02 on Node v26.7.0.

---

## Attack Category 47: Sandbox Rebuilt an Unrestricted NodeVM by Requiring vm2 From Disk; Shipped CLI Ran Untrusted Scripts With No Effective Sandbox Boundary

**Advisories**: GHSA-jxxv-8r27-vm4p, GHSA-j3hm-6rg5-mchv, GHSA-cp6g-6699-wx9c

**Tests**: test/ghsa/GHSA-jxxv-8r27-vm4p/, test/ghsa/GHSA-j3hm-6rg5-mchv/, test/ghsa/GHSA-cp6g-6699-wx9c/

### Description

`lib/cli.js` — the `npx vm2 ./script.js` entry point documented as a way to run a script under vm2 — constructed `NodeVM.file(path, { require: { external: true } })` with **no `require.root`** and the default `require.context: 'host'`.

`CustomResolver.isPathAllowed` returns `true` for every candidate when `rootPaths === undefined`, and `context: 'host'` loads each admitted module through the real host `require()`. The script handed to the CLI could therefore `require(__filename)` — or any other absolute path — and have that file executed in the **host** realm with full host authority (`child_process`, `fs`, `process`). Running `vm2 ./untrusted.js` was, for a self-requiring script, equivalent to running `node ./untrusted.js`: the CLI advertised isolation it did not provide (GHSA-jxxv-8r27-vm4p).

### Why It Works

The insecure combination is not reached by an exotic trick — it was the shipped default of the tool whose entire purpose is isolation. `require.external: true` is *documented* as permissive, but the CLI is the one caller for which "permissive" is never the intended posture, and it never set the two options (`require.root`, `require.context`) that bound the primitive.

### Mitigation

`lib/cli.js` now constructs the `NodeVM` with both bounds:

1. **`root: pa.dirname(script)`** — requires are confined to the target script's own directory, so an arbitrary absolute path is no longer loadable.
2. **`context: 'sandbox'`** — admitted modules are compiled and executed *inside* the sandbox, not in the host realm. A script that `require()`s itself or a sibling now runs sandboxed.

Verified end-to-end: under the shipped CLI, the target script cannot reach host `fs` (`require('fs')` → `Cannot find module 'fs'`) and cannot write a host marker file by re-requiring itself.

### Closing the Nesting-Default Bypass (GHSA-j3hm-6rg5-mchv)

Two changes land alongside the CLI fix in `lib/resolver-compat.js`. The first closes GHSA-j3hm-6rg5-mchv; the second is a migration aid for the accepted residual documented below:

1. **Sandbox `require()` of vm2 itself is denied — this is the GHSA-j3hm-6rg5-mchv fix.** `isVm2SelfRequire`, consulted at the top of `CustomResolver.isPathAllowed` (inherited by `LegacyResolver`), blocks vm2's importable surface — its `lib/` directory and its package main entry — matched by realpath so a symlinked candidate cannot dodge the boundary. This closes the reported mechanism: `require('vm2')` → real `VM`/`NodeVM` classes → nested *unrestricted* sandbox running `child_process`, which defeated the guarantee `nesting: false` is supposed to provide. Scoped to `lib/` + the main entry rather than the whole package root, because in the source tree that root also holds fixtures (`test/node_modules/*`) an embedder's `require.root` may legitimately point at. Legitimate `nesting: true` is unaffected — it uses the builtin-override mechanism, not an external file require.
2. **A one-time `console.warn`** is emitted when `require.external` is truthy, `require.root` is unset, and the context is host. It steers embedders toward `require.root` / `context: 'sandbox'` without breaking existing configurations. A construction-time *throw* was deliberately **not** used: it would reverse the shipped [Category 25](nodevm-require.md#attack-category-25-nodevm-nesting-configuration-trap-nesting_override-only-resolver) / GHSA-cp6g-6699-wx9c invariant that construction does not throw when `root` is unset.

### Accepted Residual — `require.external` Without `require.root` (by design; warn-only until the next major)

**`isPathAllowed`'s `if (this.rootPaths === undefined) return true;` is deliberately unchanged.** A `NodeVM({ require: { external: true } })` with no `require.root` and the default host context still host-`require()`s any attacker-named path, and that path's top-level code executes in the host realm with full authority. That breadth is the documented meaning of `require.external` without a root boundary — the option asks vm2 to load modules through the real host `require()` — not a separate defect.

It is held deliberately, for backwards compatibility:

- Refusing the `external` + no-`root` + host-context combination at construction is a **breaking change** for existing embedders (roughly twenty in-repo call sites alone depend on the current no-throw behavior), and it would reverse the shipped GHSA-cp6g-6699-wx9c invariant that construction does not throw when `root` is unset.
- The one-time warning above ships instead, steering embedders toward `require.root` / `context: 'sandbox'` without breaking working configurations.
- **Deny-by-default is deferred to the next major version**, where a breaking change is acceptable.

What GHSA-j3hm-6rg5-mchv reported is narrower, and is fixed: sandboxed code could `require('vm2')` from disk and rebuild an *unrestricted* nested `NodeVM`, defeating the nesting default. That route is denied by every spelling — bare `vm2`, the `lib/` path, `index.js`, and the package main entry — and matched by realpath, so a symlink cannot dodge it.

Embedders wanting the boundary today should set `require.root`, `context: 'sandbox'`, or both.

Re-verified 2026-09-02 on Node v26.7.0: `new NodeVM({require: {external: true}})` still host-loads an arbitrary absolute path and emits the one-time warning, while `require('vm2')` — bare, package root, `index.js`, `lib/main.js` and `lib/nodevm.js` — is denied under a `require.root` that contains vm2 itself.

### Detection Rules

- `NodeVM.file(...)` / `new NodeVM(...)` with `require.external` truthy and no `require.root` — in particular any shipped tool or CLI wrapper.
- `require.root` pointing at a tree containing `node_modules/vm2` (e.g. the `root: './'` pattern), combined with `context: 'host'`.
- Sandbox `require('vm2')` / `require('.../node_modules/vm2')` / `require('.../vm2/lib/...')`.

### Considered Attack Surfaces

- **Transitive re-export** — an allowed host-context module under `root` that itself `require('vm2')` would hand the classes back to the sandbox. This is the inherent "external + `context: 'host'` runs host code" property; the self-require block covers only the *direct* sandbox path.
- **Hardlink to vm2 under `root`** — `realpath` does not resolve hardlinks, so a hardlink to `lib/main.js` placed under `root` would not match the boundary. Creating it requires filesystem control, outside the sandbox-JS threat model.
- **Every other path under the open `require.external`-without-`root` primitive** — explicitly *not* covered; see the **Accepted Residual** section above.

---

## Attack Category 52: Host `util` Members Auto-Forwarded to the Sandbox (`util.getCallSites` Host Call-Stack Leak)

**Advisories**: GHSA-r273-hxvj-fxhp

**Tests**: test/ghsa/GHSA-r273-hxvj-fxhp/

**Uses**: [Category 48: Host Filesystem Path Leak via Host-Realm Error Stack](error-sanitization.md#attack-category-48-host-filesystem-path-leak-via-host-realm-error-stack)

**Supersedes**: extends the GHSA-v27g-jcqj-v8rw / [Category 48](error-sanitization.md#attack-category-48-host-filesystem-path-leak-via-host-realm-error-stack) host-frame redaction to the programmatic stack-introspection channel those fixes did not cover.

### Description

NodeVM exposes the host `util` module to the sandbox through `defaultBuiltinLoaderUtil` (`lib/builtin.js`), which built the exposed copy with `Object.assign({}, util)` — a **wholesale copy-everything-forward** of every host `util` member. This is a structural hole, not a single leaky function: every future host `util` member enters the sandbox unreviewed the day Node ships it.

On Node >= 22.9 the first such member to matter is `util.getCallSites()`, which returns the host process call stack as plain data — absolute file paths (vm2's own `lib/bridge.js` / `lib/nodevm.js`, the embedding application's entrypoint), `node:internal/*` frames, function names, and line numbers. It is produced host-side and never crosses the sandbox-realm Error stack formatter, so the GHSA-v27g redaction (which only rewrites CallSite getters when the *sandbox realm* formats an `Error` stack — [Defense Invariant #5](../ATTACKS.md#defense-invariants)) does not cover it. The Node 22 singular spelling `util.getCallSite` is the same class; `util.setTraceSigInt` (a process-wide host SIGINT hook) and private internals (`_errnoException`, `_exceptionWithHostPort`) were forwarded by the same wholesale copy.

The deprecated `sys` builtin is an alias of host `util` and reached the sandbox through the generic read-only loader, carrying the same members — a second channel.

Information disclosure only: the API returns strings/numbers, no host object references, no code execution. Reachable from any config allowing `util` / `sys`, including `builtin: ['*']` and the README's typical configurations.

### Attack Flow

1. A NodeVM allows the `util` (or `sys`) builtin — `require: { builtin: ['util'] }` or `['*']`.
2. Sandbox: `require('util').getCallSites(N)` (Node >= 22.9).
3. Node walks the host call stack host-side and returns CallSite objects with `scriptName` / `functionName` / `lineNumber` as data.
4. Sandbox reads host absolute paths (vm2 install path, embedder file layout, entrypoint) — the exact category GHSA-v27g promised to redact.

### Canonical Example

```js
const {NodeVM} = require('vm2');
new NodeVM({require:{builtin:['util']}}).run(
  "module.exports = require('util').getCallSites(4)[0].scriptName", 'p.js');
// -> "/abs/path/to/vm2/lib/bridge.js"  (a host path)
```

### Why It Works

`Object.assign({}, util)` copies members that did not exist when the loader was written. GHSA-v27g reasoned about the *Error-stack formatting* channel and hardened it; a *programmatic* stack API produces the same data without touching that formatter, so the redaction never runs. No allowlist gated what `util` could hand the sandbox.

### Mitigation

Close the wholesale-forwarding **class**, not just `getCallSites`. `defaultBuiltinLoaderUtil` now builds the exposed copy from a vetted **allowlist** (`SAFE_UTIL_MEMBERS`, consumed by `sanitizeUtilModule`) instead of `Object.assign`. An allowlist is *forward-safe*: a member Node adds tomorrow does not auto-enter — admitting it is a conscious edit. The allowlist enumerates the full documented + legacy `util` surface, presence-gated (`name in mod`) so one list is correct Node 8→26; members are copied by reference so `types`, `inspect`, `promisify` etc. behave as before. The host-introspection / host-mutation / private members (`getCallSites`, `getCallSite`, `setTraceSigInt`, `_errnoException`, `_exceptionWithHostPort`, `convertProcessSignalToExitCode`) are simply not on the list. `sanitizeUtilModule` is registered in the existing `BUILTIN_MEMBER_SANITIZERS` table (the GHSA-46pr member-neutralization chokepoint used by crypto/tls/sqlite/http(s)) for both `util` and `sys`, so the `sys` alias shares fate. Restores [Defense Invariant #5](../ATTACKS.md#defense-invariants) for the programmatic channel.

### Detection Rules

- A builtin loader that copies a host module wholesale (`Object.assign({}, mod)`, spread, `for..in` forward) rather than from a vetted member set — every future host member auto-enters.
- Sandbox source calling a host stack/heap/host-state introspection API (`getCallSites`, `getCallSite`, `getHeapSnapshot`-like, `getSystemError*` beyond static tables).

### Considered Attack Surfaces

- **`node:util` / `node:node:util` spellings** — the double-prefix and node: normalization (GHSA-8686/6w8r) route through the same sanitizer; verified blocked.
- **`util.getSystemErrorName` / `getSystemErrorMap` / `getSystemErrorMessage`** — kept: static errno lookup tables, not host process state.
- **`inspect.custom` / `promisify.custom` symbols** — read as `undefined` in the sandbox both before and after this fix (pre-existing bridge behaviour); the allowlist does not change util's usable surface beyond removing the leaky members.
