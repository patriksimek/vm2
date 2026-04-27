# GHSA-47x8-96vw-5wg6 — Structural fix

## The invariant I closed

> Every well-known host built-in **prototype** and **constructor** must
> be pre-mapped to its sandbox-realm equivalent in the bridge's identity
> cache, so any code path that would otherwise surface a host intrinsic
> into the sandbox returns the sandbox-realm intrinsic instead.

This is the right chokepoint because:

1. The bridge already maintains two paired weakmaps for identity:
   `mappingOtherToThis` (host → sandbox) and `mappingThisToOther`
   (sandbox → host). Every code path that converts a host value to a
   sandbox-side proxy consults `mappingOtherToThis` *before* any
   wrapping logic runs (the cache short-circuit at
   `lib/bridge.js:1600`). The same is true for `thisFromOtherForThrow`
   (line 1537) and `thisEnsureThis` (line 1499).
2. Pre-populating those weakmaps at bridge init is a single, structural
   write — not a per-trap filter, not a per-call check. Once the cache
   is seeded, every lookup path benefits without any additional code.
3. Adding the mappings symmetrically (host-side via `otherWeakMapSet`
   on `mappingThisToOther`) gives round-trip identity preservation, so
   sandbox values that flow to the host and back keep the same
   identity from the sandbox's view.

The previous symbol-filter patch (commit `67bc511`) closed the canonical
RCE payload (extraction of `nodejs.util.inspect.custom`), but the
underlying primitive — `HObject !== sandbox Object`, i.e., a *handle* on
a host built-in — survived. Any future vulnerability that converts
"I have a host built-in handle" into "I can call a host method that
bypasses bridge sanitisation" would re-enable the same escape class.
The structural fix removes that primitive: the sandbox can no longer
*hold* a wrapped host built-in.

## Implementation

`lib/bridge.js` — added `thisAddIdentityMapping(thisProto, otherProto)`
right after the existing `thisAddProtoMapping` calls (line ~1700).
The helper:

1. Writes `[otherProto, thisProto]` to `mappingOtherToThis` (sandbox-side).
2. Writes `[thisProto, otherProto]` to `mappingThisToOther` (host-side
   mirror, via `otherReflectApply(otherWeakMapSet, ...)`); failure here
   is best-effort because round-trip identity is a quality-of-life
   concern, not the security invariant.
3. Reads the `.constructor` slot via `getOwnPropertyDescriptor` on both
   prototypes (so we never trigger a getter), guards against
   `isThisDangerousFunctionConstructor` and
   `isDangerousFunctionConstructor`, and writes the constructor
   identity mapping with the same dual-direction semantics.

Called for: `Object`, `Array`, every entry in `globalsList` *except*
`Function`, every entry in `errorsList` (`RangeError`,
`ReferenceError`, `SyntaxError`, `TypeError`, `EvalError`, `URIError`,
`SuppressedError`, `Error`).

`Function` / `AsyncFunction` / `GeneratorFunction` /
`AsyncGeneratorFunction` are deliberately skipped — see "Edge cases"
below.

Every changed line is annotated with `// SECURITY (GHSA-47x8): ...`.

## Edge cases considered

### Function-family prototypes are NOT cached

If `host Function.prototype` were mapped to `sandbox Function.prototype`,
then a sandbox proto-walk landing on the host `Function.prototype`
would surface the sandbox prototype directly — and reading
`.constructor` on a real sandbox prototype follows the prototype's own
data slot, returning sandbox `Function`. Sandbox `Function` is callable
(it creates sandbox-realm functions), which means the existing
"`fp.constructor` returns `emptyFrozenObject`" defense
(`isDangerousFunctionConstructor` in `thisFromOtherWithFactory`) would
be silently bypassed for that path.

By leaving the four Function-family prototypes un-cached, the proxy
`get` trap continues to handle `fp.constructor` reads: it reads
`host Function.prototype.constructor` = host Function, and
`thisFromOtherWithFactory` returns `emptyFrozenObject` because
`isDangerousFunctionConstructor(hostFunction)` is true.

The structural-leak test "Function constructor block remains in force"
exercises this exact invariant; the existing
`getOwnPropertyDescriptor Function constructor bypass attack` regression
in `test/vm.js:1279` exercises the descriptor variant.

### Promise mapping subtlety

`setup-sandbox.js` replaces sandbox `Promise` with
`localPromise extends globalPromise` *after* `bridge.js` runs.
At bridge-init time, `thisGlobalPrototypes.Promise` is the sandbox's
**original** `globalPromise.prototype`, **not** `localPromise.prototype`.

Consequence: a host `Promise` flowing into the sandbox now collapses to
`globalPromise` (sandbox-original), not to `localPromise`. From the
sandbox's perspective, `hostPromise instanceof Promise` is false (this
matches the pre-fix behaviour — verified by stash + re-test). The
sandbox's runtime `Promise` is `localPromise` whose `.prototype.__proto__`
*is* `globalPromise.prototype`, so the proto-chain still terminates at
the original sandbox intrinsic, and bridge sanitisation is intact.
Identity-equality with `Promise.prototype` is the only thing that
changes, and that was already broken before this fix.

### Well-known symbols

V8's well-known symbols (`Symbol.iterator`, `Symbol.species`, etc.)
are realm-shared by design — they are the same value across all realms
in the same V8 isolate. The structural fix doesn't touch them; the
existing dangerous-symbol filter in `isDangerousCrossRealmSymbol`
(`Symbol.for('nodejs.util.inspect.custom')`,
`Symbol.for('nodejs.rejection')`) is unchanged.

### Round-trip identity for sandbox values

The dual-direction mapping (writing both `mappingOtherToThis` and
`mappingThisToOther`) means a sandbox-realm intrinsic flowing to the
host now resolves to the host equivalent. This is consistent with
how the bridge has always treated `Object.prototype.bind`,
`__lookupGetter__` etc. via `connect()` in `setup-sandbox.js` — the
existing `__lookupGetter__ / __lookupSetter__ attack` regression
(`test/vm.js:839`) still passes:
`Buffer.from.__lookupGetter__("__proto__") === Object.prototype.__lookupGetter__.call(Buffer.from, "__proto__")`
remains `true`.

### Existing species-defense tests

The historical PoC for GHSA-grj5-jjm8-h35p (Array species self-return)
used `op.constructor.entries({})` to mint a host array. After the
structural fix, `op.constructor === sandbox Object`, so that chain
returns a sandbox array. The species defense is still required for
genuinely-host arrays (e.g., those exposed via sandbox config or
`Buffer.from`), so I:

- updated `test/ghsa/GHSA-grj5-jjm8-h35p/repro.js` to mint a host array
  via `sandbox: { hostArrayFactory: () => [] }` (functions executing
  in the host frame still produce host-realm objects when called);
- updated `test/vm.js`'s `neutralizeArraySpecies prevents species attack
  in apply trap` to use `Buffer.from([1,2,3]).slice(0)` (still a
  bridge-traversed host call where the apply trap fires).

The canonical PoC test for GHSA-grj5 still exercises the full
Function-extraction pipeline and remains blocked. The species
defense itself is unchanged.

## Variant attacks tried (all blocked)

I ran a 12-variant red-team probe (in `/tmp/redteam2.js` and
`/tmp/redteam3.js`) to verify the structural fix closes the entire
class:

| # | Variant | Outcome |
|---|---------|---------|
| 1 | `Buffer.apply.__proto__.__proto__` | `op === Object.prototype`, `op.constructor === Object` |
| 2 | `Reflect.getPrototypeOf` chain | same |
| 3 | `Object.getPrototypeOf` chain | same |
| 4 | `Object.getOwnPropertyDescriptor(Object.prototype, '__proto__').get` walk | same |
| 5 | sandbox-config-passed host array | `arr.constructor === sandbox Array` |
| 6 | `Buffer.from(...)` proto-chain walk | terminates at sandbox `Object.prototype` |
| 7 | `Object(42)` (Number wrapper) | sandbox `Number` identity |
| 8 | host array `Symbol.iterator` | iterator API filtered (next is undefined) — no leak |
| 9 | host TypeError caught in sandbox | sandbox `TypeError` identity, sandbox `instanceof` works |
| 10 | host Promise via sandbox config | sandbox proto chain (`localPromise`/`globalPromise` subtlety, no leak) |
| 11 | `Object.getPrototypeOf(Buffer.apply).constructor('return process')()` | `process is not defined` (sandbox Function is sandbox-safe) |
| 12 | `getOwnPropertyDescriptor` on wrapped host `Function.prototype` | descriptor `.value` is undefined (filtered) |
| w1 | `e.constructor.constructor('return process')()` | `process is not defined` |
| w2 | `Buffer.from('hi')` proto walk to `.constructor.constructor` | sandbox Function (sandbox-safe) |
| w11 | descriptor extraction on `fp` (uncached Function.prototype) | `.value` is undefined ✓ |

The only paths that "succeed" are sandbox-realm Function constructor
calls — which are inherently safe because sandbox `Function` creates
sandbox-realm functions where `process` is undefined, and this has
always been the sandbox's contract.

## Second-order effects

- **Performance**: The fix runs at bridge init time only. The cache
  lookup at `thisFromOtherWithFactory` line ~1600 was already there;
  pre-populating it with ~20 extra entries is negligible. No runtime
  hot-path changes.
- **Identity preservation**: For sandbox code that depended on
  `wrappedHostObject !== Object` to detect "this came from the host",
  that test is now unreliable. I am not aware of any consumer code
  that relied on this; the documented contract is that the bridge
  hides the host realm.
- **Round-trip identity**: A sandbox `Object` that flows to the host
  and back now keeps its sandbox `Object` identity (instead of
  becoming a fresh wrapped host Object proxy on the way back). This
  is strictly better — it eliminates a class of identity-confusion
  bugs.
- **`hostPromise instanceof Promise`**: This was already false before
  the fix because of `localPromise extends globalPromise`. No change.

## Files changed

- `lib/bridge.js` — `thisAddIdentityMapping` helper + invocation loop.
- `docs/ATTACKS.md` — Category 8 mitigation paragraph + defense table
  row for "Host built-in identity leak".
- `test/ghsa/GHSA-grj5-jjm8-h35p/repro.js` — switch host-array source
  from `ho.entries({})` to `hostArrayFactory()` (sandbox config).
- `test/vm.js` — switch `neutralizeArraySpecies` test to use
  `Buffer.from([1,2,3]).slice(0)`.
- `test/ghsa/GHSA-47x8-96vw-5wg6/structural-leak.js` — cherry-picked
  from base branch (was the failing test that drove this fix).

## Test results

- `test/ghsa/GHSA-47x8-96vw-5wg6/structural-leak.js`: 7/7 pass.
- `test/vm.js`, `test/nodevm.js`, `test/compilers.js` (npm test):
  150 pass, 1 pending, 0 failing.
- `test/ghsa/**/*.js`: 46/46 pass.
