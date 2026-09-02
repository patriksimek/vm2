# Transformer and Module Loading

Syntax the Acorn transformer (`ecmaVersion: 2022`) cannot see, and the dynamic code and module loading paths. Every future transformer blind spot belongs here.

Defense invariants enforced by fixes in this family: 9, 10 (see [Defense Invariants](../ATTACKS.md#defense-invariants)).

Categories in this file: [12](transformer-and-modules.md#attack-category-12-code-transformation-bypass), [13](transformer-and-modules.md#attack-category-13-dynamic-import-and-module-loading).

---

## Attack Category 12: Code Transformation Bypass

**Advisories**: GHSA-wp5r-2gw5-m7q7

**Tests**: test/ghsa/GHSA-wp5r-2gw5-m7q7/ (`repro.js` — fast-path bypass, `with()` instrumentation, unicode-escape identifier variants); test/vm.js ("transformer attack"); test/vm.js ("internal state attack"); test/vm.js ("SuppressedError escape via using declaration" — the `using`-inside-`eval()` blind spot); test/ghsa/GHSA-2cm2-m3w5-gp2f/repro.js ("regression: transformer-instrumented try/catch still works", "regression: transformer-instrumented with(...) still works")

### Description

vm2's transformer rewrites `catch` blocks and `with` statements to prevent access to host objects through exception variables. Attackers attempt to use reserved internal variable names or bypass the transformation entirely.

### Attack Flow

1. Guess the transformer's internal variable name pattern and use it directly.
2. Or hide the payload behind `eval()` / `new Function()`, compiling it from a string built at runtime.
3. Or use syntax that Acorn's configured `ecmaVersion` does not parse (e.g., `using` declarations in ES2024), reaching it through a source that contains none of the keywords which force the AST parse.

### Canonical Examples

```javascript
// Using vm2's internal state variable
aVM2_INTERNAL_TMPNAME = {};
aVM2_INTERNAL_TMPNAME.constructor.constructor("return process")();

// Attempting to access transformer's catch variable
try { throw new Error(); }
catch (a$tmpname) {
  a$tmpname.constructor.constructor("return process")();
}
```

- `with (VM2_INTERNAL_STATE_…) { … }` in a source containing none of `catch` / `import` / `async` reaches the internal state through the fast-path skip: see test/ghsa/GHSA-wp5r-2gw5-m7q7/repro.js.
- A unicode-escaped spelling such as `\u{56}M2_INTERNAL_STATE_…` names the same identifier while evading a raw substring check: see test/ghsa/GHSA-wp5r-2gw5-m7q7/repro.js.
- `eval("{using a = obj; throw null;}")` runs an ES2024 `using` declaration the transformer never parses: see test/vm.js ("SuppressedError escape via using declaration").

### Why It Works

The transformer renames catch clause variables to internal names and wraps them with sanitization. If an attacker can guess or use the internal variable name directly, they bypass the wrapping logic. `eval()` and `new Function()` do route their source back through the transformer -- `EvalHandler` and `FunctionHandler` in `lib/setup-sandbox.js` (the latter through `makeFunction`) both call `host.transformAndCheck` -- but `eval()` inherits the same fast-path bailout as top-level `vm.run` source, so a string carrying none of the trigger keywords is never AST-parsed. The transformer uses `ecmaVersion: 2022`, so `using` declarations (ES2024) are invisible -- the transformer does not instrument their implicit catch semantics.

### Mitigation

The transformer rejects any source whose AST names the `INTERNAL_STATE_NAME` identifier. `eval` and `new Function` are proxied in the sandbox (`EvalHandler` and `FunctionHandler`, which calls `makeFunction`, in `lib/setup-sandbox.js`), so their source passes through `transformAndCheck` (`lib/vm.js`) before it is compiled, and they are sandbox-scoped (they cannot access host context directly). The fast-path bailout at the top of `transformer()` (which skips AST instrumentation for code containing none of the security-relevant keywords) is conservative: it triggers full AST parse for any source containing `catch`, `import`, `async`, `with`, the `INTERNAL_STATE_NAME` substring, or a `\u` escape sequence (GHSA-wp5r-2gw5-m7q7 plus post-fix unicode-escape hardening — identifiers can be written as `\u{56}M2_INTERNAL_…` and would slip past a substring check, so any `\u` in source forces the AST walker to decode and inspect actual identifier names). The `ecmaVersion` limitation remains a known surface — a source that contains none of those triggers is never parsed, so `using` declarations (ES2024) inside `eval()` reach the runtime uninstrumented. A `new Function` body takes the other branch of `transformer()` (`args !== null`) and is always parsed, so the same `using` declaration is rejected there as a syntax error.

### Detection Rules

- **Variables containing `VM2_INTERNAL`**, `$tmpname`, or similar patterns.
- **`with` statements** — security-sensitive and instrumented.
- **Direct `eval()`** usage — the source is re-transformed, but it takes the fast-path bailout, so a keyword-free string is never parsed.
- **`new Function()`** with dynamically constructed strings — always parsed, never fast-pathed.
- **`using` or `await using`** inside `eval()` — the eval'd source inherits the transformer's keyword fast-path bailout, so a string carrying none of the trigger keywords is never AST-parsed and the declaration reaches the runtime uninstrumented.
- **Identifiers using `\uXXXX` / `\u{...}` escapes** — recognised legitimate JS, but a vector for evading literal-string identifier checks (handled by the fast-path `\u` bailout in `transformer.js`).

---

## Attack Category 13: Dynamic Import and Module Loading

**Advisories**: none

**Tests**: test/vm.js ("Dynamic import attack"); test/ghsa/GHSA-2cm2-m3w5-gp2f/repro.js ("regression: import() in source is rewritten to throw"); test/nodevm.js ("path attack"); test/nodevm.js ("root path checking"); test/nodevm.js ("relative require not allowed to enter node modules"); test/nodevm.js ("disabled require"); test/nodevm.js ("enabled require for certain modules"); test/nodevm.js ("outer require")

### Description

`import()` expressions create Promises whose constructor chain may not be properly sandboxed. Module loading can also expose host filesystem or module resolution internals.

### Attack Flow

1. Use `import("anything")` which returns a host-realm Promise.
2. Access `.constructor.constructor` on the promise to get host `Function`.

### Canonical Examples

```javascript
// Dynamic import constructor chain
const p = import("anything");
p.constructor.constructor("return process")();

// require from NodeVM context with path traversal
require("../../host-module");
```

- Traversal above `require.root` to a file that really exists is refused as `Cannot find module`, not as a distinct policy error: see test/nodevm.js ("path attack").

### Why It Works

Dynamic `import()` returns a Promise created by the host runtime, not the sandbox. Its `.constructor` is the host `Promise`, whose `.constructor` is the host `Function`.

### Mitigation

Dynamic `import()` throws `VMError` unconditionally: the transformer rewrites every `ImportExpression` to `INTERNAL_STATE_NAME.import(...)` (`lib/transformer.js`), and that method throws `new VMError('Dynamic Import not supported')` (`lib/setup-sandbox.js`), so the promise is never created and there is no constructor chain to walk. Inside an `async` function the same throw surfaces as a rejection rather than a synchronous throw. `require()` in `NodeVM` enforces path restrictions through `isPathAllowed` (`lib/resolver-compat.js`), which resolves symlinks before the `rootPaths` prefix check and denies vm2's own package outright; note that `isPathAllowed` returns `true` unconditionally when `require.root` is left unset.

### Detection Rules

- **`import()`** expressions -- dynamic imports.
- **`require()`** with path traversal (`../`) targeting files outside allowed paths.
- **Access to `module`, `exports`, `__filename`, `__dirname`** in VM (non-NodeVM) context.
