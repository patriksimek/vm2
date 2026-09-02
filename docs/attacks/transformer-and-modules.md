# Transformer and Module Loading

Syntax the Acorn transformer (`ecmaVersion: 2022`) cannot see, and the dynamic code and module loading paths. Every future transformer blind spot belongs here.

Defense invariants enforced by fixes in this family: 9, 10 (see [Defense Invariants](../ATTACKS.md#defense-invariants)).

Categories in this file: [12](transformer-and-modules.md#attack-category-12-code-transformation-bypass), [13](transformer-and-modules.md#attack-category-13-dynamic-import-and-module-loading).

---

## Attack Category 12: Code Transformation Bypass

**Advisories**: GHSA-wp5r-2gw5-m7q7

**Tests**: test/ghsa/GHSA-wp5r-2gw5-m7q7/

### Description

vm2's transformer rewrites `catch` blocks and `with` statements to prevent access to host objects through exception variables. Attackers attempt to use reserved internal variable names or bypass the transformation entirely.

### Attack Flow

1. Guess the transformer's internal variable name pattern and use it directly.
2. Or use `eval()` / `new Function()` with dynamically constructed strings to generate code that the transformer never sees.
3. Or use syntax that Acorn's configured `ecmaVersion` does not parse (e.g., `using` declarations in ES2024).

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

### Why It Works

The transformer renames catch clause variables to internal names and wraps them with sanitization. If an attacker can guess or use the internal variable name directly, they bypass the wrapping logic. Additionally, `eval()` and `new Function()` execute dynamically generated code that the transformer never processes. The transformer uses `ecmaVersion: 2022`, so `using` declarations (ES2024) are invisible -- the transformer does not instrument their implicit catch semantics.

### Mitigation

The transformer validates against internal variable name patterns. `eval` and `new Function` are sandbox-scoped (they cannot access host context directly). The fast-path bailout at the top of `transformer()` (which skips AST instrumentation for code containing none of the security-relevant keywords) is conservative: it triggers full AST parse for any source containing `catch`, `import`, `async`, `with`, the `INTERNAL_STATE_NAME` substring, or a `\u` escape sequence (GHSA-wp5r-2gw5-m7q7 plus post-fix unicode-escape hardening — identifiers can be written as `VM2_INTERNAL_…` and would slip past a substring check, so any `\u` in source forces the AST walker to decode and inspect actual identifier names). The `ecmaVersion` limitation remains a known surface — `using` declarations (ES2024) inside `eval()` bypass catch-block instrumentation entirely.

### Detection Rules

- **Variables containing `VM2_INTERNAL`**, `$tmpname`, or similar patterns.
- **`with` statements** — security-sensitive and instrumented.
- **Direct `eval()`** usage — bypasses transformer.
- **`new Function()`** with dynamically constructed strings.
- **`using` or `await using`** inside `eval()` — bypasses transformer's `ecmaVersion: 2022`.
- **Identifiers using `\uXXXX` / `\u{...}` escapes** — recognised legitimate JS, but a vector for evading literal-string identifier checks (handled by the fast-path `\u` bailout in `transformer.js`).

---

## Attack Category 13: Dynamic Import and Module Loading

**Advisories**: none

**Tests**: none linked

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

### Why It Works

Dynamic `import()` returns a Promise created by the host runtime, not the sandbox. Its `.constructor` is the host `Promise`, whose `.constructor` is the host `Function`.

### Mitigation

Dynamic `import()` throws `VMError` unconditionally. `require()` in `NodeVM` enforces path restrictions.

### Detection Rules

- **`import()`** expressions -- dynamic imports.
- **`require()`** with path traversal (`../`) targeting files outside allowed paths.
- **Access to `module`, `exports`, `__filename`, `__dirname`** in VM (non-NodeVM) context.
