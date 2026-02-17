# vm2

vm2 safely sandboxes untrusted JavaScript code running in Node.js. This is a security-critical project -- every change must be evaluated for sandbox escape potential.

## Public API

Exported from `lib/main.js` via `index.js`:

- **`VM`** -- isolated context for synchronous execution without `require`.
- **`NodeVM`** -- sandbox emulating Node's module loader with fine-grained `require` controls.
- **`VMScript`** -- compilation, caching, and compiler selection wrapper.
- **`VMFileSystem`** -- controls sandbox filesystem access.
- **`VMError`** -- raised when sandbox policy is violated.

## Architecture

### The Boundary (Security-Critical)

| File | Role |
|------|------|
| `lib/bridge.js` | Core proxy layer. Paired proxies for every value crossing host/sandbox. WeakMap caches for identity. Proxy trap handlers (`BaseHandler`, `ProtectedHandler`, `ReadOnlyHandler`). |
| `lib/setup-sandbox.js` | Sandbox bootstrap for `VM`. `handleException`, Promise wrapping, `Symbol.for` override, symbol filtering, `Error.prepareStackTrace` safe default, `WebAssembly.JSTag` deletion. |
| `lib/setup-node-sandbox.js` | Sandbox bootstrap for `NodeVM`. `require`, module resolution, console redirection. |
| `lib/transformer.js` | Acorn parser instrumenting `catch` blocks and `with` statements. **Limitation**: `ecmaVersion: 2022` -- post-ES2022 syntax (e.g., `using`) is invisible. |

### Other Files

| File | Role |
|------|------|
| `lib/vm.js` | `VM` class. Compiles via `vm.Script`, applies transformer, enforces timeout/async. |
| `lib/nodevm.js` | `NodeVM` class. Module loader, external module access, console redirection. |
| `lib/script.js` | `VMScript`. Options, compilers, caching, async detection. |
| `lib/compiler.js` | Compiler resolution (JS passthrough, optional CoffeeScript/TypeScript). |
| `lib/filesystem.js` | `VMFileSystem` implementation. |
| `lib/resolver.js` | Module resolution for `NodeVM`. |
| `lib/events.js` | Sandbox-safe copy of Node's `events`. |

### CLI

```sh
npx vm2 path/to/script.js  # NodeVM with external modules, verbose logging
```

## Security

See [`docs/ATTACKS.md`](docs/ATTACKS.md) for the full catalog of attack patterns, fundamentals of realm separation and V8 internals, and the defense table.

**Key insight**: V8 internal algorithms (ArraySpeciesCreate, FormatStackTrace, PromiseResolveThenableJob) operate on raw objects, bypassing proxy traps. Defenses must neutralize raw objects directly, not just intercept via proxies.

### Principles

1. Never expose host constructors or prototypes.
2. Rebound every function crossing the bridge to the destination realm.
3. Freeze or proxy shared mutable state.
4. Filter property access via `Object.getOwnPropertyDescriptor`. Never `for...in` or spread on host objects.
5. Treat new symbols and language features as suspect until vetted.
6. Cache `Reflect.*` and other critical references at init time.

### Checklist for Boundary Changes

1. Does this expose any new return path for host objects?
2. Can sandbox code call this method directly (not through a proxy)?
3. Does this accept attacker-controlled parameters?
4. Are all `Reflect.*` calls using cached references?
5. Could V8 internal algorithms trigger this path (bypassing traps)?
6. Does this handle host-realm errors that could be thrown?
7. Are there new well-known symbols that need filtering?

## Tests

```sh
npm test                # Main suite (Mocha)
npm run test:compilers  # Optional (needs typescript, coffee-script)
npm run lint            # ESLint
```

- `test/vm.js` -- Main sandbox tests. Uses `makeHelpers()` for proxy boundary checks, `it.cond(name, condition, fn)` for version-gated tests.
- `test/nodevm.js` -- NodeVM module loading tests.
- `test/escape-scanner.js` -- Automated escape scanner. Serializable, runs inside `vm.run()`.

Every security fix must include tests that reproduce the attack, verify the defense, and test bypass variants. Use `it.cond()` for Node version requirements.

Use the `/hacker` skill after making security-related changes to systematically red-team the sandbox and verify it still holds.

## Updating ATTACKS.md

**Every time the library is patched**, update [`docs/ATTACKS.md`](docs/ATTACKS.md):

- Add the attack to the appropriate tier/category (or create a new one).
- Document: attack flow, canonical example, why it works, mitigation, detection rules.
- Update the Compound Attack Patterns and "How The Bridge Defends" table.
- Add new APIs/features to "Considered Attack Surfaces" or "Future Risks".

## Workflow

- Keep changes small and focused. Security-sensitive code discourages large refactors.
- Include threat model reasoning and escape-prevention tests for boundary changes.
- Follow existing ESLint code style.
- Vulnerabilities: follow `SECURITY.md`, not public issues.
