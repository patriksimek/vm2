# Contributing to vm2

Thank you for helping keep vm2 secure and useful. This document describes how the project is organised, the tooling we rely on, and the expectations for proposing and reviewing changes.

## Project overview

vm2 provides hardened alternatives to Node.js' `vm` module so that untrusted code can be evaluated with predictable host interactions.

### Top-level entry points

- `index.js` guards against unsupported Node.js versions and re-exports the library surface from `lib/main.js`.
- `lib/main.js` exposes the public API:
  - `VM` – an isolated context for synchronous execution without `require` access.
  - `NodeVM` – a sandbox that emulates Node's module loader with fine-grained `require` controls.
  - `VMScript` – a wrapper around code that handles compilation, caching and compiler selection.
  - `VMFileSystem` – an abstraction used to control what the sandbox may access on disk.
  - `Resolver`/`makeResolverFromLegacyOptions` – helpers that implement module resolution policies.
  - `VMError` – the custom error type raised when sandbox policy is violated.

### Host/sandbox boundary

- `lib/bridge.js` is the core of vm2. It builds the proxy layer that mediates every value crossing between the host and the sandbox. Because it is extremely security-sensitive, changes here must be reviewed carefully.
- `lib/setup-sandbox.js` and `lib/setup-node-sandbox.js` bootstrap the sandbox global scope and wire up bridge helpers depending on whether `VM` or `NodeVM` is being instantiated.
- `lib/events.js` is a sandbox-friendly copy of Node's `events` implementation that is loaded inside the sandbox to avoid leaking host objects.

#### How proxying works

`lib/bridge.js` creates paired proxies for every value that crosses the boundary. Host objects are wrapped before the sandbox can observe them, and sandbox objects are wrapped before the host can observe them. The wrappers:

- Expose only the minimum surface (e.g. whitelisted built-ins, safe function wrappers) while hiding internal properties such as `__proto__`, accessors, or symbols that could reveal the host realm.
- Rebind methods so the `this` value always stays inside the originating realm and cannot be swapped by user code.
- Translate errors thrown in one realm into `VMError` instances where appropriate so the sandbox cannot exploit host-specific error prototypes.
- Mirror primitives directly (numbers, strings, booleans, `null`, `undefined`) because they are immutable and safe.

When values cross repeatedly, the bridge keeps weak maps to avoid wrapping the same object twice. This prevents identity confusion while allowing garbage collection.

#### Security principles for bridge changes

1. **Never expose host constructors or prototypes.** Touching constructors like `Function` or `Object` from the host realm lets sandbox code craft escape gadgets.
2. **Keep realms separated.** Every function that travels across the bridge must be rebound to the destination global (sandbox or host) and flagged so it cannot be invoked with foreign `this` values.
3. **Freeze or clone shared state.** Host arrays, maps, and other mutables should be cloned or proxied so the sandbox cannot mutate shared objects without mediation.
4. **Validate property access.** Property descriptors should be copied with `Object.getOwnPropertyDescriptor` and filtered. Avoid `for...in` or spread on host objects because they can trigger getters.
5. **Treat symbols and accessors with suspicion.** Always vet new language features before exposing them; unknown symbols or iterator protocols often create escape vectors.
6. **Audit third-party integrations.** Optional compilers or user-provided transformers must never be able to see raw host references.

Any modification that touches these guarantees should come with:

- A threat model analysis describing how the change affects the boundary.
- Unit or integration tests that attempt to break the new invariant from sandboxed code.
- Manual verification using the CLI with crafted payloads to confirm the expected blocking behaviour.

#### Common pitfalls

- **Leaking host errors or stack traces.** Ensure thrown errors are converted and sanitised; exposing host stack traces can reveal hidden properties or call sites.
- **Prototype pollution.** When injecting objects into the sandbox, explicitly `Object.freeze` or clone them. Never rely on JSON round-trips for security.
- **Async callbacks.** Timers, promises, and event emitters often re-enter the bridge later. Confirm that callbacks remain wrapped when invoked asynchronously.
- **Regressions from new Node.js versions.** Changes to intrinsic objects (e.g. new built-in symbols) can bypass existing guards. Run tests on the newest LTS as part of reviews.
- **Performance micro-optimisations.** Rewriting bridge code for speed is risky; micro-optimisations can remove necessary checks. Benchmark only after correctness is proven.

### Execution pipeline

- `lib/vm.js` implements the `VM` class. It uses `vm.Script` to compile code, the internal transformer to wrap catch blocks/with statements safely, and enforces timeout/async constraints.
- `lib/nodevm.js` builds on `VM` to emulate Node's module loader, enable (opt-in) access to external modules, and manage console redirection.
- `lib/script.js` represents executable source. It normalises options, selects compilers, caches `vm.Script` instances for reuse, and tracks whether async constructs are present so policy can be enforced.
- `lib/transformer.js` parses user code with Acorn, instruments it to intercept `catch` clauses, `with` statements and async features, and produces nicer syntax errors.
- `lib/compiler.js` resolves requested compilers. JavaScript is passed through unchanged, while CoffeeScript and TypeScript support relies on optional peer dependencies.
- `lib/filesystem.js` supplies the default filesystem implementation and the `VMFileSystem` wrapper that can be customised or mocked in tests.
- `lib/resolver.js` and `lib/resolver-compat.js` implement the pluggable module resolution layer used by `NodeVM`. `lib/resolver.js` contains the new resolver class, while `lib/resolver-compat.js` adapts the legacy options object into resolver instances.

### CLI utilities

- `bin/vm2` starts the command line interface defined in `lib/cli.js`. It creates a `NodeVM`, enables external modules and logs lifecycle information while executing a provided script file.

### Type definitions

- `index.d.ts` exports TypeScript definitions that mirror the runtime API. Update these definitions whenever you add or change public functionality.

### Tests and auxiliary scripts

- `test/` contains the Mocha test suites. `test/vm.js` and `test/nodevm.js` cover the core sandboxes, while `test/compilers.js` exercises optional compiler integrations.
- `test/additional-modules/` provides fixture modules used by the tests.
- `scripts/legacy-test-runner.js` is a self-contained runner kept for historical compatibility.

## Getting started

1. Install an actively supported Node.js release (the package requires Node 6+, but we recommend using the latest LTS).
2. Clone the repository and install dependencies:
   ```sh
   npm install
   ```
3. Create a new branch for your changes:
   ```sh
   git checkout -b feature/your-change
   ```

## Development workflow

- Keep changes focused. vm2 is security-sensitive and large refactors or formatting-only changes are discouraged unless coordinated with the maintainers.
- Prefer small, reviewable commits with descriptive messages.
- When modifying sandbox boundaries (`lib/bridge.js`, setup files, resolver internals), include detailed reasoning and tests demonstrating that escapes are still prevented.
- Update `README.md`, `index.d.ts`, and the changelog (if applicable) when you extend the public API.
- Follow the existing code style enforced by ESLint instead of introducing new conventions.

## Running checks

Use the provided npm scripts from the project root:

- Run the main test suite (skips compiler-dependent tests):
  ```sh
  npm test
  ```
- Run the optional compiler tests (requires `typescript` and `coffee-script` to be available):
  ```sh
  npm run test:compilers
  ```
- Lint the codebase:
  ```sh
  npm run lint
  ```

All tests should pass and lint errors should be fixed before opening a pull request.

## Adding or updating tests

- Place new unit tests alongside related suites under `test/`.
- Prefer the existing Mocha style (`describe`/`it`) and use fixtures under `test/data` or `test/additional-modules` when you need auxiliary files.
- If you add optional features that depend on external packages, guard tests so they skip gracefully when the dependency is missing and document the requirement here.

## Manual testing with the CLI

You can manually reproduce sandbox behaviour by executing a script through the CLI:

```sh
npx vm2 path/to/script.js
```

It spins up a `NodeVM`, allows `require` access to external modules and prints verbose lifecycle messages, making it handy for diagnosing module resolution or policy issues.

## Security disclosures

If you find a vulnerability, follow the responsible disclosure process described in `SECURITY.md` rather than opening a public issue.

## Submitting changes

1. Ensure your branch is up-to-date with `main` and all checks pass.
2. Push your branch and open a pull request describing the change, the reasoning behind it, and any security implications.
3. Be responsive to reviewer feedback. Security-related discussions may take longer so please be patient.
4. After approval, a maintainer will merge your changes. Do not merge your own pull requests unless explicitly authorised.

We appreciate your efforts to keep vm2 robust and secure!