import { EventEmitter } from 'events';
import fs from 'fs';
import pa from 'path';

/**
 * Interface for nodes fs module
 */
export interface VMFS {
  /** Implements fs.statSync */
  statSync: typeof fs.statSync;
  /** Implements fs.readFileSync */
  readFileSync: typeof fs.readFileSync;
}

/**
 * Interface for nodes path module
 */
export interface VMPath {
  /** Implements path.resolve */
  resolve: typeof pa.resolve;
  /** Implements path.isAbsolute */
  isAbsolute: typeof pa.isAbsolute;
  /** Implements path.join */
  join: typeof pa.join;
  /** Implements path.basename */
  basename: typeof pa.basename;
  /** Implements path.dirname */
  dirname: typeof pa.dirname;
}

/**
 * Custom file system which abstracts functions from node's fs and path modules.
 */
export interface VMFileSystemInterface extends VMFS, VMPath {
  /** Implements (sep) => sep === path.sep */
  isSeparator(char: string): boolean;
}

/**
 * Implementation of a default file system.
 */
export class VMFileSystem implements VMFileSystemInterface {
  constructor(options?: { fs?: VMFS, path?: VMPath });
  /** Implements fs.statSync */
  statSync: typeof fs.statSync;
  /** Implements fs.readFileSync */
  readFileSync: typeof fs.readFileSync;
  /** Implements path.resolve */
  resolve: typeof pa.resolve;
  /** Implements path.isAbsolute */
  isAbsolute: typeof pa.isAbsolute;
  /** Implements path.join */
  join: typeof pa.join;
  /** Implements path.basename */
  basename: typeof pa.basename;
  /** Implements path.dirname */
  dirname: typeof pa.dirname;
  /** Implements (sep) => sep === path.sep */
  isSeparator(char: string): boolean;
}

export type BuiltinLoad = (vm: NodeVM) => any;
export type Builtin = BuiltinLoad | {init: (vm: NodeVM)=>void, load: BuiltinLoad};
export type Builtins = Map<string, Builtin>;
export type HostRequire = (id: string) => any;
export type JSONValue = null | boolean | number | string | readonly JSONValue[] | {[key: string]: JSONValue};
export interface Package {
  name: JSONValue,
  main: JSONValue,
  exports: JSONValue,
  imports: JSONValue,
  type: JSONValue
};

export function makeBuiltins(builtins: string[], hostRequire: HostRequire): Builtins;
export function makeBuiltinsFromLegacyOptions(builtins: string[], hostRequire: HostRequire, mocks?: {[key: string]: any}, overrides?: {[key: string]: Builtin}): Builtins;
export function makeResolverFromLegacyOptions(options: VMRequire, override?: {[key: string]: Builtin}, compiler?: CompilerFunction): Resolver;

export abstract class Resolver {
  constructor(readonly fs: VMFileSystemInterface, readonly globalPaths: readonly string[], readonly builtins: Builtins);
  init(vm: NodeVM): void;
  abstract isPathAllowed(path: string): boolean;
	checkAccess(mod: any, filename: string): void;
	pathIsRelative(path: string): boolean;
	pathIsAbsolute(path: string): boolean;
	lookupPaths(mod: any, id: string): readonly string[];
	getBuiltinModulesList(vm: NodeVM): readonly string[];
	loadBuiltinModule(vm: NodeVM, id: string): any;
	makeExtensionHandler(vm: NodeVM, name: string): (mod: any, filename: string) => void;
	getExtensions(vm: NodeVM): {[key: string]: (mod: any, filename: string) => void};
	loadJS(vm: NodeVM, mod: any, filename: string): void;
	loadJSON(vm: NodeVM, mod: any, filename: string): void;
	loadNode(vm: NodeVM, mod: any, filename: string): void;
	registerModule(mod: any, filename: string, path: string, parent: any, direct: boolean): void;
	resolve(mod: any, id: string, options: {paths?: readonly string[], unsafeOptions: any}, extList: readonly string[], direct: boolean): string;
	resolveFull(mod: any, id: string, options: {paths?: readonly string[], unsafeOptions: any}, extList: readonly string[], direct: boolean): string;
	genLookupPaths(path: string): readonly string[];
}

export abstract class DefaultResolver extends Resolver {
  private packageCache: Map<string, Package | false>;
  private scriptCache: Map<string, VMScript>;
  constructor(fs: VMFileSystemInterface, globalPaths: readonly string[], builtins: Builtins);
  getCompiler(filename: string): CompilerFunction;
	isStrict(filename: string): boolean;
	readScript(filename: string): string;
	customResolve(id: string, path: string, extList: readonly string[]): string | undefined;
	loadAsFileOrDirectory(x: string, extList: readonly string[]): string | undefined;
	tryFile(x: string): string | undefined;
	tryWithExtension(x: string, extList: readonly string[]): string | undefined;
	readPackage(path: string): Package | undefined;
	readPackageScope(path: string): {data?: Package, scope?: string};
	// LOAD_AS_FILE(X)
	loadAsFile(x: string, extList: readonly string[]): string | undefined;
	// LOAD_INDEX(X)
	loadIndex(x: string, extList: readonly string[]): string | undefined;
	// LOAD_AS_DIRECTORY(X)
	loadAsPackage(x: string, pack: Package | undefined, extList: readonly string[]): string | undefined;
	// LOAD_AS_DIRECTORY(X)
	loadAsDirectory(x: string, extList: readonly string[]): string | undefined;
	// LOAD_NODE_MODULES(X, START)
	loadNodeModules(x: string, dirs: readonly string[], extList: readonly string[]): string | undefined;
	// LOAD_PACKAGE_IMPORTS(X, DIR)
	loadPackageImports(x: string, dir: string, extList: readonly string[]): string | undefined;
	// LOAD_PACKAGE_EXPORTS(X, DIR)
	loadPackageExports(x: string, dir: string, extList: readonly string[]): string | undefined;
	// LOAD_PACKAGE_SELF(X, DIR)
	loadPackageSelf(x: string, dir: string, extList: readonly string[]): string | undefined;
	// RESOLVE_ESM_MATCH(MATCH)
	resolveEsmMatch(match: string, x: string, extList: readonly string[]): string;
	// PACKAGE_EXPORTS_RESOLVE(packageURL, subpath, exports, conditions)
	packageExportsResolve(packageURL: string, subpath: string, rexports: JSONValue, conditions: readonly string[], extList: readonly string[]): string;
	// PACKAGE_IMPORTS_EXPORTS_RESOLVE(matchKey, matchObj, packageURL, isImports, conditions)
	packageImportsExportsResolve(matchKey: string, matchObj: {[key: string]: JSONValue}, packageURL: string, isImports: boolean, conditions: readonly string[], extList: readonly string[]): string | undefined | null;
	// PATTERN_KEY_COMPARE(keyA, keyB)
	patternKeyCompare(keyA: string, keyB: string): number;
	// PACKAGE_TARGET_RESOLVE(packageURL, target, subpath, pattern, internal, conditions)
	packageTargetResolve(packageURL: string, target: JSONValue, subpath: string, pattern: boolean, internal: boolean, conditions: readonly string[], extList: readonly string[]): string | undefined | null;
	// PACKAGE_RESOLVE(packageSpecifier, parentURL)
	packageResolve(packageSpecifier: string, parentURL: string, conditions: readonly string[], extList: readonly string[]): string;
}

/**
 *  Require options for a VM
 */
export interface VMRequire {
  /**
   * Array of allowed built-in modules, accepts ["*"] for all. Using "*" increases the attack surface and potential
   * new modules allow to escape the sandbox. (default: none)
   */
  builtin?: readonly string[];
  /*
   * `host` (default) to require modules in host and proxy them to sandbox. `sandbox` to load, compile and
   * require modules in sandbox. Built-in modules except `events` always required in host and proxied to sandbox
   */
  context?: "host" | "sandbox";
  /** `true`, an array of allowed external modules or an object with external options (default: `false`) */
  external?: boolean | readonly string[] | { modules: readonly string[], transitive: boolean };
  /** Array of modules to be loaded into NodeVM on start. */
  import?: readonly string[];
  /** Restricted path(s) where local modules can be required (default: every path). */
  root?: string | readonly string[];
  /** Collection of mock modules (both external or built-in). */
  mock?: any;
  /* An additional lookup function in case a module wasn't found in one of the traditional node lookup paths. */
  resolve?: (moduleName: string, parentDirname: string) => string | { path: string, module?: string } | undefined;
  /** Custom require to require host and built-in modules. */
  customRequire?: (id: string) => any;
  /** Load modules in strict mode. (default: true) */
  strict?: boolean;
  /** FileSystem to load files from */
  fs?: VMFileSystemInterface;
}

/**
 * A custom compiler function for all of the JS that comes
 * into the VM
 */
export type CompilerFunction = (code: string, filename: string) => string;

/**
 *  Options for creating a VM
 */
export interface VMOptions {
  /**
   * `javascript` (default) or `coffeescript` or custom compiler function (which receives the code, and it's file path).
   *  The library expects you to have coffee-script pre-installed if the compiler is set to `coffeescript`.
   */
  compiler?: "javascript" | "coffeescript" | CompilerFunction;
  /** VM's global object. */
  sandbox?: any;
  /**
   * Script timeout in milliseconds.  Timeout is only effective on code you run through `run`.
   * Timeout is NOT effective on any method returned by VM.
   */
  timeout?: number;
  /**
   * If set to `false` any calls to eval or function constructors (`Function`, `GeneratorFunction`, etc.) will throw an
   * `EvalError` (default: `true`).
   */
  eval?: boolean;
  /**
   * If set to `false` any attempt to compile a WebAssembly module will throw a `WebAssembly.CompileError` (default: `true`).
   */
  wasm?: boolean;
  /**
   * If set to `true` any attempt to run code using async will throw a `VMError` (default: `false`).
   * @deprecated Use `allowAsync` instead.
   */
  fixAsync?: boolean;

  /**
   * If set to `false` any attempt to run code using async will throw a `VMError` (default: `true`).
   */
  allowAsync?: boolean;
}

/**
 *  Options for creating a NodeVM
 */
export interface NodeVMOptions extends VMOptions {
  /** `inherit` to enable console, `redirect` to redirect to events, `off` to disable console (default: `inherit`). */
  console?: "inherit" | "redirect" | "off";
  /** `true` or an object to enable `require` options (default: `false`). */
  require?: boolean | VMRequire | Resolver;
  /**
   * **WARNING**: This should be disabled. It allows to create a NodeVM form within the sandbox which could return any host module.
   * `true` to enable VMs nesting (default: `false`).
   */
  nesting?: boolean;
  /** `commonjs` (default) to wrap script into CommonJS wrapper, `none` to retrieve value returned by the script. */
  wrapper?: "commonjs" | "none";
  /** File extensions that the internal module resolver should accept. */
  sourceExtensions?: readonly string[];
  /**
   * Array of arguments passed to `process.argv`.
   * This object will not be copied and the script can change this object.
   */
  argv?: string[];
  /**
   * Environment map passed to `process.env`.
   * This object will not be copied and the script can change this object.
   */
  env?: any;
  /** Run modules in strict mode. Required modules are always strict. */
  strict?: boolean;
}

/**
 * VM is a simple sandbox, without `require` feature, to synchronously run an untrusted code.
 * Only JavaScript built-in objects + Buffer are available. Scheduling functions
 * (`setInterval`, `setTimeout` and `setImmediate`) are not available by default.
 */
export class VM {
  constructor(options?: VMOptions);
  /** Direct access to the global sandbox object */
  readonly sandbox: any;
  /** Timeout to use for the run methods */
  timeout?: number;
  /** Runs the code */
  run(script: string | VMScript, options?: string | { filename?: string }): any;
  /** Runs the code in the specific file */
  runFile(filename: string): any;
  /** Loads all the values into the global object with the same names */
  setGlobals(values: any): this;
  /** Make a object visible as a global with a specific name */
  setGlobal(name: string, value: any): this;
  /** Get the global object with the specific name */
  getGlobal(name: string): any;
  /** Freezes the object inside VM making it read-only. Not available for primitive values. */
  freeze(object: any, name?: string): any;
  /** Freezes the object inside VM making it read-only. Not available for primitive values. */
  readonly(object: any): any;
  /** Protects the object inside VM making impossible to set functions as it's properties. Not available for primitive values */
  protect(object: any, name?: string): any;
}

/**
 * A VM with behavior more similar to running inside Node.
 */
export class NodeVM extends EventEmitter implements VM {
  constructor(options?: NodeVMOptions);

  /** Require a module in VM and return it's exports. */
  require(module: string): any;

  /**
   * Create NodeVM and run code inside it.
   *
   * @param {string} script JavaScript code.
   * @param {string} [filename] File name (used in stack traces only).
   * @param {Object} [options] VM options.
   */
  static code(script: string, filename?: string, options?: NodeVMOptions): any;

  /**
   * Create NodeVM and run script from file inside it.
   *
   * @param {string} [filename] File name (used in stack traces only).
   * @param {Object} [options] VM options.
   */
  static file(filename: string, options?: NodeVMOptions): any;

  /** Direct access to the global sandbox object */
  readonly sandbox: any;
  /** Only here because of implements VM. Does nothing. */
  timeout?: number;
  /** The resolver used to resolve modules */
  readonly resolver: Resolver;
  /** Runs the code */
  run(js: string | VMScript, options?: string | { filename?: string, wrapper?: "commonjs" | "none", strict?: boolean }): any;
  /** Runs the code in the specific file */
  runFile(filename: string): any;
  /** Loads all the values into the global object with the same names */
  setGlobals(values: any): this;
  /** Make a object visible as a global with a specific name */
  setGlobal(name: string, value: any): this;
  /** Get the global object with the specific name */
  getGlobal(name: string): any;
  /** Freezes the object inside VM making it read-only. Not available for primitive values. */
  freeze(object: any, name?: string): any;
  /** Freezes the object inside VM making it read-only. Not available for primitive values. */
  readonly(object: any): any;
  /** Protects the object inside VM making impossible to set functions as it's properties. Not available for primitive values */
  protect(object: any, name?: string): any;
}

/**
 * You can increase performance by using pre-compiled scripts.
 * The pre-compiled VMScript can be run later multiple times. It is important to note that the code is not bound
 * to any VM (context); rather, it is bound before each run, just for that run.
 */
export class VMScript {
  constructor(code: string, path: string, options?: {
    lineOffset?: number;
    columnOffset?: number;
    compiler?: "javascript" | "coffeescript" | CompilerFunction;
  });
  constructor(code: string, options?: {
    filename?: string,
    lineOffset?: number;
    columnOffset?: number;
    compiler?: "javascript" | "coffeescript" | CompilerFunction;
  });
  readonly code: string;
  readonly filename: string;
  readonly lineOffset: number;
  readonly columnOffset: number;
  readonly compiler: "javascript" | "coffeescript" | CompilerFunction;
  /**
   * Wraps the code
   * @deprecated
   */
  wrap(prefix: string, postfix: string): this;
  /** Compiles the code. If called multiple times, the code is only compiled once. */
  compile(): this;
}

/** Custom Error class */
export class VMError extends Error { }
