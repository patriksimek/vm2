# vm2 [![Dependency Status](https://david-dm.org/patriksimek/vm2.png)](https://david-dm.org/patriksimek/vm2) [![NPM version](https://badge.fury.io/js/vm2.png)](http://badge.fury.io/js/vm2) [![Build Status](https://secure.travis-ci.org/patriksimek/vm2.png)](http://travis-ci.org/patriksimek/vm2)

vm2 is a sandbox that can run untrusted code with whitelisted built-in node objects. Securely!

## Features

* Runs untrusted code securely in a single process with your code side by side
* Full control over sandbox's console output
* Sandbox has limited access to process's methods
* Sandbox can require modules (native and external)
* You can limit access to certain (or all) native modules
* You can securely call methods inside sandbox with callbacks
* Is immune to `while (true) {}` (VM only, see docs)
* Is immune to all known methods of attacks
* Coffee-Script support

## How does it work

* It uses internal VM module to create secure context
* It compiles native modules inside a new context
* It overrides native require to control access to modules
* It forces modules (even native ones) to use `use strict`

## Installation

    npm install vm2

## Quick Examples

```javascript
var VM = require('vm2').VM;

var vm = new VM();
vm.run("process.exit()");
```

## Documentation

* [1.x to 2.x changes](#1x-to-2x-changes)
* [VM](#vm)
* [NodeVM](#nodevm)
* [Calling VM's methods](#calling-vms-methods)
* [CLI](#cli)
* [Known Issues](#known-issues)

## 1.x to 2.x changes

`Buffer` class is no longer globally available by default in NodeVM. To make `Buffer` accessible globaly, enable `require` option and make sure `buffer` module is whitelisted. More info in [Known Issues](#known-issues).

## VM

VM is a simple sandbox, without `require` feature, to synchronously run an untrusted code. Only JavaScript built-in objects are available.

**Options:**

* `timeout` - Script timeout in milliseconds. 
* `sandbox` - VM's global object.
* `language` - `javascript` (default) or `coffeescript`

```javascript
var VM = require('vm2').VM;

var options = {
    timeout: 1000,
    sandbox: {}
};

var vm = new VM(options);
vm.run("process.exit()"); // throws ReferenceError: process is not defined
```

You can also retrieve values from VM.

```javascript
var number = vm.run("1337"); // returns 1337
```

**IMPORTANT**: Timeout is only effective on code you run trough `run`. Timeout is NOT effective on any method returned by VM.

## NodeVM

Unlike `VM`, `NodeVM` lets you require modules same way like in regular Node's context.

**Options:**

* `console` - `inherit` to enable console, `redirect` to redirect to events, `off` to disable console (default: `inherit`)
* `sandbox` - VM's global object
* `language` - `javascript` (default) or `coffeescript`
* `require` - `true` to enable `require` method (default: `false`)
* `requireExternal` - `true` to enable `require` of external modules (default: `false`)
* `requireNative` - Array of allowed native modules. (default: all available)
* `requireRoot` - Restricted path where local modules can be required (default: every path)
* `useStrict` - Whether to add `use strict` directive to required modules (default: `true`)

**Available modules:** `assert`, `buffer`, `child_process`, `constants`, `crypto`, `tls`, `dgram`, `dns`, `http`, `https`, `net`, `punycode`, `querystring`, `url`, `domain`, `events`,  `fs`, `path`, `os`, `stream`, `string_decoder`, `timers`, `tty`,  `util`, `sys`, `vm`, `zlib`

**REMEMBER**: The more modules you allow, the more fragile your sandbox becomes.

**IMPORTANT**: Timeout is not effective for NodeVM so it is not immune to `while (true) {}` or similar evil.

```javascript
var NodeVM = require('vm2').NodeVM;

var options = {
	console: 'inherit',
    sandbox: {},
    require: true,
    requireExternal: true,
    requireNative: ['fs', 'path'],
    requireRoot : "./"
};

var vm = new NodeVM(options);
var functionInSandbox = vm.run("module.exports = function(who) { console.log('hello '+ who); }");
```

### Calling VM's methods

Securely call method in sandbox. All arguments except functions are cloned during the process to prevent context leak. Functions are wrapped to secure closures. Buffers are copied.

**IMPORTANT**: Method doesn't check for circular objects! If you send circular structure as an argument, your process will stuck in infinite loop.

**IMPORTANT**: Always use `vm.call` method to call methods or callbacks in sandbox. If you call it directly, you are exposing yourself a risk of main global context leakage!

```javascript
vm.call(functionInSandbox, 'world');
```

### Loading modules by relative path

To load modules by relative path, you must pass full path of the script you're running as a second argument of vm's `run` method. Filename then also shows up in any stack traces produced from the script.

```javascript
vm.run("require('foobar')", "/data/myvmscript.js");
```

## CLI

Before you can use vm2 in command line, install it globally with `npm install vm2 -g`.

```
$ vm2 ./script.js
```

## Known Issues

Allowing `buffer` to be required inside NodeVM may crash your app with `TypeError: Invalid non-string/buffer chunk` errors (reported [here](https://github.com/patriksimek/vm2/issues/22) and [here](https://github.com/patriksimek/vm2/issues/7)). To prevent `buffer` from loading, disable `require` option or remove `buffer` from list of whitelisted native modules. Keep in mind that modules like `fs` or `stream` do require `buffer` internally.

<a name="license" />
## License

Copyright (c) 2014-2015 Patrik Simek

The MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
