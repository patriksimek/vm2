# vm2 [![Dependency Status](https://david-dm.org/patriksimek/vm2.png)](https://david-dm.org/patriksimek/vm2) [![NPM version](https://badge.fury.io/js/vm2.png)](http://badge.fury.io/js/vm2) [![Build Status](https://secure.travis-ci.org/patriksimek/vm2.png)](http://travis-ci.org/patriksimek/vm2)

vm2 is a sandbox that can run untrusted code with whitelisted built-in node objects. Securely!

## Features

* Runs untrusted code securely in a single process with your code side by side
* Full control over sandbox's console output
* Sandbox has limited access to process's methods
* Sandbox can require modules (native and external)
* You can limit access to certain (or all) native modules
* You can securely call methods inside sandbox with parameters
* Timeout on `while (true) {}`
* Is immune to all known methods of attacks

## How does it work

* It uses internal VM module to create secure context
* It compiles native modules inside a new context
* It overrides native require to control access to modules

## Installation

**IMPORTANT: Requires Node.js 0.11.x**

    npm install vm2

## Quick Examples

```javascript
var VM = require('vm2').VM;

var vm = new VM();
vm.run("process.exit()");
```

## VM

VM is a simple sandbox, without `require` feature, to synchronously run an untrusted code. Only JavaScript built-in objects are available.

**Options:**

* `timeout` - Script timeout in milliseconds
* `sandbox` - VM's global object

```javascript
var VM = require('vm2').VM;

var options = {
    timeout: 1000,
    sandbox: {}
};

var vm = new VM(options);
vm.run("process.exit()");
```

## NodeVM

Unlike `VM`, `NodeVM` lets you require modules same way like in regular Node's context.

**Options:**

* `console` - `inherit` to enable console, `redirect` to redirect to events, `off` to disable console (default: `inherit`)
* `sandbox` - VM's global object
* `require` - `true` to enable `require` method (default: `false`)
* `requireExternal` - `true` to enable `require` of external modules (default: `false`)
* `requireNative` - Array of allowed native modules. (default: all available)

**Available modules:** `assert`, `buffer`, `child_process`, `crypto`, `tls`, `dgram`, `dns`, `http`, `https`, `net`, `querystring`, `url`, `domain`, `events`,  `fs`, `path`, `os`, `stream`, `string_decoder`, `timers`, `tty`,  `util`, `sys`, `vm`, `zlib`

Remember: the more modules you allow, the more fragile your sandbox becomes.

```javascript
var NodeVM = require('vm2').NodeVM;

var options = {
	console: 'inherit',
    sandbox: {},
    require: true,
    requireExternal: true,
    requireNative: ['fs', 'path']
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

## CLI

Before you can use vm2 in command line, install it globally with `npm install vm2 -g`.

```
$ vm2 ./script.js
```

<a name="license" />
## License

Copyright (c) 2014 Patrik Simek

The MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
