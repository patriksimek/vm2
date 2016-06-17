# vm2 [![NPM Version][npm-image]][npm-url] [![Package Quality][quality-image]][quality-url] [![Travis CI][travis-image]][travis-url]

vm2 is a sandbox that can run untrusted code with whitelisted built-in node objects. Securely!

**Features**

* Runs untrusted code securely in a single process with your code side by side
* Full control over sandbox's console output
* Sandbox has limited access to process's methods
* Sandbox can require modules (native and external)
* You can limit access to certain (or all) native modules
* You can securely call methods and exchange data and callback between sandboxes
* Is immune to `while (true) {}` (VM only, see docs)
* Is immune to all known methods of attacks
* Transpilers support

**How does it work**

* It uses internal VM module to create secure context
* It uses [Proxies](https://developer.mozilla.org/cs/docs/Web/JavaScript/Reference/Global_Objects/Proxy) to prevent escaping the sandbox
* It overrides native require to control access to modules

## Installation

**IMPORTANT**: Requires Node.js 6 or newer.

    npm install vm2

## Quick Example

```javascript
const {VM} = require('vm2');

const vm = new VM();
vm.run("process.exit()");
```

## Documentation

* [VM](#vm)
* [NodeVM](#nodevm)
* [CLI](#cli)
* [2.x to 3.x changes](https://github.com/patriksimek/vm2/wiki/1.x-and-2.x-changes)
* [1.x and 2.x docs](https://github.com/patriksimek/vm2/wiki/1.x-and-2.x-docs)

## VM

VM is a simple sandbox, without `require` feature, to synchronously run an untrusted code. Only JavaScript built-in objects + Buffer are available.

**Options:**

* `timeout` - Script timeout in milliseconds. 
* `sandbox` - VM's global object.
* `compiler` - `javascript` (default) or `coffeescript` or custom compiler function

**IMPORTANT**: Timeout is only effective on code you run through `run`. Timeout is NOT effective on any method returned by VM.

```javascript
const {VM} = require('vm2');

const vm = new VM({
    timeout: 1000,
    sandbox: {}
});

vm.run("process.exit()"); // throws ReferenceError: process is not defined
```

You can also retrieve values from VM.

```javascript
let number = vm.run("1337"); // returns 1337
```

**TIP**: See test for more usage examples.

## NodeVM

Unlike `VM`, `NodeVM` lets you require modules same way like in regular Node's context.

**Options:**

* `console` - `inherit` to enable console, `redirect` to redirect to events, `off` to disable console (default: `inherit`)
* `sandbox` - VM's global object
* `compiler` - `javascript` (default) or `coffeescript` or custom compiler function
* `require` - `true` or object to enable `require` method (default: `false`)
* `require.external` - `true` to enable `require` of external modules (default: `false`)
* `require.native` - Array of allowed native modules (default: none)
* `require.root` - Restricted path where local modules can be required (default: every path)
* `nesting` - `true` to enable VMs nesting (default: `false`)

**IMPORTANT**: Timeout is not effective for NodeVM so it is not immune to `while (true) {}` or similar evil.

**REMEMBER**: The more modules you allow, the more fragile your sandbox becomes.

```javascript
const {NodeVM} = require('vm2');

const vm = new NodeVM({
	console: 'inherit',
    sandbox: {},
    require: {
        external: true,
        native: ['fs', 'path'],
        root: "./"
    }
});

let functionInSandbox = vm.run("module.exports = function(who) { console.log('hello '+ who); }");
functionInSandbox('world');
```

**TIP**: See test for more usage examples.

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

## License

Copyright (c) 2014-2016 Patrik Simek

The MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

[npm-image]: https://img.shields.io/npm/v/vm2.svg?style=flat-square
[npm-url]: https://www.npmjs.com/package/vm2
[quality-image]: http://npm.packagequality.com/shield/vm2.svg?style=flat-square
[quality-url]: http://packagequality.com/#?package=vm2
[travis-image]: https://img.shields.io/travis/patriksimek/vm2/master.svg?style=flat-square&label=unit
[travis-url]: https://travis-ci.org/patriksimek/vm2
