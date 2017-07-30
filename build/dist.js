const fs = require('fs');
const uglify = require("uglify-es");

const version = require('../package.json').version;
const contextify = fs.readFileSync(`${__dirname}/../lib/contextify.js`).toString();
const main = fs.readFileSync(`${__dirname}/../lib/main.js`).toString();
const sandbox = fs.readFileSync(`${__dirname}/../lib/sandbox.js`).toString();
const vm = fs.readFileSync(`${__dirname}/../lib/vm.js`).toString();

function pack(code) {
	return uglify.minify(code, {parse: {bare_returns: true}}).code.replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

fs.writeFileSync(`${__dirname}/../dist/vm2.js`, `/*!
 * vm2 ${version}
 * https://github.com/patriksimek/vm2

 * Released under the MIT license
 * http://simdom.org/license
*/

window.vm2 = {};
((exports, require, __dirname, Buffer) => {
	${main}
})(vm2, (module) => {
	switch (module) {
		case 'fs': return {
			readFileSync(path) {
				switch (path) {
					case './contextify.js': return "${pack(contextify)}";
					case './sandbox.js': return "${pack(sandbox)}";
					default: throw new Error('File '+ path +' not present.');
				}
			}
		};
		case 'path': return {
			resolve(path) {
				return path;
			}
		};
		case 'events': return {
			EventEmitter: class EventEmitter {}
		};
		case 'vm':
			const wrapper = {exports: {}};
			((module, exports) => {
				${vm}
			})(wrapper, wrapper.exports);
			return wrapper.exports;

		default: throw new Error('Module '+ module +' not present.');
	}
}, '.', class Buffer {});
`);