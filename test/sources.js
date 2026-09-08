/* eslint-env mocha */

'use strict';

// The sandbox bootstrap files (bridge.js, setup-sandbox.js,
// setup-node-sandbox.js, events.js) are evaluated inside the sandbox's V8
// context via vm.Script, so they have to reach the runtime as *source text*.
// They used to be read from disk with fs.readFileSync(`${__dirname}/...`),
// which single-file bundlers (Bun compile, esbuild, pkg, ...) cannot follow:
// the files never make it into the bundle and __dirname points nowhere useful.
//
// lib/sources.js is a generated CommonJS module that embeds those four files as
// string literals. These tests keep that module honest and keep the disk reads
// from creeping back.

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const LIB_DIR = path.join(__dirname, '..', 'lib');
const EMBEDDED_FILES = ['bridge.js', 'setup-sandbox.js', 'setup-node-sandbox.js', 'events.js'];
// Files that only ever run inside the sandbox. The host never require()s them,
// so a bundle that lacks them must still work end to end.
const SANDBOX_ONLY_FILES = ['setup-sandbox.js', 'setup-node-sandbox.js', 'events.js'];

describe('embedded bootstrap sources', () => {
	it('lib/sources.js is in sync with the bootstrap files on disk', () => {
		const sources = require('../lib/sources');
		assert.deepStrictEqual(Object.keys(sources).sort(), EMBEDDED_FILES.slice().sort());
		for (let i = 0; i < EMBEDDED_FILES.length; i++) {
			const name = EMBEDDED_FILES[i];
			const onDisk = fs.readFileSync(path.join(LIB_DIR, name), 'utf8');
			assert.strictEqual(sources[name], onDisk,
				'lib/sources.js is stale for ' + name + ' -- run `npm run build:sources`');
		}
	});

	it('lib/sources.js is frozen', () => {
		const sources = require('../lib/sources');
		assert.strictEqual(Object.isFrozen(sources), true);
	});

	it('no lib file reads a package file from disk via __dirname', () => {
		const files = fs.readdirSync(LIB_DIR).filter(f => f.slice(-3) === '.js');
		const offenders = [];
		for (let i = 0; i < files.length; i++) {
			const src = fs.readFileSync(path.join(LIB_DIR, files[i]), 'utf8');
			if (/readFileSync\s*\([^)]*__dirname/.test(src)) offenders.push(files[i]);
		}
		assert.deepStrictEqual(offenders, [],
			'these files read package files at runtime, which breaks bundlers: ' + offenders.join(', '));
	});

	it('bootstrap frames stay classified as host frames in sandbox stack traces', () => {
		// The bootstrap scripts are compiled under a fixed virtual filename. The
		// GHSA-v27g / GHSA-x6m4 frame classifiers treat absolute paths as host
		// frames and redact them, so the virtual name must keep looking like one:
		// a sandbox-visible bootstrap frame would leak line/column/function
		// names of the sandbox's own defenses.
		const {VM} = require('..');
		const vm = new VM({sandbox: {hostArray: [1]}});
		const names = vm.run(`
			Error.prepareStackTrace = (err, frames) => frames.map(f => f.getFileName());
			const stacks = [];
			hostArray.map(() => { stacks.push(new Error('x').stack); });
			Promise.resolve().then(() => {});
			stacks;
		`);
		const all = [].concat.apply([], names);
		assert.ok(all.length > 0);
		const leaked = all.filter(n => typeof n === 'string' && /bridge|setup-sandbox|setup-node-sandbox/.test(n));
		assert.deepStrictEqual(leaked, []);
	});

	it('every CallSite accessor on a bootstrap frame is redacted', () => {
		// Red-team sweep: not just getFileName. Every accessor V8 exposes on a
		// CallSite, plus String()/JSON on the wrapper, must come back empty for
		// frames in /vm2/lib/*, whether reached via an array method callback, a
		// host function callback, or the Promise then-wrapper.
		const {VM} = require('..');
		const vm = new VM({sandbox: {hostArray: [1], hostFn(cb) { return cb(); }}});
		const observed = vm.run(`
			const names = ['getThis', 'getTypeName', 'getFunction', 'getFunctionName', 'getMethodName',
				'getFileName', 'getLineNumber', 'getColumnNumber', 'getEvalOrigin', 'isToplevel', 'isEval',
				'isNative', 'isConstructor', 'isAsync', 'isPromiseAll', 'getPromiseIndex',
				'getScriptNameOrSourceURL', 'getScriptHash', 'getEnclosingLineNumber',
				'getEnclosingColumnNumber', 'getPosition', 'toString'];
			const res = [];
			Error.prepareStackTrace = (e, frames) => {
				for (const f of frames) {
					for (const n of names) {
						try { if (typeof f[n] === 'function') res.push(String(f[n]())); } catch (x) { res.push(x.message); }
					}
					try { res.push(String(f)); } catch (x) {}
					try { res.push(JSON.stringify(f)); } catch (x) {}
				}
				return '';
			};
			hostArray.map(() => new Error('a').stack);
			hostFn(() => new Error('b').stack);
			res;
		`);
		assert.ok(observed.length > 0);
		const leaked = observed.filter(v => /vm2\/lib|bridge|setup-sandbox/.test(v));
		assert.deepStrictEqual(leaked, []);
	});

	it('NodeVM require() failures do not expose setup-node-sandbox frames', () => {
		const {NodeVM} = require('..');
		const stacks = new NodeVM().run(`
			const r = [];
			try { require('no-such-module'); } catch (e) { r.push(String(e.stack)); }
			try { require('fs'); } catch (e) { r.push(String(e.stack)); }
			Error.prepareStackTrace = (e, f) => f.map(x => x.getFileName() + ':' + x.getLineNumber()).join(';');
			try { require('no-such-module-2'); } catch (e) { r.push(String(e.stack)); }
			module.exports = r;
		`);
		assert.strictEqual(stacks.length, 3);
		const leaked = stacks.filter(s => /vm2\/lib|setup-node-sandbox|bridge\.js/.test(s));
		assert.deepStrictEqual(leaked, []);
	});

	it('NodeVM cannot require lib/sources.js even with external access to the package root', () => {
		// Same lib/ self-require denial that covers bridge.js and main.js
		// (defense-in-depth for GHSA-j3hm-6rg5-mchv) must cover the new file.
		const {NodeVM} = require('..');
		const root = path.join(__dirname, '..');
		const nodevm = new NodeVM({require: {external: true, root}});
		const specs = ['./lib/sources.js', './lib/sources'];
		for (let i = 0; i < specs.length; i++) {
			assert.throws(
				() => nodevm.run('module.exports = require(' + JSON.stringify(specs[i]) + ')', path.join(root, 'x.js')),
				/Cannot find module/);
		}
	});

	describe('a copy of lib/ without the sandbox-only files', () => {
		// Kept inside the repo (not os.tmpdir()) so that require('acorn') from
		// the copied files still resolves against the project's node_modules.
		const copyRoot = path.join(__dirname, '..', '.tmp-sources-test-' + process.pid);
		const copyLib = path.join(copyRoot, 'lib');
		let vm2;

		before(() => {
			fs.mkdirSync(copyRoot);
			fs.mkdirSync(copyLib);
			const files = fs.readdirSync(LIB_DIR);
			for (let i = 0; i < files.length; i++) {
				if (SANDBOX_ONLY_FILES.indexOf(files[i]) !== -1) continue;
				fs.writeFileSync(path.join(copyLib, files[i]), fs.readFileSync(path.join(LIB_DIR, files[i])));
			}
			vm2 = require(path.join(copyLib, 'main.js'));
		});

		after(() => {
			const files = fs.readdirSync(copyLib);
			for (let i = 0; i < files.length; i++) fs.unlinkSync(path.join(copyLib, files[i]));
			fs.rmdirSync(copyLib);
			fs.rmdirSync(copyRoot);
		});

		it('VM runs', () => {
			assert.strictEqual(new vm2.VM().run('1 + 1'), 2);
		});

		it('NodeVM runs', () => {
			assert.strictEqual(new vm2.NodeVM().run('module.exports = 1 + 1'), 2);
		});

		it('NodeVM serves the sandboxed events module', () => {
			const nodevm = new vm2.NodeVM({require: {builtin: ['events']}});
			const result = nodevm.run(`
				const EventEmitter = require('events');
				const e = new EventEmitter();
				let hits = 0;
				e.on('x', () => hits++);
				e.emit('x');
				module.exports = hits;
			`);
			assert.strictEqual(result, 1);
		});
	});
});
