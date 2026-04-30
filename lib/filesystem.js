'use strict';

const pa = require('path');
const fs = require('fs');

class DefaultFileSystem {

	resolve(path) {
		return pa.resolve(path);
	}

	// SECURITY: Dereferences symlinks before path-prefix root checks.
	// Without this, an attacker can place a symlink inside `require.root`
	// pointing outside it; the lexical resolve() passes the prefix check
	// while Node's native require() follows the symlink. See GHSA-cp6g-6699-wx9c.
	realpath(path) {
		return fs.realpathSync(path);
	}

	isSeparator(char) {
		return char === '/' || char === pa.sep;
	}

	isAbsolute(path) {
		return pa.isAbsolute(path);
	}

	join(...paths) {
		return pa.join(...paths);
	}

	basename(path) {
		return pa.basename(path);
	}

	dirname(path) {
		return pa.dirname(path);
	}

	statSync(path, options) {
		return fs.statSync(path, options);
	}

	readFileSync(path, options) {
		return fs.readFileSync(path, options);
	}

}

class VMFileSystem {

	constructor({fs: fsModule = fs, path: pathModule = pa} = {}) {
		this.fs = fsModule;
		this.path = pathModule;
	}

	resolve(path) {
		return this.path.resolve(path);
	}

	// SECURITY: See DefaultFileSystem.realpath. Custom fs modules that omit
	// realpathSync will surface the missing-method error here, which the
	// resolver translates into a deny-by-default. GHSA-cp6g-6699-wx9c.
	realpath(path) {
		return this.fs.realpathSync(path);
	}

	isSeparator(char) {
		return char === '/' || char === this.path.sep;
	}

	isAbsolute(path) {
		return this.path.isAbsolute(path);
	}

	join(...paths) {
		return this.path.join(...paths);
	}

	basename(path) {
		return this.path.basename(path);
	}

	dirname(path) {
		return this.path.dirname(path);
	}

	statSync(path, options) {
		return this.fs.statSync(path, options);
	}

	readFileSync(path, options) {
		return this.fs.readFileSync(path, options);
	}

}

exports.DefaultFileSystem = DefaultFileSystem;
exports.VMFileSystem = VMFileSystem;
