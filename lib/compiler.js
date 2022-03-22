'use strict';

const {
	VMError
} = require('./bridge');


/**
 * Remove the shebang from source code.
 *
 * @private
 * @param {string} code - Code from which to remove the shebang.
 * @return {string} code without the shebang.
 */
function removeShebang(code) {
	if (!code.startsWith('#!')) return code;
	return '//' + code.substring(2);
}


/**
 * The JavaScript compiler, just a identity function.
 *
 * @private
 * @type {compileCallback}
 * @param {string} code - The JavaScript code.
 * @param {string} filename - Filename of this script.
 * @return {string} The code.
 */
function jsCompiler(code, filename) {
	return removeShebang(code);
}

/**
 * Look up the compiler for a specific name.
 *
 * @private
 * @param {(string|compileCallback)} compiler - A compile callback or the name of the compiler.
 * @return {compileCallback} The resolved compiler.
 * @throws {VMError} If the compiler is unknown or the coffee script module was needed and couldn't be found.
 */
function lookupCompiler(compiler) {
	if ('function' === typeof compiler) return compiler;
	switch (compiler) {
		case 'javascript':
		case 'java-script':
		case 'js':
		case 'text/javascript':
			return jsCompiler;
		default:
			throw new VMError(`Unsupported compiler '${compiler}'.`);
	}
}

exports.removeShebang = removeShebang;
exports.lookupCompiler = lookupCompiler;
