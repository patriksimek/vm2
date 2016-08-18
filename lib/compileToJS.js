const VMError = require('./VMError')

/**
 * Compile code to JS
 * 
 * @param {String} code Code to compile.
 * @param {*} compiler Compiler to use.
 * @return {String} The compiled code.
 */

const compileToJS = function(code, compiler) {
	if ('function' === typeof compiler) return compiler(code);

	switch (compiler) {
		case 'coffeescript':
		case 'coffee-script':
		case 'cs':
		case 'text/coffeescript':
			return require('coffee-script').compile(code, {header: false, bare: true});
		
		case 'javascript':
		case 'java-script':
		case 'js':
		case 'text/javascript':
			return code;
		
		default:
			throw new VMError(`Unsupported compiler '${compiler}'.`);
	}
};

module.exports = compileToJS;