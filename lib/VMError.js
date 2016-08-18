/**
 * VMError.
 * 
 * @param {String} message Error message.
 * 
 * @class
 * @extends {Error}
 * @property {String} stack Call stack.
 * @property {String} message Error message.
 */

class VMError extends Error {
	constructor(message) {
		super(message);
		
		this.name = 'VMError';

		Error.captureStackTrace(this, this.constructor);
	}
}

module.exports = VMError;