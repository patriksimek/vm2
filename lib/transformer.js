
const {parse: acornParse} = require('acorn');
const {full: acornWalkFull} = require('acorn-walk');

const INTERNAL_STATE_NAME = 'VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL';

function assertType(node, type) {
	if (!node) throw new Error(`None existent node expected '${type}'`);
	if (node.type !== type) throw new Error(`Invalid node type '${node.type}' expected '${type}'`);
	return node;
}

function transformer(args, body, isAsync, isGenerator) {
	let code;
	let argsOffset;
	if (args === null) {
		code = body;
	} else {
		code = isAsync ? '(async function' : '(function';
		if (isGenerator) code += '*';
		code += ' anonymous(';
		code += args;
		argsOffset = code.length;
		code += '\n) {\n';
		code += body;
		code += '\n})';
	}

	const ast = acornParse(code, {
		__proto__: null,
		ecmaVersion: 2020,
		allowAwaitOutsideFunction: args === null && isAsync,
		allowReturnOutsideFunction: args === null
	});

	if (args !== null) {
		const pBody = assertType(ast, 'Program').body;
		if (pBody.length !== 1) throw new Error('Invalid arguments');
		const expr = pBody[0];
		if (expr.type !== 'ExpressionStatement') throw new Error('Invalid arguments');
		const func = expr.expression;
		if (func.type !== 'FunctionExpression') throw new Error('Invalid arguments');
		if (func.body.start !== argsOffset + 3) throw new Error('Invalid arguments');
	}

	const insertions = [];
	let hasAsync = false;

	const RIGHT = -100;
	const LEFT = 100;

	acornWalkFull(ast, (node, state, type) => {
		if (type === 'CatchClause') {
			const param = node.param;
			if (param) {
				const name = assertType(param, 'Identifier').name;
				const cBody = assertType(node.body, 'BlockStatement');
				if (cBody.body.length > 0) {
					insertions.push({
						__proto__: null,
						pos: cBody.body[0].start,
						order: RIGHT,
						code: `${name}=${INTERNAL_STATE_NAME}.handleException(${name});`
					});
				}
			}
		} else if (type === 'WithStatement') {
			insertions.push({
				__proto__: null,
				pos: node.object.start,
				order: RIGHT,
				code: INTERNAL_STATE_NAME + '.wrapWith('
			});
			insertions.push({
				__proto__: null,
				pos: node.object.end,
				order: LEFT,
				code: ')'
			});
		} else if (type === 'Identifier') {
			if (node.name === INTERNAL_STATE_NAME) {
				throw new Error('Use of internal vm2 state variable');
			}
		} else if (type === 'ImportExpression') {
			insertions.push({
				__proto__: null,
				pos: node.start,
				order: LEFT,
				code: INTERNAL_STATE_NAME + '.'
			});
		} else if (type === 'Function') {
			if (node.async) hasAsync = true;
		}
	});

	if (insertions.length === 0) return {__proto__: null, code, hasAsync};

	insertions.sort((a, b) => (a.pos == b.pos ? a.order - b.order : a.pos - b.pos));

	let ncode = '';
	let curr = 0;
	for (let i = 0; i < insertions.length; i++) {
		const change = insertions[i];
		ncode += code.substring(curr, change.pos) + change.code;
		curr = change.pos;
	}
	ncode += code.substring(curr);

	return {__proto__: null, code: ncode, hasAsync};
}

exports.INTERNAL_STATE_NAME = INTERNAL_STATE_NAME;
exports.transformer = transformer;
