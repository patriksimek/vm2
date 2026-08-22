'use strict';

const pa = require('path');

const {NodeVM, VMError} = require('../');

if (process.argv[2]) {
	const path = pa.resolve(process.argv[2]);

	console.log(`\x1B[90m[vm] creating VM for ${path}\x1B[39m`);
	const started = Date.now();

	try {
		NodeVM.file(path, {
			verbose: true,
			require: {
				external: true,
				// SECURITY (GHSA-jxxv-8r27-vm4p): the shipped CLI must not run the target
				// (or its requires) in the host realm. Bound requires to the script's own
				// directory and load them INSIDE the sandbox (context:'sandbox'), so a
				// script that require()s itself or a sibling can't execute in host context.
				root: pa.dirname(path),
				context: 'sandbox'
			}
		});

		console.log(`\x1B[90m[vm] VM completed in ${Date.now() - started}ms\x1B[39m`);
	} catch (ex) {
		if (ex instanceof VMError) {
			console.error(`\x1B[31m[vm:error] ${ex.message}\x1B[39m`);
		} else {
			const {stack} = ex;

			if (stack) {
				console.error(`\x1B[31m[vm:error] ${stack}\x1B[39m`);
			} else {
				console.error(`\x1B[31m[vm:error] ${ex}\x1B[39m`);
			}
		}
	}
}
