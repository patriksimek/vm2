fs = require 'fs'
pa = require 'path'
{NodeVM, VMError} = require '../'

if process.argv[2]
	path = require('path').resolve process.argv[2]
	
	console.log "\x1B[90m[vm] creating VM for #{path}\x1B[39m"
	started = Date.now()
	
	try
		NodeVM.file path,
			require: true
			requireExternal: true
			verbose: true
			
		console.log "\x1B[90m[vm] VM created in #{Date.now() - started}ms\x1B[39m"

	catch ex
		if ex instanceof VMError
			console.error "\x1B[31m[vm:error] #{ex.message}\x1B[39m"
		
		else
			stack = ex.stack
			
			if stack
				console.error "\x1B[31m[vm:error] #{stack}\x1B[39m"
			else
				console.error "\x1B[31m[vm:error] #{ex}\x1B[39m"