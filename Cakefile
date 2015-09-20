task 'compile', 'compile sources', ->
	setImmediate -> run [
		'coffee --compile --bare --output ./lib ./src'
	]

task 'watch', 'watch & compile sources', ->
	setImmediate -> run [
		'coffee --compile --bare --watch --output ./lib ./src'
	]

# ---------------

run = (cmds) ->
	procs = []
	for cmd in cmds
		cmd = cmd.split ' '
		
		if process.platform is 'win32'
			cmd.unshift('/c');
			procs.push require('child_process').spawn process.env.comspec, cmd, stdio: 'inherit', cwd: process.cwd()
			
		else
			procs.push require('child_process').spawn cmd.shift(), cmd, stdio: 'inherit', cwd: process.cwd()