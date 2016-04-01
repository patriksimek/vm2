global = @
global.global = global.GLOBAL = global.root = global
global.SANDBOX = true

###
Contextify is similar to deep clone, but changes context of all objects to vm's context.
###

contextify = (value, addtoglobal) =>
	'use strict'
	
	# using util of parent
	ut = require 'util'

	switch typeof value
		when 'object'
			if value is null
				o = null
			else if ut.isDate value
				o = new Date value.getTime()
			else if ut.isError value
				o = new Error value.message
			else if ut.isArray value
				o = (contextify i for i in value)
			else if ut.isRegExp value
				o = new RegExp value.source, "#{if value.global then "g" else ""}#{if value.ignoreCase then "i" else ""}#{if value.multiline then "i" else ""}"
			else if ut.isBuffer value
				if @Buffer
					o = new @Buffer value.length
					value.copy o
				else
					o = null
			else
				o = {}
				for key in Object.getOwnPropertyNames value
					desc = Object.getOwnPropertyDescriptor value, key
					desc.value = contextify desc.value if desc.value?
					desc.get = contextify desc.get if desc.get?
					desc.set = contextify desc.set if desc.set?
					Object.defineProperty o, key, desc

		when 'function'
			o = -> value arguments...
		
		when 'undefined'
			o = undefined
			
		else
			o = value
	
	if addtoglobal
		@[addtoglobal] = o

	return o

return contextify
