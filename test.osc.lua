local osc = require "osc"

print(osc)
for k, v in pairs(osc) do print(k, v) end


local s = osc.Send("localhost", 8080)
print(s:host(), s:port(), s:ip())

-- send messages:
--s:send("/fo", 1, 2, 3)	--- float
--s:send("/foo", "a", "aa", "aaa", "aaaa")

-- send bundles:
--[[

PACKET:
		if the first argument on the stack is a string, then it is a message
			send message
		else this is a bundle:
			start a bundle
			for each argument on the stack:
				assert it is a table
				allocate bundle size marker
				unpack the table elements to the stack
					recurse to PACKET:
				pop the elements
				write bundle size to marker
--]]

s:send{ 
	{ "/bee", 3, "four" }, 
	{ "/bim", 66 }, 
	{ "/bap", "a", "aa", "aaa", } 
}

--[[
s:send{ 
	{ "/bar", 1, "two" }, 
	{	-- sub-bundle:
		{ "/bar", 2, "one" }, 
		{ "/bar", 2, "one" }, 
	}
}
--]]
