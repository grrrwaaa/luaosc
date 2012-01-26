
-- add the define OSC_HOST_BIG_ENDIAN for big-endian machines

if PLAT == "Darwin" then
	APR_1_INCLUDE_DIR = "/usr/include/apr-1/"	-- OSX
	APR_1_LIB_DIR = "/usr/lib/"
	APR_1_LIBS = 'apr-1'
end

cpp.shared{
	"osc",
	src = {
		"luaopen_osc.cpp",
	},
	needs = {
		"apr-1",
		"lua",
	},
}
