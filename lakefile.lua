APR_1_INCLUDE_DIR = "/usr/include/apr-1/"	-- OSX
APR_1_LIB_DIR = "/usr/lib/"
APR_1_LIBS = 'apr-1'

cpp.shared{
	"osc",
	src = {
		"luaopen_osc.cpp",
		"oscpack/osc/OscOutboundPacketStream.cpp",
		"oscpack/osc/OscReceivedElements.cpp",
		"oscpack/osc/OscTypes.cpp",
	},
	needs = {
		"apr-1",
	},
}
