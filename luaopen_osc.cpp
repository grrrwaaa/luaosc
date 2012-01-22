/*
Luaclang is a module (loadable library) for the Lua programming language (www.lua.org) providing bindings to the LLVM/Clang APIs (www.llvm.org), in order to control LLVM/Clang from within Lua scripts.
Luaclang is built against the LLVM 2.6 stable release, for Lua 5.1.
Luaclang aims to closely follow the LLVM API, but making use of Lua idioms where possible. 

Luaclang is released under the MIT open source license
@see http://www.opensource.org/licenses/mit-license.php

Copyright (c) 2009 Graham Wakefield & Wesley Smith
http://code.google.com/p/luaclang/

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "lua_glue.h"

/* Apache Portable Runtime */
#include "apr_general.h"
#include "apr_errno.h"
#include "apr_pools.h"
#include "apr_network_io.h"
#include "apr_time.h"

/* oscpack */
#include "oscpack/osc/OscPacketListener.h"
#include "oscpack/osc/OscOutboundPacketStream.h"

/* for time-tag calculation */
#include <unistd.h>
#include <sys/time.h>

const unsigned long EPOCH = 2208988800ULL; // delta between epoch time and ntp time
const double NTP_SCALE_FRAC = 4294967295.0; // maximum value of the ntp fractional part

// used to ensure 4-byte alignment
static inline long roundup4( long x ) {
    return ((x-1) & (~0x03L)) + 4;
}

// @see http://stackoverflow.com/questions/2641954/create-ntp-time-stamp-from-gettimeofday
void ntp_time(uint64_t * dest) {
	struct timeval tv;
	uint64_t tv_ntp;
	double tv_usecs;
	
	gettimeofday(&tv, NULL);
	tv_ntp = tv.tv_sec + EPOCH;
	
	// convert tv_usec to a fraction of a second
	// next, we multiply this fraction times the NTP_SCALE_FRAC, which represents
	// the maximum value of the fraction until it rolls over to one. Thus,
	// .05 seconds is represented in NTP as (.05 * NTP_SCALE_FRAC)
	tv_usecs = (tv.tv_usec * 1e-6) * NTP_SCALE_FRAC;
	
	// next we take the tv_ntp seconds value and shift it 32 bits to the left. This puts the 
	// seconds in the proper location for NTP time stamps. I recognize this method has an 
	// overflow hazard if used after around the year 2106
	// Next we do a bitwise OR with the tv_usecs cast as a uin32_t, dropping the fractional
	// part
	*dest = ((tv_ntp << 32) | (uint32_t)tv_usecs);
}

// used to ensure network endianness
#ifdef OSC_HOST_BIG_ENDIAN
	static inline void swap(char * a, char * b){}
	static inline void swap16(void * v){}
	static inline void swap32(void * v){}
	static inline void swap64(void * v){}
#else
	static inline void swap(char * a, char * b){ char t=*a; *a=*b; *b=t; }
	static inline void swap16(void * v){	
		char * b = (char *)v;
		swap(b  , b+1);
	}
	static inline void swap32(void * v){	
		char * b = (char *)v;
		swap(b  , b+3);
		swap(b+1, b+2);
	}
	static inline void swap64(void * v){	
		char * b = (char *)v;
		swap(b  , b+7);
		swap(b+1, b+6);
		swap(b+2, b+5);
		swap(b+3, b+4);
	}
#endif

#define OSC_DEFAULT_PORT 7007
#define OSC_DEFAULT_MAXPACKETSIZE 4096

/* APR utility */
static apr_status_t lua_check_apr(lua_State * L, apr_status_t err) {
	char errstr[1024];
	if (err != APR_SUCCESS) {
		apr_strerror(err, errstr, 1024);
		luaL_error(L, "%s\n", errstr);
	}
	return err;
}

/* doesn't throw the error, just pushes it on the stack */
static int lua_status_apr(lua_State * L, apr_status_t err) {
	char errstr[1024];
	if (err != APR_SUCCESS) {
		apr_strerror(err, errstr, 1024);
		lua_pushnil(L);
		lua_pushfstring(L, "%s\n", errstr);
		return 2;
	}
	return 0;
}

/*
	Binding to osc::Blob
*/
#pragma mark osc::Blob
template<> const char * Glue<osc::Blob>::usr_name() { return "Blob"; }
template<> void Glue<osc::Blob>::usr_gc(lua_State * L, osc::Blob * u) { 
	delete u;
}
template<> void Glue<osc::Blob>::usr_mt(lua_State * L) {
	// any method to retrieve the data?
}

/* 
	OSC packet parser 
*/
#pragma mark packet parser
int osc_parsemessage(lua_State * L, const osc::ReceivedMessage & p) {
	lua_newtable(L);
		
	lua_pushstring(L, "addr");
	lua_pushstring(L, p.AddressPattern() ? p.AddressPattern() : "");
	lua_rawset(L, -3);
	
	unsigned long argc = p.ArgumentCount();
	const char *tags   = p.TypeTags() ? p.TypeTags() : "";
	lua_pushstring(L, "types");
	lua_pushstring(L, tags);
	lua_rawset(L, -3);
	
	osc::ReceivedMessageArgumentStream args = p.ArgumentStream();
	
	for(unsigned i=0; i < argc; i++) {
		try {
			switch(tags[i])
			{
				/*
					Standard OSC types
				*/
				case 'f': {
					float v; args >> v;
					lua_pushnumber(L, v);
				} break;
				case 'i': {
					osc::int32 v; args >> v;
					lua_pushinteger(L, v);
				} break;
				case 's': {
					const char * v; args >> v;
					lua_pushstring(L, v);
				} break;
				case 'b': {
					osc::Blob * v = new osc::Blob();
					args >> *v;
					Glue<osc::Blob>::push(L, v);
					
				} break;

				/*
					Non-Standard OSC types
				*/
				case 'h': {
					osc::int64 v; args >> v;
					lua_pushstring(L, "64-bit ints not handled yet");
				} break;

				case 't': {
					osc::TimeTag v; args >> v;
					lua_pushstring(L, "time-tags not handled yet");
				} break;

				case 'd': {
					double v; args >> v;
					lua_pushnumber(L, v);
				} break;
				case 'S': {
					const char * v; args >> v;
					lua_pushstring(L, v);
				} break;
				case 'c': {
					char v; args >> v;
					lua_pushstring(L, &v);
				} break;

				case 'r': {
					osc::RgbaColor v; args >> v;
					lua_pushstring(L, "RGBA-tags not handled yet");
				} break;
				case 'm': {
					osc::MidiMessage v; args >> v;
					lua_pushstring(L, "MIDI-tags not handled yet");
				} break;

				case 'T': {
					args.grahamWantsToIgnoreThisArgument();
					lua_pushboolean(L, true);
				} break;
				case 'F': {
					args.grahamWantsToIgnoreThisArgument();
					lua_pushboolean(L, false);
				} break;
				case 'N': {
					args.grahamWantsToIgnoreThisArgument();
					lua_pushnil(L);
				} break;
				case 'I': {
					args.grahamWantsToIgnoreThisArgument();
					lua_pushnumber(L, 696969);
				} break;

				case '[':
				case ']': {
					args.grahamWantsToIgnoreThisArgument();
					lua_pushstring(L, "[]-tags not handled yet");
				} break;

				default: {
					// q: how to increment args stream??
					args.grahamWantsToIgnoreThisArgument();
					lua_pushnil(L);
				} break;
			}
		
		}
		catch(const osc::WrongArgumentTypeException &e) {
			fprintf(stderr, "Recv.recv: wrong argument in message\n");
			lua_pushnil(L);
		}
		catch(...) {	// all other exceptions
			fprintf(stderr, "Recv.recv: error handling messages\n");
			lua_pushnil(L);
		}	
		lua_rawseti(L, -2, i+1);
	}
	return 1;
}

int osc_parsebundle(lua_State * L, const osc::ReceivedBundle & p) {
	int nret = 0;
	for(osc::ReceivedBundle::const_iterator i=p.ElementsBegin(); i != p.ElementsEnd(); ++i) {
		if(i->IsBundle()) {
			nret += osc_parsebundle(L, osc::ReceivedBundle(*i));
		} else {
			nret += osc_parsemessage(L, osc::ReceivedMessage(*i));
		}
	}
	return nret;
}

int osc_parse(lua_State * L, const char * buf, size_t size) {
	osc::ReceivedPacket p(buf, size);
	if(p.IsBundle()) {
		return osc_parsebundle(L, osc::ReceivedBundle(p));
	} else {
		return osc_parsemessage(L, osc::ReceivedMessage(p));
	}
}


/*
	AprObject (internal superclass)
*/
#pragma mark AprObject

struct AprObject {
	apr_pool_t * pool;
};

template<> const char * Glue<AprObject>::usr_name() { return "AprObject"; }

/*
	osc.Recv
*/
#pragma mark osc.Recv

struct Recv : public AprObject {
	apr_sockaddr_t * sa;
	apr_socket_t * sock;
	apr_port_t port;
};

template<> const char * Glue<Recv>::usr_name() { return "Recv"; }
template<> const char * Glue<Recv>::usr_supername() { return "AprObject"; }

template<> Recv * Glue<Recv>::usr_new(lua_State * L) {
	apr_port_t port = (apr_port_t)luaL_optint(L, 1, OSC_DEFAULT_PORT);
	apr_pool_t * pool;
	lua_check_apr(L, apr_pool_create(&pool, NULL));
	
	/* @see http://dev.ariel-networks.com/apr/apr-tutorial/html/apr-tutorial-13.html */
	// create socket:
	apr_sockaddr_t * sa;
	apr_socket_t * sock;
	
	lua_check_apr(L, apr_sockaddr_info_get(&sa, NULL, APR_INET, port, 0, pool));
	// for TCP, use SOCK_STREAM and APR_PROTO_TCP instead
	lua_check_apr(L, apr_socket_create(&sock, sa->family, SOCK_DGRAM, APR_PROTO_UDP, pool));
	// bind socket to address:
	lua_check_apr(L, apr_socket_bind(sock, sa));
	lua_check_apr(L, apr_socket_opt_set(sock, APR_SO_NONBLOCK, 1));
	
	Recv * u = new Recv();
	u->port = port;
	u->sa = sa;
	u->sock = sock;
	u->pool = pool;
	return u;
}

template<> void Glue<Recv>::usr_gc(lua_State * L, Recv * u) { 
	lua_check_apr(L, apr_socket_close(u->sock));
	apr_pool_destroy(u->pool);
	delete u;
}

static int recv_iter(lua_State * L) {
	Recv * u = Glue<Recv>::to(L, lua_upvalueindex(1));
	apr_size_t maxsize = OSC_DEFAULT_MAXPACKETSIZE; //lua_tointeger(L, lua_upvalueindex(2));
	
	apr_size_t len = maxsize;
	char data[maxsize];
	apr_status_t res = apr_socket_recv(u->sock, data, &len);
	if (res != 0 || len == 0) {
		lua_pushnil(L);
		return 1;
	}
	
	return osc_parse(L, data, len); 
}

static int recv_recv(lua_State * L) {
	Glue<Recv>::checkto(L, 1);
	lua_pushcclosure(L, recv_iter, 1);
	return 1;
}

static int recv_ip(lua_State * L) {
	Recv * u = Glue<Recv>::checkto(L, 1);
	char * ip;
	lua_check_apr(L, apr_sockaddr_ip_get(&ip, u->sa));
	lua_pushstring(L, ip);
	return 1;
}

static int recv_port(lua_State * L) {
	Recv * u = Glue<Recv>::checkto(L, 1);
	lua_pushinteger(L, u->port);
	return 1;
}


/* utility to get my own hostname */
static int recv_host(lua_State * L) {
	Recv * u = Glue<Recv>::checkto(L, 1);
	char hostname[APRMAXHOSTLEN+1];
	lua_check_apr(L, apr_gethostname(hostname, APRMAXHOSTLEN+1, u->pool));
	lua_pushstring(L, hostname);
	return 1;
}

template<> void Glue<Recv>::usr_mt(lua_State * L) {
	lua_pushcfunction(L, recv_ip); lua_setfield(L, -2, "ip");
	lua_pushcfunction(L, recv_port); lua_setfield(L, -2, "port");
	lua_pushcfunction(L, recv_recv); lua_setfield(L, -2, "recv");
	lua_pushcfunction(L, recv_host); lua_setfield(L, -2, "host");
}


/*
	osc.Send
*/
#pragma mark osc.Send

struct Send : public AprObject {
	apr_sockaddr_t * sa;
	apr_socket_t * sock;
	apr_port_t port;
};

template<> const char * Glue<Send>::usr_name() { return "Send"; }
template<> const char * Glue<Send>::usr_supername() { return "AprObject"; }

template<> Send * Glue<Send>::usr_new(lua_State * L) {
	const char * host = luaL_optstring(L, 1, "localhost");
	apr_port_t port = (apr_port_t)luaL_optint(L, 2, OSC_DEFAULT_PORT);
	
	apr_pool_t * pool;
	lua_check_apr(L, apr_pool_create(&pool, NULL));
	
	/* @see http://dev.ariel-networks.com/apr/apr-tutorial/html/apr-tutorial-13.html */
	// create socket:
	apr_sockaddr_t * sa;
	apr_socket_t * sock;
	
	lua_check_apr(L, apr_sockaddr_info_get(&sa, host, APR_INET, port, 0, pool));
	lua_check_apr(L, apr_socket_create(&sock, sa->family, SOCK_DGRAM, APR_PROTO_UDP, pool));
	lua_check_apr(L, apr_socket_connect(sock, sa));
	lua_check_apr(L, apr_socket_opt_set(sock, APR_SO_NONBLOCK, 1));
	
	Send * u = new Send();
	u->port = port;
	u->sa = sa;
	u->sock = sock;
	u->pool = pool;
	return u;
}

template<> void Glue<Send>::usr_gc(lua_State * L, Send * u) { 
	lua_check_apr(L, apr_socket_close(u->sock));
	apr_pool_destroy(u->pool);
	delete u;
}

/*
	-- message:
	send(addr, ...)	
	-- bundle:
	send{ addr, ... }
	-- nested bundles:
	send{ { addr, ... }, { { addr, ... }, { addr, ... }, }, }
*/
static char * packet_write(lua_State * L, int idx, char * buffer, const char * end) {
	char * data = buffer;
	
	// message or bundle?
	if (lua_type(L, idx) == LUA_TTABLE) {
		//printf("bundle\n");
		// bundle:
		// write bundle header
		// bundle header requires 20 bytes (bundle tag, time tag, size)
		if (data + 16 > end) luaL_error(L, "out of memory");
		// bundle:
		sprintf(data, "#bundle");
		data += 8;
		// write time tag:
		// TODO: this only really needs to happen once for nested bundles...
		ntp_time((uint64_t *)data);
		swap64(data);
		data += 8;
		
		// for each item on the stack
		int args = lua_gettop(L) - idx + 1;
		
		//printf("bundle with %d args {\n", args);
		
		for (int i=idx; i < idx+args; i++) {
			
			// if it is a table, then unpack & recurse 
			if (lua_type(L, i) == LUA_TTABLE) {
				
				// cache size ptr
				int32_t * size = (int32_t *)data;
				data += 4;
				char * bundlebegin = data;
					
				// unpack table:
				int nelements = lua_objlen(L, i);
				//printf("bundle arg %d with %d elements\n", i, nelements);
				for (int j=1; j <= nelements; j++) {
					lua_rawgeti(L, i, j);
				}
				
				// RECURSE:
				data = packet_write(L, lua_gettop(L)-nelements+1, data, end);
				
				// done with table:
				lua_pop(L, nelements);
				
				
				// apply size ptr
				*size = data - bundlebegin;
				//printf("} bundle size %d \n", *size);
				swap32(size);
				
				
			} // otherwise not a table; just ignore it.
		}
		
	} else {
	
		const char * addr = luaL_checkstring(L, idx);
		
		unsigned nargs = lua_gettop(L)-idx;
		unsigned addrlen = strlen(addr);
		unsigned addr4 = roundup4(addrlen+1);
		unsigned types4 = roundup4(nargs+2);
		unsigned addrblank = addr4 - addrlen;
		unsigned typesblank = types4 - (nargs+1);
		if (data + addr4 + types4 > end) luaL_error(L, "out of memory");
		
		//printf("nargs %d addrlen %d addrblank %d addr4 %d types4 %d typesblank %d required %d\n", nargs, addrlen, addrblank, addr4, types4, typesblank, addr4 + types4);
		
		// write header:
		memcpy(data, addr, addrlen);
		data += addrlen;
		// fill rest with nulls:
		for(unsigned i=0; i < addrblank; i++) *data++ = '\0';
		//printf("size of address %d (%s)\n", data - buffer, buffer);
		*data++ = ',';			// start of type tags
		for(unsigned i=idx+1; i <= idx+nargs; i++) {
			//printf("index %d (of %d) is type %s\n", i, lua_gettop(L), lua_typename(L, lua_type(L, i)));
			switch(lua_type(L, i)) {
				case LUA_TNUMBER: *data++ = 'f'; break;
				case LUA_TSTRING: *data++ = 's'; break;
				case LUA_TUSERDATA: *data++ = 'b'; break;
				default: 
					luaL_error(L, "cannot send type %s", lua_typename(L, lua_type(L, i)));
			}
		}
		// fill rest with nulls:
		for(unsigned i=0; i < typesblank; i++) *data++ = '\0';
		//printf("types %s\n", data - typeslen);
		//printf("size of header %d (%s)\n", data - buffer, data - types4);
		
		// write body:
		for(unsigned i=idx+1; i <= idx+nargs; i++) {
			switch(lua_type(L, i)) {
				// TODO: any way to explicitly send ints?
				case LUA_TNUMBER: {
					if (data + 4 > end) luaL_error(L, "out of memory");
					*(float *)data = lua_tonumber(L, i);
					swap32(data);
					data += 4;
					break;
				}
				case LUA_TSTRING: {
					const char * str = lua_tostring(L, i);
					unsigned len = strlen(str);
					unsigned str4 = roundup4(len+1);
					unsigned blank = str4-len;
					if (data + str4 > end) luaL_error(L, "out of memory");
					memcpy(data, str, len);
					data += len;
					for(unsigned j=0; j < blank; j++) *data++ = '\0';
					break;
				}
				case LUA_TUSERDATA: {
					// treat as blob... but how to know size?
					unsigned blobsize = lua_objlen(L, i);
					printf("size %d\n", blobsize);
					luaL_error(L, "not yet implemented");
					break;
				}
			}
		}
		
		//printf("size of message %d\n", data - buffer);
	}
	return data;
}

static int send_send(lua_State * L) {
	Send * u = Glue<Send>::checkto(L, 1);
	lua_remove(L, 1);
	
	char buffer[OSC_DEFAULT_MAXPACKETSIZE];
	const char * end = buffer + OSC_DEFAULT_MAXPACKETSIZE;
	
	char * data = packet_write(L, 1, buffer, end);
	apr_size_t size = data - buffer;
	
	//printf("size %d\n", size);
	apr_status_t status = apr_socket_send(u->sock, buffer, &size);
	if (size) {
		lua_pushinteger(L, size);
	} else {
		return lua_status_apr(L, status);
	}
	return 1;
}

static int send_port(lua_State * L) {
	Send * u = Glue<Send>::checkto(L, 1);
	lua_pushinteger(L, u->port);
	return 1;
}

static int send_ip(lua_State * L) {
	Send * u = Glue<Send>::checkto(L, 1);
	char * ip;
	lua_check_apr(L, apr_sockaddr_ip_get(&ip, u->sa));
	lua_pushstring(L, ip);
	return 1;
}

static int send_host(lua_State * L) {
	Send * u = Glue<Send>::checkto(L, 1);
	char * hostname;
	lua_check_apr(L, apr_getnameinfo(&hostname, u->sa, 0));
	lua_pushstring(L, hostname);
	return 1;
}

template<> void Glue<Send>::usr_mt(lua_State * L) {
	lua_pushcfunction(L, send_ip); lua_setfield(L, -2, "ip");
	lua_pushcfunction(L, send_port); lua_setfield(L, -2, "port");
	lua_pushcfunction(L, send_host); lua_setfield(L, -2, "host");
	lua_pushcfunction(L, send_send); lua_setfield(L, -2, "send");
}

/*
	luaopen_osc
*/
#pragma mark luaopen_osc

static int lua_sleep(lua_State * L) {
	apr_interval_time_t t = apr_time_from_sec(luaL_optnumber(L, 1, 0.1));
	apr_sleep(t);
	return 0;
}

static int initialized = 0;

extern "C" int luaopen_osc(lua_State * L) {

	if (!initialized) {
		lua_check_apr(L, apr_initialize());
		initialized = 1;
	}
	
	const char * libname = luaL_optstring(L, 1, "osc");
	struct luaL_reg lib[] = {
		{"sleep", lua_sleep },
		{NULL, NULL},
	};
	luaL_register(L, libname, lib);
	
	Glue<Send>::define(L);	Glue<Send>::register_ctor(L);
	Glue<Recv>::define(L);	Glue<Recv>::register_ctor(L);
	
	return 1;
}
