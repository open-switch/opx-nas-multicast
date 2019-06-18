ACLOCAL_AMFLAGS=-I m4
SUBDIRS = inc

lib_LTLIBRARIES=libopx_nas_multicast.la
COMMON_HARDEN_FLAGS=-fexceptions -fstack-protector-strong -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wall -Wformat -Wformat-security -Werror
C_HARDEN_FLAGS=-Wimplicit-function-declaration
LD_HARDEN_FLAGS=-Wl,-z,defs -Wl,-z,now

libopx_nas_multicast_la_SOURCES= \
                                src/mcast_l3/nas_mc_l3_walker.cpp \
                                src/mcast_l3/nas_mc_repl_grp_db.cpp \
                                src/mcast_l3/nas_mc_l3_msg.cpp \
                                src/mcast_l3/nas_mc_repl_grp.cpp \
                                src/mcast_l3/nas_mc_l3_cps.cpp \
                                src/mcast_l3/nas_mc_l3_ndi.cpp \
                                src/mcast_l3/nas_mc_l3_route_db.cpp \
                                src/mcast_l3/nas_mc_l3_cache.cpp \
                                src/mcast_l3/nas_mc_l3_main.cpp \
                                src/mcast_l3/nas_mc_l3_utils.cpp \
                                src/mcast_snooping/nas_mc_main.cpp \
                                src/mcast_snooping/nas_mc_proc.cpp \
                                src/mcast_snooping/nas_mc_cps.cpp


libopx_nas_multicast_la_CPPFLAGS= -D_FILE_OFFSET_BITS=64 -I$(top_srcdir)/inc/opx -I$(includedir)/opx $(COMMON_HARDEN_FLAGS) -fPIC
libopx_nas_multicast_la_CXXFLAGS=-std=c++11
libopx_nas_multicast_la_CFLAGS= $(C_HARDEN_FLAGS)
libopx_nas_multicast_la_LDFLAGS=-shared -version-info 1:1:0 $(LD_HARDEN_FLAGS)
libopx_nas_multicast_la_LIBADD=-lopx_common -lopx_logging -lopx_cps_api_common -lopx_nas_common -lopx_nas_ndi
