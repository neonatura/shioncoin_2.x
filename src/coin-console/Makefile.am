AUTOMAKE_OPTIONS = foreign

noinst_PROGRAMS = shcointool
bin_SCRIPTS = shc

if USDE_SERVICE
bin_SCRIPTS += usde

usde: shcointool
	cp -f shcointool usde
endif

if EMC2_SERVICE
bin_SCRIPTS += emc2

emc2: shcointool
	cp -f shcointool emc2
endif

shc: shcointool
	cp -f shcointool shc


console_sources = \
	shcon.c \
	shcon.h \
	shcon_init.c \
	shcon_init.h \
	shcon_term.c \
	shcon_term.h \
	shcon_opt.c \
	shcon_opt.h \
	shcon_log.c \
	shcon_log.h \
	net/net.c \
	net/net.h \
	net/net_conn.c \
	net/net_read.c \
	net/net_write.c \
	key/key.c \
	key/key.h \
	key/key_dat.c \
	key/key_auth.c \
	command/command.c \
	command/command.h \
	command/command_print.c

shcointool_SOURCES = \
	$(console_sources)
shcointool_CFLAGS = -DSHCOIN_CLIENT
shcointool_CXXFLAGS = -DSHCOIN_CLIENT -DOS_LINUX
if STATIC_LIBSHARE
shcointool_LDADD = \
	$(LIBSHARE)/src/share-lib/libshare.a \
	$(LIBSHARE)/src/sexe/libshare_sexe.a
shcointool_CFLAGS += -I$(LIBSHARE)/include
shcointool_CXXFLAGS += -I$(LIBSHARE)/include
endif


if DEBUG
CFLAGS += -g3 
CXXFLAGS += -g3
else
CFLAGS += -O2
CXXFLAGS += -O2
endif


