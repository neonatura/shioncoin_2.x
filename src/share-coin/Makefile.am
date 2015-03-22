AUTOMAKE_OPTIONS = foreign
LDFLAGS = \
	-lboost_system -lboost_filesystem -lboost_thread \
	-ldb_cxx -ldl 

INCLUDES = -I$(top_srcdir)/src/share-ssl-lib/$(OPENSSL_DIR)/include \
	-I$(top_srcdir)/src/share-lib \
	-I$(top_srcdir)/src/share-coin/leveldb \
	-I$(top_srcdir)/src/share-coin/leveldb

common_includes = \
	$(top_builddir)/config.h \
	$(top_srcdir)/src/share-lib/share.h \
	$(top_srcdir)/src/share-lib/mem/shmem.h \
	$(top_srcdir)/src/share-lib/sherr.h \
	$(top_srcdir)/src/share-lib/share_base.h \
	$(top_srcdir)/src/share-lib/shpeer.h \
	$(top_srcdir)/src/share-lib/shtime.h \
	$(top_srcdir)/src/share-lib/shpref.h \
	$(top_srcdir)/src/share-lib/shcrc.h \
	$(top_srcdir)/src/share-lib/shfile.h \
	$(top_srcdir)/src/share-lib/fs/shfs.h \
	$(top_srcdir)/src/share-lib/delta/xdelta3.h \
	$(top_srcdir)/src/share-lib/net/shnet.h \
	server/addrman.h \
	server/allocators.h \
	server/base58.h \
	server/bignum.h \
	server/bitcoinrpc.h \
	server/checkpoints.h \
	server/compat.h \
	server/crypter.h \
	server/db.h \
	server/init.h \
	server/key.h \
	server/keystore.h \
	server/leveldb.h \
	server/main.h \
	server/mruset.h \
	server/netbase.h \
	server/net.h \
	server/protocol.h \
	server/script.h \
	server/scrypt.h \
	server/serialize.h \
	server/strlcpy.h \
	server/sync.h \
	server/ui_interface.h \
	server/uint256.h \
	server/util.h \
	server/version.h \
	server/walletdb.h \
	server/wallet.h \
	shcoind_version.h \
	server_iface.h \
	stratum/stratum_message.h \
	stratum/stratum_protocol.h \
	stratum/stratum_user.h \
	stratum/stratum_task.h \
	stratum/stratum.h \
	shcoind_block.h \
	shcoind_rpc.h \
	shcoind.h
common_sources = \
	server/addrman.cpp \
	server/bitcoinrpc.cpp \
	server/checkpoints.cpp \
	server/crypter.cpp \
	server/db.cpp \
	server/init.cpp \
	server/key.cpp \
	server/keystore.cpp \
	server/leveldb.cpp \
	server/main.cpp \
	server/netbase.cpp \
	server/noui.cpp \
	server/protocol.cpp \
	server/rpcdump.cpp \
	server/rpcnet.cpp \
	server/rpcrawtransaction.cpp \
	server/script.cpp \
	server/sync.cpp \
	server/util.cpp \
	server/version.cpp \
	server/wallet.cpp \
	server/walletdb.cpp \
	server/scrypt.c \
	wallet_iface.cpp \
	block_iface.cpp \
	server_iface.cpp \
	shcoind_block.c \
	shcoind_rpc.c
server_sources =
stratum_sources = \
	stratum/stratum_message.c \
	stratum/stratum_protocol.c \
	stratum/stratum_user.c \
	stratum/stratum_task.c

bin_PROGRAMS = shcoin
sbin_PROGRAMS = shcoind

shcoind_SOURCES = \
	$(common_includes) $(common_sources) \
	$(server_sources) $(stratum_sources) \
	shcoind.c \
	shcoind_daemon.c \
	shcoind_daemon.h

shcoind_LDADD = \
	$(top_builddir)/src/share-ssl-lib/libshare_ssl.a \
	libleveldb.a
if STATIC_LIBSHARE
shcoind_LDADD += $(LIBSHARE)/src/share-lib/libshare.a
shcoind_CFLAGS = -I$(LIBSHARE)/include
shcoind_CXXFLAGS = -I$(LIBSHARE)/include
endif

shcoin_SOURCES = shcoind_tool.cpp $(common_includes) $(common_sources)
shcoin_LDADD = \
	$(top_builddir)/src/share-ssl-lib/libshare_ssl.a \
	libleveldb.a
if STATIC_LIBSHARE
shcoin_LDADD += $(LIBSHARE)/src/share-lib/libshare.a
shcoin_CFLAGS = -I$(LIBSHARE)/include
shcoin_CXXFLAGS = -I$(LIBSHARE)/include
endif

noinst_LIBRARIES = libleveldb.a

libleveldb_a_CXXFLAGS = -I$(srcdir)/leveldb/include -I$(srcdir)/leveldb/helpers -I$(srcdir)/leveldb \
	-std=c++0x -DOS_LINUX -DLEVELDB_CSTDATOMIC_PRESENT -DLEVELDB_PLATFORM_POSIX
libleveldb_a_SOURCES = \
	leveldb/db/builder.cc leveldb/db/c.cc leveldb/db/dbformat.cc leveldb/db/db_impl.cc leveldb/db/db_iter.cc leveldb/db/filename.cc leveldb/db/log_reader.cc leveldb/db/log_writer.cc leveldb/db/memtable.cc leveldb/db/repair.cc leveldb/db/table_cache.cc leveldb/db/version_edit.cc leveldb/db/version_set.cc leveldb/db/write_batch.cc leveldb/table/block_builder.cc leveldb/table/block.cc leveldb/table/filter_block.cc leveldb/table/format.cc leveldb/table/iterator.cc leveldb/table/merger.cc leveldb/table/table_builder.cc leveldb/table/table.cc leveldb/table/two_level_iterator.cc leveldb/util/arena.cc leveldb/util/bloom.cc leveldb/util/cache.cc leveldb/util/coding.cc leveldb/util/comparator.cc leveldb/util/crc32c.cc leveldb/util/env.cc leveldb/util/env_posix.cc leveldb/util/env_win.cc leveldb/util/filter_policy.cc leveldb/util/hash.cc leveldb/util/histogram.cc leveldb/util/logging.cc leveldb/util/options.cc leveldb/util/status.cc leveldb/port/port_posix.cc leveldb/helpers/memenv/memenv.cc


if HAVE_INITD_DIR
EXTRA_DIST = $(top_builddir)/scripts/initd/shcoind

install-exec-hook:
	rm -f $(INITD_DIR)/init.d/shcoind  
	rm -f $(INITD_DIR)/rc3.d/S87shcoind  
	rm -f $(INITD_DIR)/rc3.d/K87shcoind  
	rm -f $(INITD_DIR)/rc4.d/S87shcoind  
	rm -f $(INITD_DIR)/rc4.d/K87shcoind  
	rm -f $(INITD_DIR)/rc5.d/S87shcoind  
	rm -f $(INITD_DIR)/rc5.d/K87shcoind  
	cp $(top_builddir)/scripts/initd/shcoind $(INITD_DIR)/init.d/
	cd $(INITD_DIR)/rc3.d && $(LN_S) ../init.d/shcoind S87shcoind
	cd $(INITD_DIR)/rc3.d && $(LN_S) ../init.d/shcoind K87shcoind
	cd $(INITD_DIR)/rc4.d && $(LN_S) ../init.d/shcoind S87shcoind
	cd $(INITD_DIR)/rc4.d && $(LN_S) ../init.d/shcoind K87shcoind
	cd $(INITD_DIR)/rc5.d && $(LN_S) ../init.d/shcoind S87shcoind
	cd $(INITD_DIR)/rc5.d && $(LN_S) ../init.d/shcoind K87shcoind

uninstall-hook:
	rm -f $(INITD_DIR)/init.d/shcoind  
	rm -f $(INITD_DIR)/rc3.d/S87shcoind  
	rm -f $(INITD_DIR)/rc3.d/K87shcoind  
	rm -f $(INITD_DIR)/rc4.d/S87shcoind  
	rm -f $(INITD_DIR)/rc4.d/K87shcoind  
	rm -f $(INITD_DIR)/rc5.d/S87shcoind  
	rm -f $(INITD_DIR)/rc5.d/K87shcoind  
endif

CXXFLAGS = -I$(srcdir)/leveldb/include -I$(srcdir)/leveldb/helpers -I$(srcdir)/leveldb -I$(srcdir)/server \
	-std=c++0x -DOS_LINUX -DLEVELDB_CSTDATOMIC_PRESENT -DLEVELDB_PLATFORM_POSIX

if DEBUG
CFLAGS += -g3 
CXXFLAGS += -g3
else
CFLAGS += -fexpensive-optimizations -ffast-math \
	-fomit-frame-pointer -fstrength-reduce -fthread-jumps -funroll-loops
CXXFLAGS += \
	-fexpensive-optimizations -ffast-math \
	-fomit-frame-pointer -fstrength-reduce -fthread-jumps -funroll-loops
endif

