AUTOMAKE_OPTIONS = foreign

TESTS = test_shcoind

INCLUDES = -I$(top_srcdir)/src/share-ssl-lib/$(OPENSSL_DIR)/include \
	-I$(top_srcdir)/src/share-lib \
	-I$(srcdir)/proto \
	-I$(srcdir)/fractal \
	-I$(srcdir)/server \
	-I$(srcdir)/server/ext \
	-I$(srcdir)/server/blockchain \
	-I$(srcdir)/server/rpc

blockchain_sources = \
	$(srcdir)/blockchain/bc_block.c \
	$(srcdir)/blockchain/bc_index.c \
	$(srcdir)/blockchain/bc_arch.c \
	$(srcdir)/blockchain/bc_fmap.c \
	$(srcdir)/blockchain/bc.h \
	$(srcdir)/blockchain/bc_block.h \
	$(srcdir)/blockchain/bc_index.h \
	$(srcdir)/blockchain/bc_arch.h \
	$(srcdir)/blockchain/bc_arch.h \
	$(srcdir)/blockchain/bc_fmap.h

proto_sources = \
	$(srcdir)/proto/coin_proto.c \
	$(srcdir)/proto/shc_proto.cpp \
	$(srcdir)/proto/usde_proto.cpp \
	$(srcdir)/proto/emc2_proto.cpp \
	$(srcdir)/proto/test_proto.cpp \
	$(srcdir)/proto/coin_proto.h \
	$(srcdir)/proto/shc_proto.h \
	$(srcdir)/proto/usde_proto.h \
	$(srcdir)/proto/emc2_proto.h \
	$(srcdir)/proto/test_proto.h

stratum_sources = \
	stratum/stratum.h \
	stratum/stratum_http.h \
	stratum/stratum_message.h \
	stratum/stratum_protocol.h \
	stratum/stratum_user.h \
	stratum/stratum_task.h \
	stratum/stratum_sync.h \
	stratum/stratum.c \
	stratum/stratum_http.c \
	stratum/stratum_message.c \
	stratum/stratum_protocol.c \
	stratum/stratum_user.c \
	stratum/stratum_task.c \
	stratum/stratum_sync.c

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
	unet/unet.h \
	server/block.h \
	server/coin.h \
	server/chain.h \
	server/global.h \
	server/allocators.h \
	server/base58.h \
	server/bignum.h \
	server/rpc_proto.h \
	server/rpcalias_proto.h \
	server/rpccert_proto.h \
	server/compat.h \
	server/crypter.h \
	server/txidx.h \
	server/init.h \
	server/key.h \
	server/keystore.h \
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
	shcoind_rpc.h \
	shcoind_log.h \
	shcoind_opt.h \
	shcoind_signal.h \
	shcoind_descriptor.h \
	shcoind.h

common_sources = \
	$(blockchain_sources) \
	server/mnemonic.cpp \
	shcoind_rpc.c \
	shcoind_log.c \
	shcoind_opt.c \
	shcoind_signal.c \
	shcoind_descriptor.c \
	unet/unet_accept.c \
	unet/unet_bind.c \
	unet/unet.c \
	unet/unet_close.c \
	unet/unet_connect.c \
	unet/unet.h \
	unet/unet_io.c \
	unet/unet_timer.c \
	unet/unet_peer.c \
	unet/unet_event.c \
	unet/unet_local.c \
	server/base58.cpp \
	server/netbase.cpp \
	server/version.cpp \
	server/util.cpp

server_sources = \
	$(proto_sources) \
	fractal/fractal.c \
	fractal/fractal_bmp.c \
	server/test/test_wallet.cpp \
	server/test/test_wallet.h \
	server/test/test_block.cpp \
	server/test/test_block.h \
	server/shc/shc_netmsg.cpp \
	server/shc/shc_netmsg.h \
	server/shc/shc_block.cpp \
	server/shc/shc_block.h \
	server/shc/shc_wallet.cpp \
	server/shc/shc_wallet.h \
	server/shc/shc_txidx.cpp \
	server/shc/shc_txidx.h \
	server/shc/shc_rpc.cpp \
	server/usde/usde_netmsg.cpp \
	server/usde/usde_netmsg.h \
	server/usde/usde_block.cpp \
	server/usde/usde_block.h \
	server/usde/usde_wallet.cpp \
	server/usde/usde_wallet.h \
	server/usde/usde_txidx.cpp \
	server/usde/usde_txidx.h \
	server/emc2/emc2_txidx.cpp \
	server/emc2/emc2_txidx.h \
	server/emc2/emc2_block.cpp \
	server/emc2/emc2_block.h \
	server/emc2/emc2_wallet.cpp \
	server/emc2/emc2_wallet.h \
	server/emc2/emc2_netmsg.cpp \
	server/emc2/emc2_netmsg.h \
	server/ext/txext.cpp \
	server/ext/alias.cpp \
	server/ext/certificate.cpp \
	server/ext/offer.cpp \
	server/ext/asset.cpp \
	server/ext/exec.cpp \
	server/ext/channel.cpp \
	server/rpc/rpcalias_proto.cpp \
	server/rpc/rpccert_proto.cpp \
	server/rpc/rpcdump.cpp \
	server/rpc/rpcnet.cpp \
	server/rpc/rpc_proto.cpp \
	server/rpc/rpcrawtransaction.cpp \
	server/protocol.cpp \
	server/block.cpp \
	server/coin.cpp \
	server/chain.cpp \
	server/matrix.cpp \
	server/spring.c \
	server/bloom.cpp \
	server/global.cpp \
	server/block_merkle.cpp \
	server/crypter.cpp \
	server/txidx.cpp \
	server/init.cpp \
	server/key.cpp \
	server/hdkey.cpp \
	server/keystore.cpp \
	server/main.cpp \
	server/script.cpp \
	server/sync.cpp \
	server/wallet.cpp \
	server/walletdb.cpp \
	server/scrypt.c \
	server/addrman.h \
	server/addrman.cpp \
	wallet_iface.cpp \
	block_iface.cpp \
	server_iface.cpp

tool_sources = \
	tool/tool_irc.cpp

noinst_PROGRAMS = test_shcoind shcointool
sbin_PROGRAMS = shcoind
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

test_shcoind_SOURCES = \
	$(common_includes) $(common_sources) \
	$(server_sources) \
	test/CuTest.c \
	test/CuTest.h \
	test/test_shcoind.c \
	test/test_shcoind.h \
	test/test_init.cpp \
	test/testcoin_key.cpp \
	test/testcoin_coin.cpp \
	test/testcoin_bignum.cpp \
	test/testcoin_hash.cpp \
	test/testcoin_block.cpp \
	test/testcoin_json.cpp \
	test/testcoin_bloom.cpp

test_shcoind_LDADD = $(top_builddir)/src/share-ssl-lib/libshare_ssl.a \
	-lboost_system -lboost_filesystem -lboost_thread -ldb_cxx -ldl
test_shcoind_CFLAGS = -DSHCOIN_SERVER -g -O0 -DTEST_SHCOIND
test_shcoind_CXXFLAGS = -DOS_LINUX -DSHCOIN_SERVER -g -O0 -DTEST_SHCOIND
if STATIC_LIBSHARE
test_shcoind_LDADD += \
	$(LIBSHARE)/src/share-lib/libshare.a \
	$(LIBSHARE)/src/sexe/libshare_sexe.a
test_shcoind_CFLAGS += -I$(LIBSHARE)/include
test_shcoind_CXXFLAGS += -I$(LIBSHARE)/include
endif



shcoind_SOURCES = \
	$(common_includes) $(common_sources) \
	$(server_sources) $(stratum_sources) \
	shcoind.c \
	shcoind_daemon.c \
	shcoind_daemon.h


shcoind_LDADD = \
	$(top_builddir)/src/share-ssl-lib/libshare_ssl.a
shcoind_CFLAGS = -DSHCOIN_SERVER
shcoind_CXXFLAGS = -DOS_LINUX -DSHCOIN_SERVER
if STATIC_LIBSHARE
shcoind_LDADD += \
	$(LIBSHARE)/src/share-lib/libshare.a \
	$(LIBSHARE)/src/sexe/libshare_sexe.a
shcoind_CFLAGS += -I$(LIBSHARE)/include
shcoind_CXXFLAGS += -I$(LIBSHARE)/include
endif
shcoind_LDADD += -lboost_system -lboost_filesystem -lboost_thread -ldb_cxx -ldl

shcointool_SOURCES = $(common_includes) $(common_sources) \
	shcoind_tool.cpp clientrpc_iface.cpp $(tool_sources)
shcointool_LDADD = \
	$(top_builddir)/src/share-ssl-lib/libshare_ssl.a 
shcointool_CFLAGS = -DSHCOIN_CLIENT
shcointool_CXXFLAGS = -DSHCOIN_CLIENT -DOS_LINUX
if STATIC_LIBSHARE
shcointool_LDADD += \
	$(LIBSHARE)/src/share-lib/libshare.a \
	$(LIBSHARE)/src/sexe/libshare_sexe.a
shcointool_CFLAGS += -I$(LIBSHARE)/include
shcointool_CXXFLAGS += -I$(LIBSHARE)/include
endif
shcointool_LDADD += -lboost_system -lboost_filesystem -lboost_thread -ldb_cxx -ldl

#noinst_LIBRARIES = libleveldb.a
#libleveldb_a_CXXFLAGS = \
#	-I$(srcdir)/leveldb/include -I$(srcdir)/leveldb/helpers -I$(srcdir)/leveldb \
#	-DOS_LINUX -DLEVELDB_PLATFORM_POSIX
#libleveldb_a_SOURCES = \
#	leveldb/db/builder.cc leveldb/db/c.cc leveldb/db/dbformat.cc leveldb/db/db_impl.cc leveldb/db/db_iter.cc leveldb/db/filename.cc leveldb/db/log_reader.cc leveldb/db/log_writer.cc leveldb/db/memtable.cc leveldb/db/repair.cc leveldb/db/table_cache.cc leveldb/db/version_edit.cc leveldb/db/version_set.cc leveldb/db/write_batch.cc leveldb/table/block_builder.cc leveldb/table/block.cc leveldb/table/filter_block.cc leveldb/table/format.cc leveldb/table/iterator.cc leveldb/table/merger.cc leveldb/table/table_builder.cc leveldb/table/table.cc leveldb/table/two_level_iterator.cc leveldb/util/arena.cc leveldb/util/bloom.cc leveldb/util/cache.cc leveldb/util/coding.cc leveldb/util/comparator.cc leveldb/util/crc32c.cc leveldb/util/env.cc leveldb/util/env_posix.cc leveldb/util/env_win.cc leveldb/util/filter_policy.cc leveldb/util/hash.cc leveldb/util/histogram.cc leveldb/util/logging.cc leveldb/util/options.cc leveldb/util/status.cc leveldb/port/port_posix.cc leveldb/helpers/memenv/memenv.cc
#
#if HAVE_CSTDATOMIC
#libleveldb_a_CXXFLAGS += -std=c++0x
#endif
#if HAVE_ATOMIC
#libleveldb_a_CXXFLAGS += -std=c++11
#endif

if HAVE_INITD_DIR
EXTRA_DIST = $(top_builddir)/scripts/initd/shcoind

install-exec-hook:
	[ "`grep ^shc /etc/services`" != "" ] || echo "shc            24104/tcp       shcoind   # SHC virtual currency" >> /etc/services
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
else
install-exec-hook:
	[ "`grep ^shc /etc/services`" != "" ] || echo "shc            24104/tcp       shcoind    # SHC virtual currency" >> /etc/services
endif


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


