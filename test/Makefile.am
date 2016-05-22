AUTOMAKE_OPTIONS = foreign

#noinst_PROGRAMS = test_shcoind

test_shcoind_CFLAGS = \
	-I$(top_srcdir)/src/share-coin -I$(top_srcdir)/src/share-coin/proto
test_shcoind_CXXFLAGS = \
	-I$(top_srcdir)/src/share-coin/server \
	-I$(top_srcdir)/src/share-coin \
	-I$(top_srcdir)/src/share-coin/proto
test_shcoind_LDADD = \
	$(top_builddir)/src/share-ssl-lib/libshare_ssl.a
if STATIC_LIBSHARE
test_shcoind_LDADD += $(LIBSHARE)/src/share-lib/libshare.a
test_shcoind_CFLAGS += -I$(LIBSHARE)/include
test_shcoind_CXXFLAGS += -I$(LIBSHARE)/include
endif
test_shcoind_LDADD += \
	-lboost_unit_test_framework \
  -lboost_system -lboost_filesystem -lboost_thread \
  -ldb_cxx -ldl

test_shcoind_SOURCES = \
	$(testcase_sources) $(common_sources)

testcase_sources = \
	base32_tests.cpp \
	base64_tests.cpp \
	bignum_tests.cpp \
	getarg_tests.cpp \
	mruset_tests.cpp \
	multisig_tests.cpp \
	rpc_tests.cpp \
	sigopcount_tests.cpp \
	test_shcoind.cpp \
	uint160_tests.cpp \
	uint256_tests.cpp \
	util_tests.cpp \
	wallet_tests.cpp

common_sources = \
	$(top_srcdir)/src/share-coin/proto/coin_proto.c \
	$(top_srcdir)/src/share-coin/proto/usde_proto.cpp \
	$(top_srcdir)/src/share-coin/proto/shc_proto.cpp \
	$(top_srcdir)/src/share-coin/shcoind_opt.c \
	$(top_srcdir)/src/share-coin/shcoind_log.c \
	$(top_srcdir)/src/share-coin/unet/unet_accept.c \
	$(top_srcdir)/src/share-coin/unet/unet_bind.c \
	$(top_srcdir)/src/share-coin/unet/unet_buff.c \
	$(top_srcdir)/src/share-coin/unet/unet.c \
	$(top_srcdir)/src/share-coin/unet/unet_close.c \
	$(top_srcdir)/src/share-coin/unet/unet_connect.c \
	$(top_srcdir)/src/share-coin/unet/unet.h \
	$(top_srcdir)/src/share-coin/unet/unet_io.c \
	$(top_srcdir)/src/share-coin/unet/unet_timer.c \
	$(top_srcdir)/src/share-coin/unet/unet_peer.c \
	$(top_srcdir)/src/share-coin/unet/unet_event.c \
	$(top_srcdir)/src/share-coin/server/usde/usde_netmsg.cpp \
	$(top_srcdir)/src/share-coin/server/usde/usde_block.cpp \
	$(top_srcdir)/src/share-coin/server/usde/usde_wallet.cpp \
	$(top_srcdir)/src/share-coin/server/shc/shc_netmsg.cpp \
	$(top_srcdir)/src/share-coin/server/shc/shc_block.cpp \
	$(top_srcdir)/src/share-coin/server/shc/shc_wallet.cpp \
	$(top_srcdir)/src/share-coin/server/addrman.cpp \
	$(top_srcdir)/src/share-coin/server/block.cpp \
	$(top_srcdir)/src/share-coin/server/rpc_proto.cpp \
	$(top_srcdir)/src/share-coin/server/checkpoints.cpp \
	$(top_srcdir)/src/share-coin/server/crypter.cpp \
	$(top_srcdir)/src/share-coin/server/db.cpp \
	$(top_srcdir)/src/share-coin/server/init.cpp \
	$(top_srcdir)/src/share-coin/server/key.cpp \
	$(top_srcdir)/src/share-coin/server/keystore.cpp \
	$(top_srcdir)/src/share-coin/server/main.cpp \
	$(top_srcdir)/src/share-coin/server/netbase.cpp \
	$(top_srcdir)/src/share-coin/server/noui.cpp \
	$(top_srcdir)/src/share-coin/server/protocol.cpp \
	$(top_srcdir)/src/share-coin/server/rpcdump.cpp \
	$(top_srcdir)/src/share-coin/server/rpcnet.cpp \
	$(top_srcdir)/src/share-coin/server/rpcrawtransaction.cpp \
	$(top_srcdir)/src/share-coin/server/script.cpp \
	$(top_srcdir)/src/share-coin/server/sync.cpp \
	$(top_srcdir)/src/share-coin/server/util.cpp \
	$(top_srcdir)/src/share-coin/server/version.cpp \
	$(top_srcdir)/src/share-coin/server/wallet.cpp \
	$(top_srcdir)/src/share-coin/server/walletdb.cpp \
	$(top_srcdir)/src/share-coin/server/scrypt.c \
	$(top_srcdir)/src/share-coin/wallet_iface.cpp \
	$(top_srcdir)/src/share-coin/block_iface.cpp \
	$(top_srcdir)/src/share-coin/server_iface.cpp \
	$(top_srcdir)/src/share-coin/shcoind_block.c \
	$(top_srcdir)/src/share-coin/shcoind_rpc.c \
	$(top_srcdir)/src/share-coin/blockchain/bc_block.c \
	$(top_srcdir)/src/share-coin/blockchain/bc_fmap.c \
	$(top_srcdir)/src/share-coin/blockchain/bc_index.c
