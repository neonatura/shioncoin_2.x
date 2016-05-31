

#include "test_shcoind.h"
#include "server/wallet.h"
#include "server/test/test_block.h"
#include "server/test/test_wallet.h"

#ifdef __cplusplus
extern "C" {
#endif


void test_shcoind_init(void)
{
  TESTWallet *wallet;

  wallet = testWallet;//new TESTWallet();
  SetWallet(TEST_COIN_IFACE, wallet);
  RegisterWallet(wallet);
  RandAddSeedPerfmon();

}


#ifdef __cplusplus
}
#endif
