

#include "test_shcoind.h"
#include "server/wallet.h"
#include "server/test/test_block.h"
#include "server/test/test_wallet.h"

#ifdef __cplusplus
extern "C" {
#endif


void test_shcoind_init(void)
{

  /* initialize chain */
  test_CreateGenesisBlock();
  test_GenerateBlock();

  /* load wallet */
  SetWallet(TEST_COIN_IFACE, testWallet);
  RegisterWallet(testWallet);
  RandAddSeedPerfmon();

}


#ifdef __cplusplus
}
#endif
