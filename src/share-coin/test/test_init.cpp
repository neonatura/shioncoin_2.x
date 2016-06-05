

#include "test_shcoind.h"
#include "server/wallet.h"
#include "server/test/test_block.h"
#include "server/test/test_wallet.h"
#include "server/test/test_txidx.h"

#ifdef __cplusplus
extern "C" {
#endif


void test_shcoind_init(void)
{
  uint256 thash;

  /* initialize chain */
  {
    TESTTxDB txdb("cr");
 //   txdb.ReadHashBestChain(thash);
    txdb.Close();
  }
  test_CreateGenesisBlock();

//  test_GenerateBlock();

  /* load wallet */
  SetWallet(TEST_COIN_IFACE, testWallet);
  RegisterWallet(testWallet);
  RandAddSeedPerfmon();

}


#ifdef __cplusplus
}
#endif
