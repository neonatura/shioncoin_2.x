

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
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  uint256 thash;

  /* initialize configuration options */
  opt_init();

  /* initialize chains */
  bc_t *tx_bc = GetBlockTxChain(iface);
  bc_t *bc = GetBlockChain(iface);

  /* load wallet */
  testWallet = new TESTWallet();
  SetWallet(TEST_COIN_IFACE, testWallet);
  //RegisterWallet(testWallet);
  RandAddSeedPerfmon();

  /* initialize chain */
  {
    TESTTxDB txdb("cr");
 //   txdb.ReadHashBestChain(thash);
    txdb.Close();
  }
  test_CreateGenesisBlock();


  /* initialize wallet */
  test_LoadWallet();


//CBlock *test_block = test_GenerateBlock(); /* DEBUG: */

}


#ifdef __cplusplus
}
#endif
