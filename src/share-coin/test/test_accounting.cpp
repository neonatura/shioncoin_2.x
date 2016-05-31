
#include "test_shcoind.h"
#include <boost/foreach.hpp>

#include "init.h"
#include "wallet.h"
#include "walletdb.h"


#ifdef __cplusplus
extern "C" {
#endif


#if 0
static void
GetResults(CWalletDB& walletdb, std::map<int64, CAccountingEntry>& results)
{
    std::list<CAccountingEntry> aes;

    results.clear();
    BOOST_CHECK(walletdb.ReorderTransactions(pwalletMain) == DB_LOAD_OK);
    walletdb.ListAccountCreditDebit("", aes);
    BOOST_FOREACH(CAccountingEntry& ae, aes)
    {
        results[ae.nOrderPos] = ae;
    }
}
#endif

//acc_orderupgrade
_TEST(wallet_accounting)
{
#if 0
  CWallet *pwalletMain = GetWallet(TEST_COIN_IFACE);
  CWalletDB walletdb(pwalletMain->strWalletFile);
  std::vector<CWalletTx*> vpwtx;
  CWalletTx wtx;
  CAccountingEntry ae;
  std::map<int64, CAccountingEntry> results;

  ae.strAccount = "";
  ae.nCreditDebit = 1;
  ae.nTime = 1333333333;
  ae.strOtherAccount = "b";
  ae.strComment = "";
  walletdb.WriteAccountingEntry(ae);

  wtx.mapValue["comment"] = "z";
  pwalletMain->AddToWallet(wtx);
  vpwtx.push_back(&pwalletMain->mapWallet[wtx.GetHash()]);
  vpwtx[0]->nTimeReceived = (unsigned int)1333333335;
  vpwtx[0]->nOrderPos = -1;

  ae.nTime = 1333333336;
  ae.strOtherAccount = "c";
  walletdb.WriteAccountingEntry(ae);

  GetResults(walletdb, results);

  _TRUE(pwalletMain->nOrderPosNext == 3);
  _TRUE(2 == results.size());
  _TRUE(results[0].nTime == 1333333333);
  _TRUE(results[0].strComment.empty());
  _TRUE(1 == vpwtx[0]->nOrderPos);
  _TRUE(results[2].nTime == 1333333336);
  _TRUE(results[2].strOtherAccount == "c");


  ae.nTime = 1333333330;
  ae.strOtherAccount = "d";
  ae.nOrderPos = pwalletMain->IncOrderPosNext();
  walletdb.WriteAccountingEntry(ae);

  GetResults(walletdb, results);

  _TRUE(results.size() == 3);
  _TRUE(pwalletMain->nOrderPosNext == 4);
  _TRUE(results[0].nTime == 1333333333);
  _TRUE(1 == vpwtx[0]->nOrderPos);
  _TRUE(results[2].nTime == 1333333336);
  _TRUE(results[3].nTime == 1333333330);
  _TRUE(results[3].strComment.empty());


  wtx.mapValue["comment"] = "y";
  --wtx.nLockTime;  // Just to change the hash :)
  pwalletMain->AddToWallet(wtx);
  vpwtx.push_back(&pwalletMain->mapWallet[wtx.GetHash()]);
  vpwtx[1]->nTimeReceived = (unsigned int)1333333336;

  wtx.mapValue["comment"] = "x";
  --wtx.nLockTime;  // Just to change the hash :)
  pwalletMain->AddToWallet(wtx);
  vpwtx.push_back(&pwalletMain->mapWallet[wtx.GetHash()]);
  vpwtx[2]->nTimeReceived = (unsigned int)1333333329;
  vpwtx[2]->nOrderPos = -1;

  GetResults(walletdb, results);

  _TRUE(results.size() == 3);
  _TRUE(pwalletMain->nOrderPosNext == 6);
  _TRUE(0 == vpwtx[2]->nOrderPos);
  _TRUE(results[1].nTime == 1333333333);
  _TRUE(2 == vpwtx[0]->nOrderPos);
  _TRUE(results[3].nTime == 1333333336);
  _TRUE(results[4].nTime == 1333333330);
  _TRUE(results[4].strComment.empty());
  _TRUE(5 == vpwtx[1]->nOrderPos);


  ae.nTime = 1333333334;
  ae.strOtherAccount = "e";
  ae.nOrderPos = -1;
  walletdb.WriteAccountingEntry(ae);

  GetResults(walletdb, results);

  _TRUE(results.size() == 4);
  _TRUE(pwalletMain->nOrderPosNext == 7);
  _TRUE(0 == vpwtx[2]->nOrderPos);
  _TRUE(results[1].nTime == 1333333333);
  _TRUE(2 == vpwtx[0]->nOrderPos);
  _TRUE(results[3].nTime == 1333333336);
  _TRUE(results[3].strComment.empty());
  _TRUE(results[4].nTime == 1333333330);
  _TRUE(results[4].strComment.empty());
  _TRUE(results[5].nTime == 1333333334);
  _TRUE(6 == vpwtx[1]->nOrderPos);
#endif
}

#ifdef __cplusplus
}
#endif
