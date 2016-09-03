
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "test_shcoind.h"
#include <string>
#include <vector>
#include "wallet.h"
#include "test/test_block.h"
#include "test/test_txidx.h"

#include "offer.h"
#include "asset.h"
#include "spring.h"
#include "hdkey.h"




#ifdef __cplusplus
extern "C" {
#endif


_TEST(blockchain)
{
  bc_t *bc;
  bc_hash_t hash[10];
  bc_hash_t t_hash;
  char buf[10240];
  unsigned char *t_data;
  size_t t_data_len;
  int idx;
  bcsize_t n_pos;
  bcsize_t pos;
  int err;

  err = bc_open("rawtest", &bc);
  _TRUE(err == 0);

  srand(time(NULL));

n_pos = bc_idx_next(bc);

  for (idx = 0; idx < 10; idx++) {
    buf[0] = (rand() % 254);
    buf[1] = (rand() % 254);
    buf[2] = (rand() % 254);
    memset(buf + 3, (rand() % 254), sizeof(buf) - 3);

    memcpy(hash[idx], buf + 1, sizeof(hash[idx]));

    pos = bc_append(bc, hash[idx], buf, sizeof(buf));
    _TRUE(pos >= 0);

    err = bc_find(bc, hash[idx], NULL);
    _TRUE(err == 0);

    _TRUE(((pos + 1) == bc_idx_next(bc)));

    err = bc_get(bc, pos, &t_data, &t_data_len);
    _TRUE(err == 0);
    _TRUE(t_data_len == sizeof(buf));

    _TRUE(0 == memcmp(t_data, buf, t_data_len));
    free(t_data);

    memset(t_hash, 255, sizeof(t_hash));
    err = bc_find(bc, t_hash, NULL);
    _TRUE(err == SHERR_NOENT);
  }

  err = bc_purge(bc, n_pos + 1);
  _TRUE(err == 0);

  /* re-write purged records. */
  for (idx = 1; idx < 10; idx++) {
    bcsize_t a_pos;
    _TRUE(!(err = bc_arch_find(bc, hash[idx], NULL, &a_pos)));
    _TRUE(!(err = bc_arch(bc, a_pos, &t_data, &t_data_len)));
    _TRUEPTR(t_data);
    /* verify hash */  
    memcpy(t_hash, t_data + 1, sizeof(t_hash));
    _TRUE(0 == memcmp(hash[idx], t_hash, sizeof(bc_hash_t)));
    /* add back to main chain */
    _TRUE(0 == bc_write(bc, n_pos + idx, hash[idx], t_data, t_data_len));
    free(t_data);
  }
  

//fprintf(stderr, "OK (height %d)\n", (bc_idx_next(bc)-1));
  _TRUE(bc_idx_next(bc) == (n_pos + 10));
  bc_close(bc);


}

_TEST(reorganize)
{
  blkidx_t *blockIndex = GetBlockTable(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CBlock *parent;
  CBlock *chain1;
  CBlock *chain2;
  CBlock *chain3;
  CBlock *blocks[40];
  uint256 hashParent;
shtime_t ts;
  int i;

  /* battle1 : start */
  parent = test_GenerateBlock();
  _TRUEPTR(parent);
  hashParent = parent->GetHash();
  _TRUE(ProcessBlock(NULL, parent) == true);
  delete parent;
  /* battle1 : finish */

  /* battle2 : start */
  chain1 = test_GenerateBlock();
  _TRUEPTR(chain1);
  chain2 = test_GenerateBlock();
  _TRUEPTR(chain2);
  chain3 = test_GenerateBlock();
  _TRUEPTR(chain3);
  _TRUE(ProcessBlock(NULL, chain1) == true);
  _TRUE(ProcessBlock(NULL, chain2) == true);
  _TRUE(GetBestBlockChain(iface) == chain1->GetHash()); /* verify mem */
  CBlock *t_block = GetBlockByHeight(iface, 2);
  _TRUEPTR(t_block);
  _TRUE(t_block->GetHash() == chain1->GetHash()); /* verify disk */
  delete t_block;
  /* battle2 : finish */

  /* battle3 : start */
  for (i = 0; i < 39; i++) { 
    blocks[i] = test_GenerateBlock();
    _TRUEPTR(blocks[i]);
    _TRUE(ProcessBlock(NULL, blocks[i]) == true);
  }
  blocks[39] = test_GenerateBlock();
  _TRUEPTR(blocks[39]);

  _TRUE(ProcessBlock(NULL, chain3) == true); /* ALT CHAIN */

  _TRUE(ProcessBlock(NULL, blocks[39]) == true);
  /* battle3 : finish */

  t_block = GetBlockByHeight(iface, 0);
  _TRUEPTR(t_block); 
  _TRUE(t_block->GetHash() == test_hashGenesisBlock);
  delete(t_block);

  t_block = GetBlockByHeight(iface, 1);
  _TRUEPTR(t_block); 
  _TRUE(t_block->GetHash() == hashParent); 
  delete(t_block);

  for (i = 0; i < 40; i++) {
    int nHeight = 3 + i;
    t_block = GetBlockByHeight(iface, nHeight);
    _TRUEPTR(t_block); 
    _TRUE(t_block->GetHash() == blocks[i]->GetHash());
    delete t_block;
  }

  CBlockIndex *pindexBest = GetBestBlockIndex(iface);
  _TRUEPTR(pindexBest);
  _TRUE(pindexBest->GetBlockHash() == blocks[39]->GetHash());
  _TRUE(pindexBest->nHeight == 42);

  for (i = 0; i < 40; i++) { 
    delete(blocks[i]);
  }

  delete chain3;
  delete chain2;
  delete chain1;
}

_TEST(serializetx)
{
  CDataStream ser(SER_DISK, DISK_VERSION);
  CDataStream a_ser(SER_DISK, DISK_VERSION);
  CDataStream e_ser(SER_DISK, DISK_VERSION);
  CTransaction tx;
  CTransaction cmp_tx;

  ser << tx;
  ser >> cmp_tx;
  _TRUE(tx.GetHash() == cmp_tx.GetHash());

  string strAlias("test");
  uint160 addrAlias("0x1");
  CAlias alias = CAlias(strAlias, addrAlias);
  CAlias cmp_alias;
  a_ser << alias;
  a_ser >> cmp_alias;
  _TRUE(alias.GetHash() == cmp_alias.GetHash());
tx.nFlag |= CTransaction::TXF_ALIAS;
tx.alias = alias;

  string strAsset("test");
char hashstr[256];
  strcpy(hashstr, "0x0");
  string strAssetHash(hashstr);
  CAsset asset(strAsset);//, strAssetHash);
  CAsset cmp_asset;
  a_ser << asset;
  a_ser >> cmp_asset;
  _TRUE(asset.GetHash() == cmp_asset.GetHash());

  CIdent ident;
  ident.SetLabel("test");
  CIdent cmp_ident;
  a_ser << ident;
  a_ser >> cmp_ident;
  _TRUE(ident.GetHash() == cmp_ident.GetHash());

  CCert cert = CCert();
  CCert cmp_cert;
  a_ser << cert;
  a_ser >> cmp_cert;
  _TRUE(cert.GetHash() == cmp_cert.GetHash());

  COffer offer = COffer();
  COfferAccept acc = COfferAccept();
offer.accepts.push_back(acc);
  COffer cmp_offer;
  a_ser << offer;
  a_ser >> cmp_offer;
  _TRUE(offer.GetHash() == cmp_offer.GetHash());
//_TRUE(offer.accepts.first().GetHash() == cmp_offer.accepts.first().GetHash());

  CTransaction mtx;
  mtx.nFlag |= CTransaction::TXF_MATRIX;
  mtx.matrix.vData[0][0] = 1;
  mtx.matrix.vData[0][1] = 2;
  mtx.matrix.vData[1][0] = 3;
  mtx.matrix.nHeight = 1;
  CTransaction cmp_mtx;
  a_ser << mtx;
  a_ser >> cmp_mtx;
  _TRUE(mtx.matrix.GetHash() == cmp_mtx.matrix.GetHash());
  _TRUE(mtx.GetHash() == cmp_mtx.GetHash());

  CTxMatrix cmp_matrix;
  cmp_matrix.Init(mtx.matrix);
  _TRUE(mtx.matrix.GetHash() == cmp_matrix.GetHash());
}

_TEST(signtx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  string strAccount("");
  CCoinAddr extAddr = GetAccountAddress(wallet, strAccount, true);
  unsigned char *data;
  size_t data_len;
  bool ret;

  data = (unsigned char *)strdup("secret");
  data_len = (size_t)sizeof(strlen("secret"));
  string strSecret("secret");

  /* CExtCore.origin */
  CCert cert;
  _TRUE(cert.signature.Sign(TEST_COIN_IFACE, extAddr, data, data_len) == true);
  _TRUE(cert.signature.Verify(extAddr, data, data_len) == true);

  cert.SetNull();
  cbuff vchSecret(vchFromString(strSecret));
  _TRUE(cert.Sign(TEST_COIN_IFACE, extAddr, vchSecret) == true);
  _TRUE(cert.VerifySignature(vchSecret) == true);
 
  CAsset asset;
  _TRUE(asset.Sign(cert.GetHash()) == true);
  _TRUE(asset.VerifySignature() == true);

  CLicense license;
  _TRUE(license.signature.SignOrigin(TEST_COIN_IFACE, extAddr) == true);
  _TRUE(license.signature.VerifyOrigin(extAddr) == true);

  free(data);
}

_TEST(cointx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  int idx;

  for (idx = 0; idx < 10; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  bool found = false;
  string strAccount;
  CCoinAddr addr;
  BOOST_FOREACH(const PAIRTYPE(CCoinAddr, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = item.first;
    const string& account = item.second;
    addr = address;
    strAccount = account;
    found = true;
    break;
  }

  string strExtAccount = "*" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  CWalletTx wtx;
  wtx.SetNull();
  wtx.strFromAccount = string("");

  int64 nFee = 18 * COIN;

  /* send to extended tx storage account */
  CScript scriptPubKey;
  scriptPubKey.SetDestination(extAddr.Get());

  for (idx = 0; idx < 3; idx++) {
    // send transaction
    string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
fprintf(stderr, "DEBUG: TEST: cointx: wallet->SendMoney: error \"%s\"\n", strError.c_str());
    _TRUE(strError == "");

    _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  }
}

_TEST(aliastx)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  int idx;
  int err;

  string strLabel("");

  /* create a coin balance */
  for (idx = 0; idx < 5; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CCoinAddr addr = GetAccountAddress(wallet, strLabel, false);
  _TRUE(addr.IsValid() == true);

  CWalletTx wtx;
  err = init_alias_addr_tx(iface, "test", addr, wtx);
  _TRUE(0 == err);

  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyAlias(wtx) == true);

  /* incorporate alias into block-chain + few more coins */
  for (idx = 0; idx < 5; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  err = update_alias_addr_tx(iface, "test", addr, wtx);
  _TRUE(0 == err);

  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE) == true); /* .. */
  _TRUE(VerifyAlias(wtx) == true);

/* insert into block-chain */
  for (idx = 0; idx < 5; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

CTransaction t_tx;
string strTitle("test");
_TRUE(GetTxOfAlias(iface, strTitle, t_tx) == true);
}




_TEST(assettx)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  int idx;
  int err;


  string strLabel("");

  /* create a coin balance */
  for (idx = 0; idx < 8; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CCoinAddr addr = GetAccountAddress(wallet, strLabel, false);
  _TRUE(addr.IsValid() == true);

  CWalletTx wtx;
  err = init_asset_tx(iface, strLabel, "test", addr.ToString(), wtx);
  _TRUE(0 == err);

  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyAsset(wtx) == true);

  CAsset asset(wtx.certificate);
  uint160 hashAsset = asset.GetHash();

  /* incorporate asset into block-chain + few more coins */
  for (idx = 0; idx < 8; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  err = update_asset_tx(iface, strLabel, hashAsset, "test", addr.ToString(), wtx);
  _TRUE(0 == err);

  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyAsset(wtx) == true);

wtx.print();
}

_TEST(identtx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  CWalletTx wtx;
  string strAccount("");
  int64 orig_bal;
  int64 bal;
  int mode;
  int idx;
  int err;

  CWalletTx cert_wtx;
  const char *raw = "test-secret";
  cbuff vchSecret(raw, raw+strlen(raw));
  uint160 issuer;
  err = init_cert_tx(iface, strAccount, "test", vchSecret, 1, cert_wtx);
  _TRUE(0 == err);
  uint160 hashCert = cert_wtx.certificate.GetHash();

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  orig_bal = GetAccountBalance(TEST_COIN_IFACE, strAccount, 1);
  _TRUE(orig_bal > (COIN + iface->min_tx_fee));


  err = init_ident_donate_tx(iface, strAccount, orig_bal - COIN, hashCert, wtx);  
  _TRUE(err == 0);
  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
wtx.print();
  _TRUE(VerifyIdent(wtx, mode) == true);
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  for (idx = 0; idx < 3; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  /* verify insertion into block-chain */
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

  bal = GetAccountBalance(TEST_COIN_IFACE, strAccount, 1);
  _TRUE(bal < orig_bal);
  orig_bal = bal;


  /* send certified coins to self */
  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);
  _TRUE(addr.IsValid() == true);

  CWalletTx csend_tx;
  err = init_ident_certcoin_tx(iface, strAccount, bal - COIN, hashCert, addr, csend_tx);
if (err) fprintf(stderr, "DEBUG: IDENT-TX(cert coin): err == %d\n", err);
  _TRUE(err == 0);
  _TRUE(csend_tx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyIdent(csend_tx, mode) == true);

  for (idx = 0; idx < 3; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  bal = GetAccountBalance(TEST_COIN_IFACE, strAccount, 1); /* not counting to-be-matured coins */
  _TRUE(bal > orig_bal);

}

_TEST(certtx)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  int idx;
  int err;


  string strLabel("");

  /* create a coin balance */
  for (idx = 0; idx < 15; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CCoinAddr addr = GetAccountAddress(wallet, strLabel, false);
  _TRUE(addr.IsValid() == true);

unsigned int nBestHeight = GetBestHeight(iface) + 1;
  CWalletTx wtx;
  const char *raw = "test-secret";
  cbuff vchSecret(raw, raw+strlen(raw));
  uint160 issuer;
  err = init_cert_tx(iface, strLabel, "test", vchSecret, 1, wtx);
  _TRUE(0 == err);
  uint160 hashCert = wtx.certificate.GetHash();
 // uint256 hashTx = wtx.GetHash();

  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyCert(iface, wtx, nBestHeight) == true);
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  /* insert cert into chain + create a coin balance */
  for (idx = 0; idx < 10; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  /* verify insertion */
  CTransaction t_tx;
  _TRUE(GetTxOfCert(iface, hashCert, t_tx) == true);
  _TRUE(t_tx.GetHash() == wtx.GetHash());
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

  /* generake test license from certificate */
  CWalletTx lic_wtx;
  err = init_license_tx(iface, strLabel, hashCert, lic_wtx);
if (err)  fprintf(stderr, "DEBUG: %d = init_license_tx()\n", err);
  _TRUE(0 == err);

  _TRUE(lic_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyLicense(lic_wtx) == true);
  CLicense lic(lic_wtx.certificate);
  uint160 licHash = lic.GetHash();
  _TRUE(lic_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  for (idx = 0; idx < 3; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  /* verify insertion */
  CTransaction t2_tx;
  _TRUE(GetTxOfLicense(iface, licHash, t2_tx) == true);
  _TRUE(lic_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);
}

_TEST(offertx)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CTransaction t_tx;
  int64 srcValue;
  int64 destValue;
  int idx;
  int err;

  string strLabel("");

  /* create a coin balance */
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CCoinAddr addr = GetAccountAddress(wallet, strLabel, false);
  _TRUE(addr.IsValid() == true);

  int64 bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
  srcValue = -1 * (bal / 3);
  destValue = 1 * (bal / 4);

  CWalletTx wtx;
  err = init_offer_tx(iface, strLabel, srcValue, TEST_COIN_IFACE, destValue, wtx);
if (err) fprintf(stderr, "DEBUG: TEST: OFFER: OFFER-TX: %d = init_offer_tx()\n", err); 
  _TRUE(0 == err);
  uint160 hashOffer = wtx.offer.GetHash();
  uint256 hashTx = wtx.GetHash();

  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer initialized .. bal is now %f\n", ((double)t_bal / COIN));
  }

  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE));
  _TRUE(VerifyOffer(wtx) == true);
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  /* insert offer-tx into chain */
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  /* verify insertion */
  _TRUE(GetTxOfOffer(iface, hashOffer, t_tx) == true);
  _TRUE(t_tx.GetHash() == hashTx); 
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

  srcValue = 1 * (bal / 3);
  destValue = -1 * (bal / 4);

  /* generate test license from certificate */
  CWalletTx acc_wtx;
  err = accept_offer_tx(iface, strLabel, hashOffer, srcValue, destValue, acc_wtx);
if (err) fprintf(stderr, "DEBUG: OFFER-TX: %d = accept_offer_tx()\n", err);
  if (err == -2) {
    CTxMemPool *mempool = GetTxMemPool(iface);
    if (mempool->exists(hashTx)) {
      fprintf(stderr, "DEBUG: tx '%s' still in mempool\n", hashTx.GetHex().c_str());
    }
  }
  _TRUE(0 == err);
  uint160 hashAccept = acc_wtx.offer.GetHash();
  _TRUE(acc_wtx.CheckTransaction(TEST_COIN_IFACE));
  _TRUE(VerifyOffer(acc_wtx) == true);
  _TRUE(acc_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer accepted .. bal is now %f\n", ((double)t_bal / COIN));
  }

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
acc_wtx.print();

  /* verify insertion */
  _TRUE(acc_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

  /* offer generate operation */
  CWalletTx gen_wtx;
  err = generate_offer_tx(iface, hashOffer, gen_wtx);
if (err) fprintf(stderr, "DEBUG: %d = generate_offer_tx\n", err);
  _TRUE(0 == err);
  uint160 hashGen = gen_wtx.offer.GetHash();
  _TRUE(gen_wtx.CheckTransaction(TEST_COIN_IFACE));
  _TRUE(VerifyOffer(gen_wtx) == true);
  _TRUE(hashGen == hashOffer);

  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer generated .. bal is now %f\n", ((double)t_bal / COIN));
  }

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
gen_wtx.print();

  /* pay operation */
  CWalletTx pay_wtx;
  err = pay_offer_tx(iface, hashAccept, pay_wtx);
if (err) fprintf(stderr, "DEBUG: %d = pay_offer_tx\n", err);
  _TRUE(0 == err);

  /* verify pending transaction */
  uint160 hashPay = pay_wtx.offer.GetHash();
  _TRUE(pay_wtx.CheckTransaction(TEST_COIN_IFACE));
  _TRUE(VerifyOffer(pay_wtx) == true);
  _TRUE(hashPay == hashAccept);
  _TRUE(pay_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer pay'd .. bal is now %f\n", ((double)t_bal / COIN));
  }

  for (idx = 0; idx < 3; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
pay_wtx.print();

  _TRUE(pay_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);
#if 0
  /* verify payment has been appended to block-chain */
  _TRUE(GetTxOfOffer(iface, hashPay, t_tx) == false);
  _TRUE(t_tx.GetHash() == pay_wtx.GetHash());
#endif

/* verify payment */
  int64 new_bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
fprintf(stderr, "DEBUG: TEST OFFER: offertx: bal %llu < new_bal %llu\n", (unsigned long long)bal, (unsigned long long)new_bal);
  _TRUE(new_bal >= bal);
}



_TEST(matrix)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CTransaction tx;
  CTxMatrix *m;
  double lat, lon;
bool ret;
  int idx;
  int err;

  CBlockIndex *pindex;
  CBlockIndex *t_pindex;
  uint256 hashBlock;


  /* check for false negative */
  pindex = new CBlockIndex();
  pindex->phashBlock = &hashBlock;
  pindex->nHeight = 54;
  m = tx.GenerateValidateMatrix(TEST_COIN_IFACE, pindex);
  _TRUE(m == NULL);

  /* initial block with no seed */
  t_pindex = new CBlockIndex();
  t_pindex->phashBlock = &hashBlock;
  t_pindex->nHeight = 81;
  t_pindex->pprev = pindex;
  pindex = t_pindex;
  m = tx.GenerateValidateMatrix(TEST_COIN_IFACE, pindex);
  _TRUEPTR(m);
  ret = tx.VerifyValidateMatrix(*m, pindex);
  _TRUE(ret == true);

  for (idx = 108; idx < 351; idx += 27) {
    char buf[256];
    sprintf(buf, "0x%x%x%x%x", idx, idx, idx, idx);
    hashBlock = uint256(buf);

    t_pindex = new CBlockIndex();
    t_pindex->phashBlock = &hashBlock;
    t_pindex->nHeight = idx;
    t_pindex->pprev = pindex;
    pindex = t_pindex;

    tx.SetNull();
    m = tx.GenerateValidateMatrix(TEST_COIN_IFACE, pindex);
    _TRUEPTR(m);

    ret = tx.VerifyValidateMatrix(*m, pindex);
    _TRUE(ret == true);
  }
  matrixValidate.SetNull();

}

_TEST(matrixtx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CTransaction tx;
  CTxMatrix *m;
  double lat, lon;
bool ret;
  int idx;
  int err;

  CBlockIndex *pindex;
  CBlockIndex *t_pindex;
  uint256 hashBlock;


  /* claim a known 'root' location in spring matrix */
  lat = 46.6317; lon = 114.0946;
  _TRUE(is_spring_loc(lat, lon));
  spring_loc_claim(lat, lon);
  _TRUE(!is_spring_loc(lat, lon));

  /* claim a location through block-chain */
  CWalletTx wtx;
  string strAccount("");
  string strComment("geo:46.7467,-114.1096");
  err = init_ident_stamp_tx(iface, strAccount, strComment, wtx); 
  _TRUE(err == 0);


/* DEBUG: TODO: free blockindex's for valgrind mem check */

  /* ensure that block processing does not fail past x2 Validate matrix */
  for (idx = 0; idx < 67; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
}

_TEST(channeltx)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CTransaction t_tx;
  int64 srcValue;
  int64 destValue;
  int idx;
  int err;
  int i;

  for (i = 0; i < 16; i++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }



  string strLabel("");

  /* create a coin balance */
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CCoinAddr addr = GetAccountAddress(wallet, strLabel, true);
  _TRUE(addr.IsValid() == true);

  CCoinAddr dest_addr = GetAccountAddress(wallet, strLabel, true);
  _TRUE(dest_addr.IsValid() == true);

  int64 nValue = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1) / 4;

  /* ** Regular Channel Scenerio ** */

  /* request channel funding */
  CWalletTx fund_wtx;
  err = init_channel_tx(iface, strLabel, nValue, dest_addr, fund_wtx); 
fprintf(stderr, "DEBUG: %d = init_channel_tx()\n", err);
  _TRUE(0 == err);
fprintf(stderr, "DEBUG: CHAN INIT: %s\n", fund_wtx.ToString().c_str());

  /* fund channel as counter-party */
  CWalletTx chan_wtx;
  err = activate_channel_tx(iface, (CTransaction *)&fund_wtx, nValue, chan_wtx);
  _TRUE(0 == err);

  uint160 hChan = chan_wtx.channel.GetHash();

fprintf(stderr, "DEBUG: CHAN OPEN: %s\n", chan_wtx.ToString().c_str());
//  _TRUE(chan_wtx.channel.GetHash() == hChan);

  /* perform pay operation to counter-party */
  CWalletTx commit_wtx;
  err = pay_channel_tx(iface, strLabel, hChan, dest_addr, nValue / 2, commit_wtx);  
fprintf(stderr, "DEBUG: CHAN PAY[err %d]: %s\n", err, commit_wtx.ToString().c_str());
  _TRUE(0 == err);

  /* validate pay op */
  CWalletTx val_wtx;
  err = validate_channel_tx(iface, (CTransaction *)&commit_wtx, val_wtx);  
  _TRUE(0 == err);
fprintf(stderr, "DEBUG: CHAN VALIDATE: %s\n", val_wtx.ToString().c_str());

#if 0
  /* perform pay operation from counter-party */
  CWalletTx commit_wtx;
  uint160 hChan = chan_wtx.channel.GetHash();
  err = pay_channel_tx(iface, strLabel, hChan, nValue / 2, commit_wtx);  
  _TRUE(0 == err);
#endif

  /* close channel and finalize transaction. */
  CWalletTx fin_wtx;
  err = generate_channel_tx(iface, hChan, fin_wtx);
  _TRUE(0 == err);
fprintf(stderr, "DEBUG: CHAN GEN: %s\n", fin_wtx.ToString().c_str());

  /* ** Abort Channel Scenerio ** */

  /* request channel funding */

  /* fund channel as counter-party */

  /* perform pay operation to counter-party */

  /* abort channel and redeem funds at current state */

}

/* test in-script verification of HD sig */
_TEST(hdtx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  string strAccount("");
  int i;

  CTransaction prevTx;
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    prevTx = block->vtx[0];
    delete block;
  }

  /* regular key */
  CKey key;
  CKeyID keyid;
  cbuff vchPubKey;
  CPubKey pubkey;
  _TRUE(wallet->GetKeyFromPool(pubkey, false) == true);
  wallet->SetAddressBookName(pubkey.GetID(), strAccount);
  _TRUE(wallet->GetKey(pubkey.GetID(), key) == true);
  _TRUE(key.IsValid());

  /* hd key */
  HDPrivKey mkey;
  HDPubKey mpubkey = wallet->GenerateNewHDKey();
  wallet->SetAddressBookName(mpubkey.GetID(), strAccount);
//  _TRUE(wallet->HaveKey(mpubkey.GetID() == true));
  _TRUE(wallet->GetKey(mpubkey.GetID(), mkey) == true);
fprintf(stderr, "DEBUG: TEST: hdtx: mkey = %s\n", mkey.ToString().c_str());
  if(mpubkey != mkey.GetPubKey()) fprintf(stderr, "DEBUG: mpubkey != mkey.GetPubKey: mpubkey is %s\n", HexStr(mpubkey.Raw()).c_str());
  if(mpubkey != mkey.GetPubKey()) fprintf(stderr, "DEBUG: mpubkey != mkey.GetPubKey: mkey.pubkey is %s\n", HexStr(mkey.GetPubKey().Raw()).c_str());
  _TRUE(key.IsValid());
  _TRUE(mpubkey == mkey.GetPubKey());

  for (i = 0; i < 16; i++) { /* mature block */
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }


  {
    CScript scriptCode;
    scriptCode.SetDestination(mpubkey.GetID());
fprintf(stderr, "DEBUG: TEST: hdtx: sending tx to hd key: scriptCode %s\n", scriptCode.ToString().c_str());
    CWalletTx wtx;
    wtx.vin.push_back(CTxIn(prevTx.GetHash(), 0));
    wtx.vout.push_back(CTxOut(1, scriptCode));
    _TRUE(SignSignature(*wallet, prevTx, wtx, 0) == true);  
    _TRUE(VerifySignature(prevTx, wtx, 0, false, 0) == true);
CReserveKey rkey(wallet);
_TRUE(wallet->CommitTransaction(wtx, rkey) == true);

#if 0
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    block->vtx.push_back(wtx);
    block->BuildMerkleTree();
    _TRUE(ProcessBlock(NULL, block) == true);
#endif

    prevTx = wtx;
  }


  {

    CScript scriptCode;
    scriptCode << OP_RETURN;
//    scriptCode.SetDestination(pubkey.GetID());
    CWalletTx wtx;
    wtx.vin.push_back(CTxIn(prevTx.GetHash(), 0));
    wtx.vout.push_back(CTxOut(1, scriptCode));
    _TRUE(SignSignature(*wallet, prevTx, wtx, 0, SIGHASH_HDKEY) == true);  
    _TRUE(VerifySignature(prevTx, wtx, 0, false, SIGHASH_HDKEY) == true);
  }

}

_TEST(exectx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  string strPath("/tmp/exectx.sx");
  string strAccount("");
  int mode = -1;
  int idx;
  int err;

  for (idx = 0; idx < 3; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CWalletTx wtx;
  wtx.SetNull();
  wtx.strFromAccount = strAccount;

  err = init_exec_tx(iface, strAccount, strPath, 0, wtx); 
fprintf(stderr, "DEBUG: TEST: EXECTX[status %d]: %s\n", err, wtx.ToString().c_str());
  _TRUE(err == 0);
  _TRUE(VerifyExec(wtx, mode) == true);
  _TRUE(mode == OP_EXT_NEW);

  CExec *exec = &((CExec&)wtx.certificate);
  _TRUE(exec->VerifyContext());


}



#ifdef __cplusplus
}
#endif
