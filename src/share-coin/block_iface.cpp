
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura
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

#include "main.h"
#include "wallet.h"
#include "db.h"
#include "walletdb.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "base58.h"
#include "server/rpc_proto.h"
#include "server_iface.h" /* BLKERR_XXX */

#undef printf
#include <boost/asio.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/shared_ptr.hpp>
#include <list>

#define printf OutputDebugStringF

using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace json_spirit;

//std::map<uint256, CBlockIndex*> transactionMap;
map<int, CBlock*>mapWork;
string blocktemplate_json; 
string mininginfo_json; 
string transactioninfo_json;

extern std::string HexBits(unsigned int nBits);
extern string JSONRPCReply(const Value& result, const Value& error, const Value& id);
extern void ScriptPubKeyToJSON(const CScript& scriptPubKey, Object& out);
extern Value ValueFromAmount(int64 amount);
extern void WalletTxToJSON(const CWalletTx& wtx, Object& entry);

extern double GetDifficulty(const CBlockIndex* blockindex = NULL);

extern void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret);

static double nextDifficulty;
double GetBitsDifficulty(unsigned int nBits)
{
  // Floating point number that is a multiple of the minimum difficulty,
  // minimum difficulty = 1.0.

  int nShift = (nBits >> 24) & 0xff;

  double dDiff =
    (double)0x0000ffff / (double)(nBits & 0x00ffffff);

  while (nShift < 29)
  {
    dDiff *= 256.0;
    nShift++;
  }
  while (nShift > 29)
  {
    dDiff /= 256.0;
    nShift--;
  }

  return (dDiff);
}

void SetNextDifficulty(unsigned int nBits)
{
  nextDifficulty = GetBitsDifficulty(nBits);
}

/**
 * Generate a block to work on.
 * @returns JSON encoded block state information
 */
const char *c_getblocktemplate(void)
{
  static CReserveKey reservekey(pwalletMain);
  static unsigned int nTransactionsUpdatedLast;
  static CBlockIndex* pindexPrev;
  static unsigned int work_id;
  static time_t last_reset_t;
  CBlock* pblock;
  int reset;

  /* DEBUG: required for release
     if (vNodes.empty())
     return (NULL);
     */

  /* DEBUG: required for release
     if (IsInitialBlockDownload())
     return (NULL);
     */

  if (!pwalletMain) {
    fprintf(stderr, "DEBUG: CreateNewBlock: Wallet not initialized.");
    return (NULL);
  }

  // Update block

  pblock = NULL;

  /* clear work after new block and every 5 minutes. */
  reset = 0;
  if (pindexPrev != NULL && pindexPrev->nHeight != pindexBest->nHeight) {
    reset = 1;
    last_reset_t = time(NULL);
  } else if ((last_reset_t + 300) < time(NULL)) {
    reset = 1;
    last_reset_t = time(NULL);
  }
  if (reset == 1) { /* delete all worker blocks. */
    for (map<int, CBlock*>::const_iterator mi = mapWork.begin(); mi != mapWork.end(); ++mi)
    {
      CBlock *tblock = mi->second;
      delete tblock;
    }
    mapWork.clear();
  }

  // Store the pindexBest used before CreateNewBlock, to avoid races
  nTransactionsUpdatedLast = nTransactionsUpdated;
  CBlockIndex* pindexPrevNew = pindexBest;

  pblock = CreateNewBlock(reservekey);
  if (!pblock)
    return (NULL);

  // Need to update only after we know CreateNewBlock succeeded
  pindexPrev = pindexPrevNew;

  /* store "worker" block for until height increment. */
  work_id++;
  mapWork[work_id] = pblock; 

  // Update nTime
  pblock->UpdateTime(pindexPrev);
  pblock->nNonce = 0;

  SetNextDifficulty(pblock->nBits);

  Array transactions;
  //map<uint256, int64_t> setTxIndex;
  int i = 0;
  CTxDB txdb("r");
  BOOST_FOREACH (CTransaction& tx, pblock->vtx)
  {
    uint256 txHash = tx.GetHash();

    if (tx.IsCoinBase())
      continue;
    transactions.push_back(txHash.GetHex());
  }

  uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

  fprintf(stderr, "DEBUG: getblocktemplate: target hash '%s'\n",
      hashTarget.GetHex().c_str());
  fprintf(stderr, "DEBUG: getblocktemplate: target diff %f\n", 
      (double)0x0000ffff / (double)(pblock->nBits & 0x00ffffff));

  Object result;

  /* all pool mining is defunc when "connections=0". */
  result.push_back(Pair("connections",   (int)vNodes.size()));

  result.push_back(Pair("version", pblock->nVersion));
  result.push_back(Pair("task", (int64_t)work_id));
  result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
  result.push_back(Pair("transactions", transactions));
  result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
  result.push_back(Pair("target", hashTarget.GetHex()));
  result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE));
  result.push_back(Pair("curtime", (int64_t)pblock->nTime));
  result.push_back(Pair("bits", HexBits(pblock->nBits)));

  if (!pindexPrev) {
    /* mining is defunct when "height < 2" */
    result.push_back(Pair("height", (int64_t)0));
  } else {
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));
  }

  /* dummy nExtraNonce */
  SetExtraNonce(pblock, "f0000000f0000000");

  /* coinbase */
  CTransaction coinbaseTx = pblock->vtx[0];
  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
  ssTx << coinbaseTx;
  result.push_back(Pair("coinbase", HexStr(ssTx.begin(), ssTx.end())));
  //  result.push_back(Pair("sigScript", HexStr(pblock->vtx[0].vin[0].scriptSig.begin(), pblock->vtx[0].vin[0].scriptSig.end())));
  result.push_back(Pair("coinbaseflags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

  blocktemplate_json = JSONRPCReply(result, Value::null, Value::null);
  return (blocktemplate_json.c_str());
}

int c_processblock(CBlock* pblock)
{
  CNode *pfrom = NULL;

  // Check for duplicate
  uint256 hash = pblock->GetHash();
  if (mapBlockIndex.count(hash))// || mapOrphanBlocks.count(hash))
    return (BLKERR_DUPLICATE_BLOCK);

  // Preliminary checks
  if (!pblock->CheckBlock()) {
fprintf(stderr, "DEBUG: c_processblock: !CheckBlock()\n");
    return (BLKERR_CHECKPOINT);
  }

  // Store to disk
  if (!pblock->AcceptBlock()) {
fprintf(stderr, "DEBUG: c_processblock: !AcceptBlock()\n");
    return (BLKERR_INVALID_BLOCK);
  }

  pblock->print();

  return (0);
}

#if 0
static bool QuickCheckWork(CBlock* pblock, double *ret_diff)
{
  uint256 hash = pblock->GetPoWHash();
  uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
//  uint256 bhash = Hash(BEGIN(pblock->nVersion), END(pblock->nNonce));

  if (ret_diff)
    *ret_diff = GetBitsDifficulty(hash.GetCompact());

  if (hash > hashTarget)
    return false;

fprintf(stderr, "generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

  return true;
}
#endif

#if 0
  fprintf(stderr, "DEBUG: submitblock: previousblockhash %s\n", pblock->hashPrevBlock.GetHex().c_str());
  fprintf(stderr, "DEBUG: submitblock: previousblockhash %s\n", HexStr(pblock->hashPrevBlock.begin(), pblock->hashPrevBlock.end()).c_str());
  CTransaction coinbaseTx = pblock->vtx[0];
  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
  ssTx << coinbaseTx;
  fprintf(stderr, "DEBUG: submitblock: coinbase %s\n", HexStr(ssTx.begin(), ssTx.end()).c_str());
  fprintf(stderr, "DEBUG: sigScript: %s\n", HexStr(pblock->vtx[0].vin[0].scriptSig.begin(), pblock->vtx[0].vin[0].scriptSig.end()).c_str());
  fprintf(stderr, "DEBUG: submitblock: merkleroot %s\n", pblock->hashMerkleRoot.GetHex().c_str());
  fprintf(stderr, "DEBUG: submitblock: merkleroot %s\n", HexStr(pblock->hashMerkleRoot.begin(), pblock->hashMerkleRoot.end()).c_str());
  fprintf(stderr, "DEBUG: submitblock: hash %s\n", pblock->GetHash().GetHex().c_str());
  fprintf(stderr, "DEBUG: submitblock: target %s\n",  CBigNum().SetCompact(pblock->nBits).GetHex().c_str());
#endif
int c_submitblock(unsigned int workId, unsigned int nTime, unsigned int nNonce, char *xn_hex, char *ret_hash, double *ret_diff)
{
  CBlock *pblock;
  uint256 hash;
  uint256 hashTarget;
  int err;
  bool ok;

  if (ret_hash)
    ret_hash[0] = '\000';
  if (ret_diff)
    *ret_diff = 0.0;

  pblock = mapWork[workId];
  if (pblock == NULL)
    return (SHERR_TIME); /* task is stale */

  if (pblock->nNonce == nNonce)
    return (SHERR_ALREADY);

  pblock->nTime = nTime;
  pblock->nNonce = nNonce;
  SetExtraNonce(pblock, xn_hex);
  pblock->hashMerkleRoot = pblock->BuildMerkleTree();
fprintf(stderr, "DEBUG: submitblock: nTime(%u) nNonce(%u) xNonce(%s)\n", (unsigned int)nTime, (unsigned int)nNonce, xn_hex);

  hash = pblock->GetPoWHash();
  hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

  if (ret_diff) {
    const char *hash_str = hash.ToString().c_str();
    char nbit_str[256];
    unsigned int nbit;

    memset(nbit_str, '\000', sizeof(nbit_str));
    strcpy(nbit_str, hash.ToString().substr(0,8).c_str());

    nbit = (unsigned int)strtoll(nbit_str, NULL, 16);
    if (nbit == 0) nbit = 1;

    *ret_diff = ((double)0x0000ffff /  (double)nbit);
fprintf(stderr, "DEBUG: submit_block: share nbits '%s' with diff %f [hash length %d, hash '%s']\n", nbit_str, *ret_diff, strlen(hash_str), hash_str);
  }

  if (hash > hashTarget) {
fprintf(stderr, "DEBUG: submitblock: proof-of-work not found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    return (0); /* share was submitted successfully */
  }

  err = c_processblock(pblock);
  if (!err) {
    string submit_block_hash;
    char errbuf[1024];

    submit_block_hash = pblock->GetHash().GetHex();
    if (ret_hash)
      strcpy(ret_hash, submit_block_hash.c_str());

 fprintf(stderr, "proof-of-work found: hash(%s) target(%s)\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();


    sprintf(errbuf, "submitblock: mined block (%s) generated %s coins.\n", submit_block_hash.c_str(), FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());
    shcoind_log(errbuf);
  } else {
fprintf(stderr, "DEBUG: submitblock: processblock error %d\n", err); 
pblock->print();
}

  return (0);
}

Object c_AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Object entry)
{
  bool fAllAccounts = (strAccount == string("*"));

  if (fAllAccounts || acentry.strAccount == strAccount)
  {
    entry.push_back(Pair("account", acentry.strAccount));
    entry.push_back(Pair("category", "move"));
    entry.push_back(Pair("time", (boost::int64_t)acentry.nTime));
    entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
    entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
    entry.push_back(Pair("comment", acentry.strComment));
  }

  return (entry);
}

#if 0
bool c_ListGenerateTransactions(const CWalletTx& wtx, Object entry)
{
  string strAccount = "*";
  int64 nGeneratedImmature, nGeneratedMature, nFee;
  string strSentAccount;
  list<pair<CTxDestination, int64> > listReceived;
  list<pair<CTxDestination, int64> > listSent;

  wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount);

  bool fAllAccounts = (strAccount == string("*"));

  // Generated blocks assigned to account ""
  //if ((nGeneratedMature+nGeneratedImmature) != 0) {
  if (nGeneratedMature) {
    entry.push_back(Pair("account", string("")));
    entry.push_back(Pair("category", "generate"));
    entry.push_back(Pair("amount", ValueFromAmount(nGeneratedMature)));
    WalletTxToJSON(wtx, entry);
    return (true);
  }

  return (false);
}
#endif
void c_ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret)
{
  int64 nGeneratedImmature, nGeneratedMature, nFee;
  string strSentAccount;
  list<pair<CTxDestination, int64> > listReceived;
  list<pair<CTxDestination, int64> > listSent;

  wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount);

  bool fAllAccounts = (strAccount == string("*"));

  // Generated blocks assigned to account ""
  if (nGeneratedMature != 0)
  {
    Object entry;
    entry.push_back(Pair("account", string("")));
    if (nGeneratedImmature)
    {
      entry.push_back(Pair("category", wtx.GetDepthInMainChain() ? "immature" : "orphan"));
      entry.push_back(Pair("amount", ValueFromAmount(nGeneratedImmature)));
    }
    else
    {
      entry.push_back(Pair("category", "generate"));
      entry.push_back(Pair("amount", ValueFromAmount(nGeneratedMature)));
    }
    if (fLong)
      WalletTxToJSON(wtx, entry);
    ret.push_back(entry);
  }

}

const char *c_getblocktransactions(void)
{
  string strAccount = "";
  int nCount = 1;
  int nFrom = 0;
  Array ret;
  CWalletDB walletdb(pwalletMain->strWalletFile);


  // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
  typedef pair<CWalletTx*, CAccountingEntry*> TxPair;
  typedef multimap<int64, TxPair > TxItems;
  TxItems txByTime;

  // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
  // would make this much faster for applications that do this a lot.
  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
  {
    CWalletTx* wtx = &((*it).second);
    txByTime.insert(make_pair(wtx->GetTxTime(), TxPair(wtx, (CAccountingEntry*)0)));
  }

/*
  list<CAccountingEntry> acentries;
  walletdb.ListAccountCreditDebit(strAccount, acentries);
  BOOST_FOREACH(CAccountingEntry& entry, acentries)
  {
    txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
  }
*/

  if ((int)vNodes.size() > 1) { /* if more than one usde server connection */
    // iterate backwards until we have nCount items to return:
    for (TxItems::reverse_iterator it = txByTime.rbegin(); it != txByTime.rend(); ++it)
    {
      CWalletTx *const pwtx = (*it).second.first;
      if (pwtx != 0)
        c_ListTransactions(*pwtx, strAccount, 0, true, ret);
      /*
         CAccountingEntry *const pacentry = (*it).second.second;
         if (pacentry != 0)
         AcentryToJSON(*pacentry, strAccount, ret);
         */

      if ((int)ret.size() >= (nCount+nFrom)) break;
    }
  }

  // ret is newest to oldest
  if (nFrom > (int)ret.size())
    nFrom = ret.size();
  if ((nFrom + nCount) > (int)ret.size())
    nCount = ret.size() - nFrom;
  Array::iterator first = ret.begin();
  std::advance(first, nFrom);
  Array::iterator last = ret.begin();
  std::advance(last, nFrom+nCount);

  if (last != ret.end()) ret.erase(last, ret.end());
  if (first != ret.begin()) ret.erase(ret.begin(), first);

  /* convert to a json string. */
  if (ret.size() > 0)
    blocktemplate_json = JSONRPCReply(ret.at(0), Value::null, Value::null);
  else
    blocktemplate_json = JSONRPCReply(ret, Value::null, Value::null);
  return (blocktemplate_json.c_str());
}

#if 0
const char *c_getblocktransactions(void)
{

  string strAccount = "*";
  int nCount = 10;
  int nFrom = 0;


//  Array ret;
  CWalletDB walletdb(pwalletMain->strWalletFile);

  // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
  typedef pair<CWalletTx*, CAccountingEntry*> TxPair;
  typedef multimap<int64, TxPair > TxItems;
  TxItems txByTime;

  // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
  // would make this much faster for applications that do this a lot.
  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
  {
    CWalletTx* wtx = &((*it).second);
    txByTime.insert(make_pair(wtx->GetTxTime(), TxPair(wtx, (CAccountingEntry*)0)));
  }
  list<CAccountingEntry> acentries;
  walletdb.ListAccountCreditDebit(strAccount, acentries);
  BOOST_FOREACH(CAccountingEntry& entry, acentries)
  {
    txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
  }

  Object result;

  // iterate backwards until we have nCount items to return:
  for (TxItems::reverse_iterator it = txByTime.rbegin(); it != txByTime.rend(); ++it)
  {
    CWalletTx *const pwtx = (*it).second.first;
    if (pwtx != 0) {
      if (c_ListGenerateTransactions(*pwtx, result))
        break; /* found mature generation. */
    }
  }
  // ret is newest to oldest

  blocktemplate_json = JSONRPCReply(result, Value::null, Value::null);
  return (blocktemplate_json.c_str());
}
#endif

double c_GetNetworkHashRate(void)
{
  int lookup = 120;

  if (pindexBest == NULL)
    return 0;

  // If lookup is -1, then use blocks since last difficulty change.
  if (lookup <= 0)
    lookup = pindexBest->nHeight % 2016 + 1;

  // If lookup is larger than chain, then set it to chain length.
  if (lookup > pindexBest->nHeight)
    lookup = pindexBest->nHeight;

  CBlockIndex* pindexPrev = pindexBest;
  for (int i = 0; i < lookup; i++)
    pindexPrev = pindexPrev->pprev;

  double timeDiff = pindexBest->GetBlockTime() - pindexPrev->GetBlockTime();
  double timePerBlock = timeDiff / lookup;

  return ((double)GetDifficulty() * pow(2.0, 32)) / (double)timePerBlock;
}

const char *c_getmininginfo(void)
{
  Array result;

  result.push_back((int)nBestHeight);

  if (nextDifficulty > 0.00000000)
    result.push_back((double)nextDifficulty);
  else
    result.push_back((double)GetDifficulty());

  result.push_back((double)c_GetNetworkHashRate());

  mininginfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (mininginfo_json.c_str());
}

double c_getdifficulty(void)
{
  return ((double)GetDifficulty());
}

string blockinfo_json;
const char *c_getblockindexinfo(CBlockIndex *pblockindex)
{
  CBlock block;
  Object result;

  block.ReadFromDisk(pblockindex, true);

  result.push_back(Pair("hash", block.GetHash().GetHex()));
  CMerkleTx txGen(block.vtx[0]);
  txGen.SetMerkleBranch(&block);
  result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
  result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
  result.push_back(Pair("height", pblockindex->nHeight));
  result.push_back(Pair("version", block.nVersion));
  result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));

  Array txs;
  int64 nAmount = 0;
  BOOST_FOREACH(const CTransaction&tx, block.vtx) {
    txs.push_back(tx.GetHash().GetHex());
    nAmount += tx.GetValueOut();
  }
  result.push_back(Pair("tx", txs));
  result.push_back(Pair("amount", ValueFromAmount(nAmount)));

  result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
  result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
  result.push_back(Pair("bits", HexBits(block.nBits)));
  result.push_back(Pair("difficulty", GetDifficulty(pblockindex)));

  if (pblockindex->pprev)
    result.push_back(Pair("previousblockhash", pblockindex->pprev->GetBlockHash().GetHex()));
  if (pblockindex->pnext)
    result.push_back(Pair("nextblockhash", pblockindex->pnext->GetBlockHash().GetHex()));

  blockinfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (blockinfo_json.c_str());
}
const char *c_getblockinfo(const char *hash_addr)
{
  long nHeight;

  if (!hash_addr)
    return (NULL);

  std::string strHash(hash_addr);

  if (strlen(hash_addr) <= 12 && (nHeight = atol(hash_addr))) {
    /* convert block index to block hash */
    if (nHeight < 0 || nHeight > nBestHeight) {
      //throw runtime_error("Block number out of range.");
      //fprintf(stderr, "DEBUG: Block number (%d) out of range.", nHeight);
      return (NULL);
    }

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hashBestChain];
    while (pblockindex->nHeight > nHeight)
      pblockindex = pblockindex->pprev;
    strHash = pblockindex->phashBlock->GetHex();
  }

  uint256 hash(strHash);
  if (mapBlockIndex.count(hash) == 0) {
//    throw JSONRPCError(-5, "Block not found");
    return (NULL);
  }

  CBlockIndex* pblockindex = mapBlockIndex[hash];
  return (c_getblockindexinfo(pblockindex));
}
#if 0
  CBlock block;
  block.ReadFromDisk(pblockindex, true);

  Object result;
  result.push_back(Pair("hash", block.GetHash().GetHex()));
  CMerkleTx txGen(block.vtx[0]);
  txGen.SetMerkleBranch(&block);
  result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
  result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
  result.push_back(Pair("height", pblockindex->nHeight));
  result.push_back(Pair("version", block.nVersion));
  result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
  Array txs;
  BOOST_FOREACH(const CTransaction&tx, block.vtx)
    txs.push_back(tx.GetHash().GetHex());
  result.push_back(Pair("tx", txs));
  result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
  result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
  result.push_back(Pair("bits", HexBits(block.nBits)));
  result.push_back(Pair("difficulty", GetDifficulty(pblockindex)));

  if (pblockindex->pprev)
    result.push_back(Pair("previousblockhash", pblockindex->pprev->GetBlockHash().GetHex()));
  if (pblockindex->pnext)
    result.push_back(Pair("nextblockhash", pblockindex->pnext->GetBlockHash().GetHex()));

  blockinfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (blockinfo_json.c_str());
}
#endif

int findBlockTransaction(CBlockIndex *pblockindex, const char *tx_id, CTransaction& ret_tx, time_t dur)
{
  CBlock block;
  uint256 hashTx;
  int64 nOut;
  int confirms;
  time_t min_t;

  if (!tx_id || !*tx_id)
    return (NULL);

  hashTx.SetHex(tx_id);

  min_t = 0;
  if (dur)
    min_t = time(NULL) - dur;

  block.ReadFromDisk(pblockindex, true);
  if (min_t && ((time_t)block.GetBlockTime() < min_t)) {
    /* exceeds duration limit */
    return (-1);
  }
  BOOST_FOREACH(CTransaction&tx, block.vtx) {
/*
    std::string txStr = tx.GetHash().GetHex();
    if (0 == strcasecmp(txStr.c_str(), tx_id)) {
      ret_tx = tx;
      return (0);
    }
*/
    if (tx.GetHash() == hashTx) {
      ret_tx = tx;
      return (0);
    }

  }

  return (-1);
}

CBlockIndex *findTransaction(uint256 hashTx, CTransaction& ret_tx, time_t dur)
{
  CTxDB txdb("r");
  CBlockIndex *pblockindex;
  CTxIndex txindex;
  time_t min_t;
  bool ok;

  /* find transaction (weed out false requests) */
  ok = txdb.ReadTxIndex(hashTx, txindex);
  if (!ok)
    return (NULL);

  min_t = 0;
  if (dur)
    min_t = time(NULL) - dur;

#if 0
  /* load transaction */
  ok = ret_tx.ReadFromDisk(txindex.pos);
  if (!ok)
    return (NULL);
#endif

  /* find block (slow disk crawl) */
  for (pblockindex = pindexBest; pblockindex; pblockindex = pblockindex->pprev)  {
    CBlock block;
    CTransaction tx;

    block.ReadFromDisk(pblockindex, true);
    if (min_t && ((time_t)block.GetBlockTime() < min_t)) {
      /* exceeds duration limit */
      return (NULL);
    }

    BOOST_FOREACH(CTransaction&tx, block.vtx) {
      if (hashTx == tx.GetHash()) {
        ret_tx = tx;
//        transactionMap[hashTx] = pblockindex;
        return (pblockindex);
      }
    }
  }

  return (NULL);
}


#if 0
CBlockIndex *findBlockByTransaction(const char *tx_id)
{
  CBlockIndex *pblockindex;

  for (pblockindex = pindexBest; pblockindex; pblockindex = pblockindex->pprev)  {
    CBlock block;

    block.ReadFromDisk(pblockindex, true);
    BOOST_FOREACH(const CTransaction&tx, block.vtx) {
      std::string txStr = tx.GetHash().GetHex();
      if (0 == strcasecmp(txStr.c_str(), tx_id))
        return (pblockindex);
    }
  }

  return (NULL);
}
#endif

int64 GetTxFee(CTransaction tx)
{
  map<uint256, CTxIndex> mapQueuedChanges;
  MapPrevTx inputs;
  int64 nFees;
  int i;

  if (tx.IsCoinBase())
    return (0);

  CTxDB txdb;

  nFees = 0;
  bool fInvalid = false;
  if (tx.FetchInputs(txdb, mapQueuedChanges, true, false, inputs, fInvalid))
    nFees += tx.GetValueIn(inputs) - tx.GetValueOut();

  txdb.Close();

  return (nFees);
}

#define MAX_HISTORY_TIME 10454400 /* 1/3 year */
const char *c_gettransactioninfo(const char *tx_id)
{
  CTransaction tx;
  CBlockIndex *pblockindex;
  Object result;
  shtime_t ts;
  uint256 hashBlock;
  uint256 hashTx;
  int64 nOut;
  int confirms;
  int err;

  if (!tx_id || !*tx_id)
    return (NULL);


  hashTx.SetHex(tx_id);
//  pblockindex = transactionMap[hashTx]; /* check tx map */
  if (!pblockindex) {
    timing_init("findTransaction", &ts);
    pblockindex = findTransaction(hashTx, tx, MAX_HISTORY_TIME);
    timing_term("findTransaction", &ts);
    if (!pblockindex)
      return (NULL);

    hashTx = tx.GetHash();
  } else {
    timing_init("findBlockTransaction", &ts);
    err = findBlockTransaction(pblockindex, tx_id, tx, MAX_HISTORY_TIME);
    timing_term("findBlockTransaction", &ts);
    if (err)
      return (NULL);
  }

  hashBlock = 0;
  if (pblockindex)
    hashBlock = pblockindex->GetBlockHash();

  if (hashBlock != 0)
  {
    result.push_back(Pair("blockhash", hashBlock.GetHex()));

    if (!pblockindex) { /* redundant secondary lookup */
      map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
      if (mi != mapBlockIndex.end() && (*mi).second) {
        pblockindex = (*mi).second;
      }
    }

    if (pblockindex && pblockindex->IsInMainChain())
    {
      result.push_back(Pair("confirmations", 1 + nBestHeight - pblockindex->nHeight));
      result.push_back(Pair("time", (boost::int64_t)pblockindex->nTime));
    }
    else {
      result.push_back(Pair("confirmations", 0));
    }
  }

  result.push_back(Pair("txid", tx.GetHash().GetHex()));
  result.push_back(Pair("version", tx.nVersion));
  result.push_back(Pair("locktime", (boost::int64_t)tx.nLockTime));
  result.push_back(Pair("amount", ValueFromAmount(tx.GetValueOut())));
  result.push_back(Pair("fee", ValueFromAmount(GetTxFee(tx))));

  Array vin;
  BOOST_FOREACH(const CTxIn& txin, tx.vin)
  {
    Object in;
    if (tx.IsCoinBase())
      in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    else
    {
      in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
      in.push_back(Pair("vout", (boost::int64_t)txin.prevout.n));
      in.push_back(Pair("asm", txin.scriptSig.ToString()));
      in.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    }
    in.push_back(Pair("sequence", (boost::int64_t)txin.nSequence));
    vin.push_back(in);
  }
  result.push_back(Pair("vin", vin));

  Array vout;
  for (unsigned int i = 0; i < tx.vout.size(); i++)
  {
    const CTxOut& txout = tx.vout[i];
    Object out;
    out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
    out.push_back(Pair("n", (boost::int64_t)i));
    ScriptPubKeyToJSON(txout.scriptPubKey, out);
    vout.push_back(out);
  }
  result.push_back(Pair("vout", vout));

  transactioninfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (transactioninfo_json.c_str());
}
#if 0
const char *c_gettransactioninfo(const char *tx_id)
{

  if (!tx_id)
    return (NULL);

  std::string txStr(tx_id);
  uint256 hash;
  hash.SetHex(txStr);

  Object result;
  if (!pwalletMain->mapWallet.count(hash)) {
    //  throw JSONRPCError(-5, "Invalid or non-wallet transaction id");
    return (NULL);
  }
  const CWalletTx& wtx = pwalletMain->mapWallet[hash];

  int64 nCredit = wtx.GetCredit();
  int64 nDebit = wtx.GetDebit();
  int64 nNet = nCredit - nDebit;
  int64 nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);

  result.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
  //if (wtx.IsFromMe())
  result.push_back(Pair("fee", ValueFromAmount(nFee)));

  int confirms = wtx.GetDepthInMainChain();
  result.push_back(Pair("confirmations", confirms));
  if (confirms)
  {
    result.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
    result.push_back(Pair("blockindex", wtx.nIndex));
  }
  result.push_back(Pair("txid", wtx.GetHash().GetHex()));
  result.push_back(Pair("time", (boost::int64_t)wtx.GetTxTime()));
  BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
    result.push_back(Pair(item.first, item.second));

  Array details;
  ListTransactions(wtx, "*", 0, false, details);
  result.push_back(Pair("details", details));

  transactioninfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (transactioninfo_json.c_str());
}
#endif

const char *c_getlastblockinfo(int target_height)
{
  CBlockIndex *block;
  uint256 blockId;
  int blockHeight;

  for (block = pindexBest; block; block = block->pprev)  {
    if (target_height == 0 || block->nHeight == target_height)
      return (c_getblockindexinfo(block));
  }

  return (NULL);
}

uint64_t c_getblockheight(void)
{
  
  if (!pindexBest) {
    /* mining is defunct when "height < 2" */
    return (0);
  }

  return ((int64_t)(pindexBest->nHeight+1));
}

string miningtransactioninfo_json;
const char *c_getminingtransactions(unsigned int workId)
{
  Array result;
//  map<uint256, int64_t> setTxIndex;
  int i = 0;
  CBlock *pblock;
  int err;
  bool ok;

  pblock = mapWork[workId];
  if (pblock == NULL)
    return (NULL);

  CTxDB txdb("r");
  BOOST_FOREACH (CTransaction& tx, pblock->vtx)
  {
//    uint256 txHash = tx.GetHash();
//    setTxIndex[txHash] = i++;
    Object entry;

/*
    if (tx.IsCoinBase())
      continue;
*/

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;

    result.push_back(HexStr(ssTx.begin(), ssTx.end()));
  }

  miningtransactioninfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (miningtransactioninfo_json.c_str());
}

string block_save_json;
bool WriteToShareNet(CBlock* pBlock, int nHeight)
{
  Object result;
  Array transactions;
  int err;

  result.push_back(Pair("version", pBlock->nVersion));
  result.push_back(Pair("height", (int64_t)nHeight));
  result.push_back(Pair("hash", pBlock->GetHash().ToString()));
  result.push_back(Pair("prevblock", pBlock->hashPrevBlock.GetHex()));
  result.push_back(Pair("merkleroot", pBlock->hashMerkleRoot.GetHex()));
  result.push_back(Pair("time", (int64_t)pBlock->nTime));
  result.push_back(Pair("bits", (int64_t)pBlock->nBits));
  result.push_back(Pair("nonce", (int64_t)pBlock->nNonce));

  //CTxDB txdb("r");
  BOOST_FOREACH (CTransaction& tx, pBlock->vtx)
  {
    uint256 txHash = tx.GetHash();

    Object entry;

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    transactions.push_back(HexStr(ssTx.begin(), ssTx.end()));
  }
  result.push_back(Pair("transactions", transactions));

  block_save_json = JSONRPCReply(result, Value::null, Value::null);
  err = block_save(nHeight, block_save_json.c_str());
  if (err)
    return false;

  return true;
}

extern bool LoadExternalBlockFile(FILE* fileIn);
const int cxx_reloadblockfile(const char *path)
{
  string strFile(path);
  FILE *file;

  file = fopen(path, "rb");
  if (!file)
    return (-1);

  LoadExternalBlockFile(file);
  return (0);
}


#ifdef __cplusplus
extern "C" {
#endif

const char *getblocktemplate(void)
{
  return (c_getblocktemplate());
}

int submitblock(unsigned int workId, unsigned int nTime, unsigned int nNonce, char *xn_hex, char *ret_hash, double *ret_diff)
{
  return (c_submitblock(workId, nTime, nNonce, xn_hex, ret_hash, ret_diff));
}

const char *getblocktransactions(void)
{
  return (c_getblocktransactions());
}

const char *getmininginfo(void)
{
  return (c_getmininginfo());
}

double getdifficulty(void)
{
  return (c_getdifficulty());
}

const char *getblockinfo(const char *hash)
{
  return (c_getblockinfo(hash));
}

const char *gettransactioninfo(const char *hash)
{
  return (c_gettransactioninfo(hash));
}

const char *getlastblockinfo(int height)
{
  return (c_getlastblockinfo(height));
}

uint64_t getblockheight(void)
{
  return (c_getblockheight());
}

const char *getminingtransactioninfo(unsigned int workId)
{
  return (c_getminingtransactions(workId));
}
const int reloadblockfile(const char *path)
{
  return (cxx_reloadblockfile(path));
}

#ifdef __cplusplus
}
#endif

