
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

#include "shcoind.h"
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>

using namespace std;
using namespace json_spirit;

#include "block.h"
#include "wallet.h"
#include "certificate.h"
#include "alias.h"


alias_list *GetAliasTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapAlias);
}

alias_list *GetAliasPendingTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapAlias);
}

bool DecodeAliasHash(const CScript& script, int& mode, uint160& hash)
{
  CScript::const_iterator pc = script.begin();
  opcodetype opcode;
  int op;

  if (!script.GetOp(pc, opcode)) {
    return false;
  }
  mode = opcode; /* extension mode (new/activate/update) */
  if (mode < 0xf0 || mode > 0xf9)
    return false;

  if (!script.GetOp(pc, opcode)) { 
    return false;
  }
  if (opcode < OP_1 || opcode > OP_16) {
    return false;
  }
  op = CScript::DecodeOP_N(opcode); /* extension type (alias) */
  if (op != OP_ALIAS) {
    return false;
  }

  vector<unsigned char> vch;
  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  if (opcode != OP_HASH160)
    return (false);

  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  hash = uint160(vch);
  return (true);
}




#if 0
void RemoveAliasTxnFromMemoryPool(const CTransaction& tx) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return;

	if (tx.vout.size() < 1)
		return;

	vector<vector<unsigned char> > vvch;

	int op;
	int nOut;

	if (!DecodeAliasTx(tx, op, nOut, vvch, -1))
		return;

	if (op != OP_ALIAS_NEW) {
		{
			TRY_LOCK(cs_main, cs_trymain);
			std::map<std::vector<unsigned char>, std::set<uint256> >::iterator mi =
					mapAliasesPending.find(vvch[0]);
			if (mi != mapAliasesPending.end())
				mi->second.erase(tx.GetHash());
		}
	}
}

void PutToAliasList(std::vector<CAliasIndex> &aliasList, CAliasIndex& index) {
	int i = aliasList.size() - 1;
	BOOST_REVERSE_FOREACH(CAliasIndex &o, aliasList) {
        if(index.nHeight != 0 && o.nHeight == index.nHeight) {
        	aliasList[i] = index;
            return;
        }
        else if(o.txHash != 0 && o.txHash == index.txHash) {
        	aliasList[i] = index;
            return;
        }
        i--;
	}
    aliasList.push_back(index);
}



int GetMinActivateDepth() {
	if (fCakeNet)
		return MIN_ACTIVATE_DEPTH_CAKENET;
	else
		return MIN_ACTIVATE_DEPTH;
}


bool InsertAliasFee(CBlockIndex *pindex, uint256 hash, uint64 vValue) {
	TRY_LOCK(cs_main, cs_trymain);
	list<CAliasFee> txnDup;
	CAliasFee txnVal(hash, pindex->nTime, pindex->nHeight, vValue);
	bool bFound = false;

	BOOST_FOREACH(CAliasFee &nmTxnValue, lstAliasFees) {
		if (txnVal.hash == nmTxnValue.hash
				&& txnVal.nHeight == nmTxnValue.nHeight) {
			nmTxnValue = txnVal;
			bFound = true;
			break;
		}
	}
	if (!bFound)
		lstAliasFees.push_front(txnVal);
	return bFound;
}

bool RemoveAliasFee(CAliasFee &txnVal) {
	TRY_LOCK(cs_main, cs_trymain);
	CAliasFee *theval = NULL;
	if(lstAliasFees.size()==0) return false;

	BOOST_FOREACH(CAliasFee &nmTxnValue, lstAliasFees) {
		if (txnVal.hash == nmTxnValue.hash
		 && txnVal.nHeight == nmTxnValue.nHeight) {
			theval = &nmTxnValue;
			break;
		}
	}

	if(theval)
		lstAliasFees.remove(*theval);
	return theval != NULL;
}

uint64 GetAliasFeeSubsidy(unsigned int nHeight) {
	uint64 hr1 = 1, hr12 = 1;
	{
		TRY_LOCK(cs_main, cs_trymain);

		unsigned int h12 = 60 * 60 * 12;
		unsigned int nTargetTime = 0;
		unsigned int nTarget1hrTime = 0;
		unsigned int blk1hrht = nHeight - 1, blk12hrht = nHeight - 1;
		bool bFound = false;

		BOOST_FOREACH(CAliasFee &nmTxnValue, lstAliasFees) {
			if (nmTxnValue.nHeight <= nHeight)
				bFound = true;
			if (bFound) {
				if (nTargetTime == 0) {
					hr1 = hr12 = 0;
					nTargetTime = nmTxnValue.nBlockTime - h12;
					nTarget1hrTime = nmTxnValue.nBlockTime - (h12 / 12);
				}
				if (nmTxnValue.nBlockTime > nTargetTime) {
					hr12 += nmTxnValue.nValue;
					blk12hrht = nmTxnValue.nHeight;
					if (nmTxnValue.nBlockTime > nTarget1hrTime) {
						hr1 += nmTxnValue.nValue;
						blk1hrht = nmTxnValue.nHeight;
					}
				}
			}
		}
		hr12 /= (nHeight - blk12hrht) + 1;
		hr1 /= (nHeight - blk1hrht) + 1;
	//	printf("GetAliasFeeSubsidy() : Alias fee mining reward for height %d: %llu\n", nHeight, nSubsidyOut);
	}
	return (hr12 + hr1) / 2;
}


// get the depth of transaction txnindex relative to block at index pIndexBlock, looking
// up to maxdepth. Return relative depth if found, or -1 if not found and maxdepth reached.
int CheckTransactionAtRelativeDepth(CBlockIndex* pindexBlock,
		const CCoins *txindex, int maxDepth) {
	for (CBlockIndex* pindex = pindexBlock;
			pindex && pindexBlock->nHeight - pindex->nHeight < maxDepth;
			pindex = pindex->pprev)
		if (pindex->nHeight == (int) txindex->nHeight)
			return pindexBlock->nHeight - pindex->nHeight;
	return -1;
}


int GetAliasHeight(vector<unsigned char> vchName) {
	vector<CAliasIndex> vtxPos;
	if (paliasdb->ExistsAlias(vchName)) {
		if (!paliasdb->ReadAlias(vchName, vtxPos))
			return error("GetAliasHeight() : failed to read from alias DB");
		if (vtxPos.empty())
			return -1;
		CAliasIndex& txPos = vtxPos.back();
		return txPos.nHeight;
	}
	return -1;
}

// Check that the last entry in name history matches the given tx pos
bool CheckAliasTxPos(const vector<CAliasIndex> &vtxPos, const int txPos) {
	if (vtxPos.empty())
		return false;
	return vtxPos.back().nHeight == txPos;
}


bool CheckAliasInputs(CBlockIndex *pindexBlock, const CTransaction &tx,
		CValidationState &state, CCoinsViewCache &inputs,
		map<vector<unsigned char>, uint256> &mapTestPool, bool fBlock,
		bool fMiner, bool fJustCheck) {

	if (!tx.IsCoinBase()) {

		bool found = false;
		const COutPoint *prevOutput = NULL;
		const CCoins *prevCoins = NULL;
		int prevOp;
		vector<vector<unsigned char> > vvchPrevArgs;

		// Strict check - bug disallowed
		for (int i = 0; i < (int) tx.vin.size(); i++) {
			prevOutput = &tx.vin[i].prevout;
			prevCoins = &inputs.GetCoins(prevOutput->hash);
			vector<vector<unsigned char> > vvch;
			if (DecodeAliasScript(prevCoins->vout[prevOutput->n].scriptPubKey,
					prevOp, vvch)) {
				found = true;
				vvchPrevArgs = vvch;
				break;
			}
		}

		// Make sure alias outputs are not spent by a regular transaction, or the alias would be lost
		if (tx.nVersion != SYSCOIN_TX_VERSION) {
			if (found)
				return error(
						"CheckAliasInputs() : a non-syscoin transaction with a syscoin input");
			return true;
		}

		// decode alias info from transaction
		vector<vector<unsigned char> > vvchArgs;
		int op, nOut, nPrevHeight;
		int64 nDepth;
		if (!DecodeAliasTx(tx, op, nOut, vvchArgs, -1))
			return error(
					"CheckAliasInputs() : could not decode syscoin alias info from tx %s",
					tx.GetHash().GetHex().c_str());
		int64 nNetFee;

#if 0
		fprintf(stderr, "DEBUG: %s : name=%s, tx=%s\n", aliasFromOp(op).c_str(),
				stringFromVch(
						op == OP_ALIAS_NEW ?
								vchFromString(HexStr(vvchArgs[0])) :
								vvchArgs[0]).c_str(),
				tx.GetHash().GetHex().c_str());
#endif

		switch (op) {

		case OP_ALIAS_NEW:

			// validate inputs
			if (found)
				return error(
						"CheckAliasInputs() : aliasnew tx pointing to previous syscoin tx");
			if (vvchArgs[0].size() != 20)
				return error("aliasnew tx with incorrect hash length");

			printf("CONNECTED ALIAS: name=%s  op=%s  hash=%s  height=%d\n",
					HexStr(vvchArgs[0]).c_str(), aliasFromOp(op).c_str(),
					tx.GetHash().ToString().c_str(), pindexBlock->nHeight);

			break;

		case OP_ALIAS_ACTIVATE:

			// verify enough fees with this txn
			nNetFee = GetAliasReturnFee(tx);
			if (nNetFee < GetAliasNetworkFee(1, pindexBlock->nHeight))
				return error(
						"CheckAliasInputs() : got tx %s with fee too low %lu",
						tx.GetHash().GetHex().c_str(),
						(long unsigned int) nNetFee);

			// veryify that prev txn is aliasnew
			if ((!found || prevOp != OP_ALIAS_NEW) && !fJustCheck)
				return error(
						"CheckAliasInputs() : aliasactivate tx without previous aliasnew tx");

			// verify rand and value lengths
			if (vvchArgs[1].size() > 20)
				return error("aliasactivate tx with guid too big");
			if (vvchArgs[2].size() > MAX_VALUE_LENGTH)
				return error("aliasactivate tx with value too long");

			if (fBlock && !fJustCheck) {
				// Check hash
				const vector<unsigned char> &vchHash = vvchPrevArgs[0];
				const vector<unsigned char> &vchName = vvchArgs[0];
				const vector<unsigned char> &vchRand = vvchArgs[1];
				vector<unsigned char> vchToHash(vchRand);
				vchToHash.insert(vchToHash.end(), vchName.begin(),
						vchName.end());
				uint160 hash = Hash160(vchToHash);
				if (uint160(vchHash) != hash)
					return error(
							"CheckAliasInputs() : aliasactivate hash mismatch");

				nDepth = CheckTransactionAtRelativeDepth(pindexBlock, prevCoins,
						GetMinActivateDepth());
				if ((fBlock || fMiner) && nDepth >= 0
						&& nDepth < GetMinActivateDepth())
					return false;
				nDepth = CheckTransactionAtRelativeDepth(pindexBlock, prevCoins,
						GetAliasExpirationDepth(pindexBlock->nHeight));
				if (nDepth == -1)
					return error(
							"CheckAliasInputs() : aliasactivate cannot be mined if aliasnew is not already in chain and unexpired");

				nPrevHeight = GetAliasHeight(vvchArgs[0]);
				if (!fBlock && nPrevHeight >= 0
						&& pindexBlock->nHeight - nPrevHeight
								< GetAliasExpirationDepth(pindexBlock->nHeight))
					return error(
							"CheckAliasInputs() : aliasactivate on an unexpired alias");

				// BOOST_FOREACH(const MAPTESTPOOLTYPE &s, mapTestPool) {
				//     if (s.first == vvchArgs[0]) {
				//         return error("CheckAliasInputs() : will not mine %s because it clashes with %s",
				//                tx.GetHash().GetHex().c_str(),
				//                s.second.GetHex().c_str());
				//     }
				// }
			}

			break;

		case OP_ALIAS_UPDATE:

			if (fBlock && fJustCheck && !found)
				return true;

			if (!found
					|| (prevOp != OP_ALIAS_ACTIVATE && prevOp != OP_ALIAS_UPDATE))
				return error("aliasupdate tx without previous update tx");

			if (vvchArgs[1].size() > MAX_VALUE_LENGTH)
				return error("aliasupdate tx with value too long");

			// Check name
			if (vvchPrevArgs[0] != vvchArgs[0])
				return error("CheckAliasInputs() : aliasupdate alias mismatch");

			// TODO CPU intensive
			nDepth = CheckTransactionAtRelativeDepth(pindexBlock, prevCoins,
					GetAliasExpirationDepth(pindexBlock->nHeight));
			if ((fBlock || fMiner) && nDepth < 0)
				return error(
						"CheckAliasInputs() : aliasupdate on an expired alias, or there is a pending transaction on the alias");

			// BOOST_FOREACH(const MAPTESTPOOLTYPE &s, mapTestPool) {
			//     if (s.first == vvchArgs[0]) {
			//         return error("CheckAliasInputs() : will not mine %s because it clashes with %s",
			//                tx.GetHash().GetHex().c_str(),
			//                s.second.GetHex().c_str());
			//     }
			// }

			break;

		default:
			return error(
					"CheckAliasInputs() : alias transaction has unknown op");
		}

		if (fBlock || (!fBlock && !fMiner && !fJustCheck)) {

			if (op != OP_ALIAS_NEW) {

				// get the alias from the DB
				vector<CAliasIndex> vtxPos;
				if (paliasdb->ExistsAlias(vvchArgs[0])) {
					if (!paliasdb->ReadAlias(vvchArgs[0], vtxPos)
							&& op == OP_ALIAS_UPDATE && !fJustCheck)
						return error(
								"CheckAliasInputs() : failed to read from alias DB");
				}

				//// if an update then check for a prevtx and error out if not found
				// if (fJustCheck && op == OP_ALIAS_UPDATE && !CheckAliasTxPos(vtxPos, prevCoins->nHeight)) {
				// 	printf("CheckAliasInputs() : tx %s rejected, since previous tx (%s) is not in the alias DB\n",
				// 		tx.GetHash().ToString().c_str(), prevOutput->hash.ToString().c_str());
				// 	return false;
				// }

				if (!fMiner && !fJustCheck
						&& pindexBlock->nHeight != pindexBest->nHeight) {
					
					int nHeight = pindexBlock->nHeight;

					CAliasIndex txPos2;		
					const vector<unsigned char> &vchVal = vvchArgs[
						op == OP_ALIAS_ACTIVATE ? 2 : 1];
					txPos2.nHeight = nHeight;
					txPos2.vValue = vchVal;
					txPos2.txHash = tx.GetHash();
					txPos2.txPrevOut = *prevOutput;

					PutToAliasList(vtxPos, txPos2);

					{
					TRY_LOCK(cs_main, cs_trymain);

					if (!paliasdb->WriteName(vvchArgs[0], vtxPos))
						return error( "CheckAliasInputs() :  failed to write to alias DB");
					mapTestPool[vvchArgs[0]] = tx.GetHash();

					// write alias fees to db
					int64 nTheFee = GetAliasReturnFee(tx);
					InsertAliasFee(pindexBlock, tx.GetHash(), nTheFee);
					if (nTheFee != 0)
						printf( "ALIAS FEES: Added %lf in fees to track for regeneration.\n",
								(double) nTheFee / COIN);

					vector<CAliasFee> vAliasFees(lstAliasFees.begin(),
							lstAliasFees.end());
					if (!paliasdb->WriteAliasTxFees(vAliasFees))
						return error( "CheckOfferInputs() : failed to write fees to alias DB");
					
						std::map<std::vector<unsigned char>, std::set<uint256> >::iterator mi =
								mapAliasesPending.find(vvchArgs[0]);
						if (mi != mapAliasesPending.end())
							mi->second.erase(tx.GetHash());
					}

					printf(
							"CONNECTED ALIAS: name=%s  op=%s  hash=%s  height=%d\n",
							stringFromVch(vvchArgs[0]).c_str(),
							aliasFromOp(op).c_str(),
							tx.GetHash().ToString().c_str(), nHeight);
				}
			}
		}
	}
	return true;
}

bool ExtractAliasAddress(const CScript& script, string& address) {
	if (script.size() == 1 && script[0] == OP_RETURN) {
		address = string("network fee");
		return true;
	}
	vector<vector<unsigned char> > vvch;
	int op;
	if (!DecodeAliasScript(script, op, vvch))
		return false;

	string strOp = aliasFromOp(op);
	string strName;
	if (op == OP_ALIAS_NEW) {
#ifdef GUI

		std::map<uint160, std::vector<unsigned char> >::const_iterator mi = mapMyNameHashes.find(uint160(vvch[0]));
		if (mi != mapMyNameHashes.end())
		strName = stringFromVch(mi->second);
		else
#endif
		strName = HexStr(vvch[0]);
	} else
		strName = stringFromVch(vvch[0]);

	address = strOp + ": " + strName;
	return true;
}

int64 getAmount(Value value) {
	ConvertTo<double>(value);
	double dAmount = value.get_real();
	int64 nAmount = roundint64(dAmount * COIN);
	if (!MoneyRange(nAmount))
		throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
	return nAmount;
}

string stringFromValue(const Value& value) {
	string strName = value.get_str();
	return strName;
}

vector<unsigned char> vchFromValue(const Value& value) {
	string strName = value.get_str();
	unsigned char *strbeg = (unsigned char*) strName.c_str();
	return vector<unsigned char>(strbeg, strbeg + strName.size());
}

std::vector<unsigned char> vchFromString(const std::string &str) {
	unsigned char *strbeg = (unsigned char*) str.c_str();
	return vector<unsigned char>(strbeg, strbeg + str.size());
}

string stringFromVch(const vector<unsigned char> &vch) {
	string res;
	vector<unsigned char>::const_iterator vi = vch.begin();
	while (vi != vch.end()) {
		res += (char) (*vi);
		vi++;
	}
	return res;
}

bool CAliasDB::ScanNames(const std::vector<unsigned char>& vchName,
		unsigned int nMax,
		std::vector<std::pair<std::vector<unsigned char>, CAliasIndex> >& nameScan) {

	leveldb::Iterator *pcursor = paliasdb->NewIterator();

	CDataStream ssKeySet(SER_DISK, CLIENT_VERSION);
	ssKeySet << make_pair(string("namei"), vchName);
	string sType;
	pcursor->Seek(ssKeySet.str());

	while (pcursor->Valid()) {
		boost::this_thread::interruption_point();
		try {
			leveldb::Slice slKey = pcursor->key();
			CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(),
					SER_DISK, CLIENT_VERSION);

			ssKey >> sType;
			if (sType == "namei") {
				vector<unsigned char> vchName;
				ssKey >> vchName;
				leveldb::Slice slValue = pcursor->value();
				CDataStream ssValue(slValue.data(),
						slValue.data() + slValue.size(), SER_DISK,
						CLIENT_VERSION);
				vector<CAliasIndex> vtxPos;
				ssValue >> vtxPos;
				CAliasIndex txPos;
				if (!vtxPos.empty())
					txPos = vtxPos.back();
				nameScan.push_back(make_pair(vchName, txPos));
			}
			if (nameScan.size() >= nMax)
				break;

			pcursor->Next();
		} catch (std::exception &e) {
			return error("%s() : deserialize error", __PRETTY_FUNCTION__);
		}
	}
	delete pcursor;
	return true;
}

void rescanforaliases(CBlockIndex *pindexRescan) {
	printf("Scanning blockchain for names to create fast index...\n");
	paliasdb->ReconstructNameIndex(pindexRescan);
}

bool CAliasDB::ReconstructNameIndex(CBlockIndex *pindexRescan) {
	CDiskTxPos txindex;
	CBlockIndex* pindex = pindexRescan;

	{
		TRY_LOCK(pwalletMain->cs_wallet, cs_trylock);
		while (pindex) {
			CBlock block;
			block.ReadFromDisk(pindex);
			int nHeight = pindex->nHeight;
			uint256 txblkhash;

			BOOST_FOREACH(CTransaction& tx, block.vtx) {

				if (tx.nVersion != SYSCOIN_TX_VERSION)
					continue;

				vector<vector<unsigned char> > vvchArgs;
				int op, nOut;

				// decode the alias op
				bool o = DecodeAliasTx(tx, op, nOut, vvchArgs, -1);
				if (!o || !IsAliasOp(op))
					continue;
				if (op == OP_ALIAS_NEW)
					continue;

				const vector<unsigned char> &vchName = vvchArgs[0];
				const vector<unsigned char> &vchValue = vvchArgs[
						op == OP_ALIAS_ACTIVATE ? 2 : 1];

				if (!GetTransaction(tx.GetHash(), tx, txblkhash, true))
					continue;

				// if name exists in DB, read it to verify
				vector<CAliasIndex> vtxPos;
				if (ExistsAlias(vchName)) {
					if (!ReadAlias(vchName, vtxPos))
						return error(
								"ReconstructNameIndex() : failed to read from alias DB");
				}

				// rebuild the alias object, store to DB
				CAliasIndex txName;
				txName.nHeight = nHeight;
				txName.vValue = vchValue;
				txName.txHash = tx.GetHash();

				PutToAliasList(vtxPos, txName);

				if (!WriteName(vchName, vtxPos))
					return error(
							"ReconstructNameIndex() : failed to write to alias DB");

				// get fees for txn and add them to regenerate list
				int64 nTheFee = GetAliasReturnFee(tx);
				InsertAliasFee(pindex, tx.GetHash(), nTheFee);
				vector<CAliasFee> vAliasFees(lstAliasFees.begin(),
					lstAliasFees.end());
				if (!paliasdb->WriteAliasTxFees(vAliasFees))
					return error(
							"CheckOfferInputs() : failed to write fees to alias DB");


				printf(
						"RECONSTRUCT ALIAS: op=%s alias=%s value=%s hash=%s height=%d fees=%llu\n",
						aliasFromOp(op).c_str(), stringFromVch(vchName).c_str(),
						stringFromVch(vchValue).c_str(),
						tx.GetHash().ToString().c_str(), nHeight,
						nTheFee / COIN);

			} /* TX */
			pindex = pindex->pnext;
		} /* BLOCK */
		Flush();
	} /* LOCK */
	return true;
}


// 10080 blocks = 1 week
// alias expiration time is ~ 6 months or 26 weeks
// expiration blocks is 262080 (final)
// expiration starts at 87360, increases by 1 per block starting at
// block 174721 until block 349440

//
// Increase expiration to 262080 gradually starting at block 174720.
// Use for validation purposes and pass the chain height.
int GetAliasExpirationDepth(int nHeight) {
	if (nHeight < 174720)
		return 87360;
	if (nHeight < 349440)
		return nHeight - 87360;
	return 262080;
}

// For display purposes, pass the name height.
int GetAliasDisplayExpirationDepth(int nHeight) {
	return GetAliasExpirationDepth(nHeight);
}

int GetNameTxPosHeight(const CDiskTxPos& txPos) {
	// Read block header
	CBlock block;
	if (!block.ReadFromDisk(txPos))
		return 0;
	// Find the block in the index
	map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(
			block.GetHash());
	if (mi == mapBlockIndex.end())
		return 0;
	CBlockIndex* pindex = (*mi).second;
	if (!pindex || !pindex->IsInMainChain())
		return 0;
	return pindex->nHeight;
}

int GetNameTxPosHeight2(const CDiskTxPos& txPos, int nHeight) {
	nHeight = GetNameTxPosHeight(txPos);
	return nHeight;
}




int64 GetAliasTxHashHeight(const uint256 txHash) {
	CDiskTxPos postx;
	pblocktree->ReadTxIndex(txHash, postx);
	return GetNameTxPosHeight(postx);
}

bool GetValueOfAliasTxHash(const uint256 &txHash, vector<unsigned char>& vchValue, uint256& hash, int& nHeight) {
	nHeight = GetAliasTxHashHeight(txHash);
	CTransaction tx;
	uint256 blockHash;

	if (!GetTransaction(txHash, tx, blockHash, true))
		return error("GetValueOfAliasTxHash() : could not read tx from disk");

	if (!GetValueOfAliasTx(tx, vchValue))
		return error("GetValueOfAliasTxHash() : could not decode value from tx");

	hash = tx.GetHash();
	return true;
}

bool GetValueOfName(CAliasDB& dbName, const vector<unsigned char> &vchName,
		vector<unsigned char>& vchValue, int& nHeight) {
	vector<CAliasIndex> vtxPos;
	if (!paliasdb->ReadAlias(vchName, vtxPos) || vtxPos.empty())
		return false;

	CAliasIndex& txPos = vtxPos.back();
	nHeight = txPos.nHeight;
	vchValue = txPos.vValue;
	return true;
}


bool GetAliasAddress(const CTransaction& tx, std::string& strAddress) {
	int op, nOut = 0;
	vector<vector<unsigned char> > vvch;

	if (!DecodeAliasTx(tx, op, nOut, vvch, -1))
		return error("GetAliasAddress() : could not decode name tx.");

	const CTxOut& txout = tx.vout[nOut];

	const CScript& scriptPubKey = RemoveAliasScriptPrefix(txout.scriptPubKey);

	CTxDestination dest;
	ExtractDestination(scriptPubKey, dest);
	strAddress = CBitcoinAddress(dest).ToString();
	return true;
}

bool GetAliasAddress(const CDiskTxPos& txPos, std::string& strAddress) {
	CTransaction tx;
	if (!tx.ReadFromDisk(txPos))
		return error("GetAliasAddress() : could not read tx from disk");
	return GetAliasAddress(tx, strAddress);
}
void GetAliasValue(const std::string& strName, std::string& strAddress) {

	{
		TRY_LOCK(pwalletMain->cs_wallet, cs_trywallet);
		TRY_LOCK(cs_main, cs_trymain);
		vector<unsigned char> vchName = vchFromValue(strName);
		if (!paliasdb->ExistsAlias(vchName))
			throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Alias not found");

		// check for alias existence in DB
		vector<CAliasIndex> vtxPos;
		if (!paliasdb->ReadAlias(vchName, vtxPos))
			throw JSONRPCError(RPC_WALLET_ERROR,
					"failed to read from alias DB");
		if (vtxPos.size() < 1)
			throw JSONRPCError(RPC_WALLET_ERROR, "no alias result returned");

		// get transaction pointed to by alias
		uint256 blockHash;
		CTransaction tx;
		uint256 txHash = vtxPos.back().txHash;
		if (!GetTransaction(txHash, tx, blockHash, true))
			throw JSONRPCError(RPC_WALLET_ERROR,
					"failed to read transaction from disk");

		GetAliasAddress(tx, strAddress);
	}
}

int IndexOfNameOutput(const CTransaction& tx) {
	vector<vector<unsigned char> > vvch;

	int op;
	int nOut;
	bool good = DecodeAliasTx(tx, op, nOut, vvch, -1);

	if (!good)
		throw runtime_error("IndexOfNameOutput() : name output not found");
	return nOut;
}

bool GetAliasOfTx(const CTransaction& tx, vector<unsigned char>& name) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return false;
	vector<vector<unsigned char> > vvchArgs;
	int op;
	int nOut;

	bool good = DecodeAliasTx(tx, op, nOut, vvchArgs, -1);
	if (!good)
		return error("GetAliasOfTx() : could not decode a syscoin tx");

	switch (op) {
	case OP_ALIAS_ACTIVATE:
	case OP_ALIAS_UPDATE:
		name = vvchArgs[0];
		return true;
	}
	return false;
}

bool IsConflictedAliasTx(CBlockTreeDB& txdb, const CTransaction& tx,
		vector<unsigned char>& name) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return false;
	vector<vector<unsigned char> > vvchArgs;
	int op;
	int nOut;

	bool good = DecodeAliasTx(tx, op, nOut, vvchArgs, -1);
	if (!good)
		return error("IsConflictedAliasTx() : could not decode a syscoin tx");
	int nPrevHeight;

	switch (op) {
	case OP_ALIAS_ACTIVATE:
		nPrevHeight = GetAliasHeight(vvchArgs[0]);
		name = vvchArgs[0];
		if (nPrevHeight >= 0
				&& pindexBest->nHeight - nPrevHeight
						< GetAliasExpirationDepth(pindexBest->nHeight))
			return true;
	}
	return false;
}

bool GetValueOfAliasTx(const CTransaction& tx, vector<unsigned char>& value) {
	vector<vector<unsigned char> > vvch;

	int op;
	int nOut;

	if (!DecodeAliasTx(tx, op, nOut, vvch, -1))
		return false;

	switch (op) {
	case OP_ALIAS_NEW:
		return false;
	case OP_ALIAS_ACTIVATE:
		value = vvch[2];
		return true;
	case OP_ALIAS_UPDATE:
		value = vvch[1];
		return true;
	default:
		return false;
	}
}

bool DecodeAliasTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch, int nHeight) 
{
  bool found = false;


  // Strict check - bug disallowed
  for (unsigned int i = 0; i < tx.vout.size(); i++) {
    const CTxOut& out = tx.vout[i];
    vector<vector<unsigned char> > vvchRead;
    if (DecodeAliasScript(out.scriptPubKey, op, vvchRead)) {
      nOut = i;
      found = true;
      vvch = vvchRead;
      break;
    }
  }
  if (!found)
    vvch.clear();

  return found;
}

bool GetValueOfAliasTx(const CCoins& tx, vector<unsigned char>& value) {
	vector<vector<unsigned char> > vvch;

	int op;
	int nOut;

	if (!DecodeAliasTx(tx, op, nOut, vvch, -1))
		return false;

	switch (op) {
	case OP_ALIAS_NEW:
		return false;
	case OP_ALIAS_ACTIVATE:
		value = vvch[2];
		return true;
	case OP_ALIAS_UPDATE:
		value = vvch[1];
		return true;
	default:
		return false;
	}
}

bool DecodeAliasTx(const CCoins& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch, int nHeight) {
	bool found = false;

	// Strict check - bug disallowed
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		vector<vector<unsigned char> > vvchRead;
		if (DecodeAliasScript(out.scriptPubKey, op, vvchRead)) {
			nOut = i;
			found = true;
			vvch = vvchRead;
			break;
		}
	}
	if (!found)
		vvch.clear();
	return found;
}

Value aliasnew(const Array& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("aliasnew <aliasname>\n"
				"<aliasname> name, 255 chars max." + HelpRequiringPassphrase());

	vector<unsigned char> vchName = vchFromValue(params[0]);
	if (vchName.size() > 255)
		throw runtime_error("alias name > 255 bytes!\n");

	CWalletTx wtx;
	wtx.nVersion = SYSCOIN_TX_VERSION;

	uint64 rand = GetRand((uint64) -1);
	vector<unsigned char> vchRand = CBigNum(rand).getvch();
	vector<unsigned char> vchToHash(vchRand);
	vchToHash.insert(vchToHash.end(), vchName.begin(), vchName.end());
	uint160 hash = Hash160(vchToHash);

	CPubKey newDefaultKey;
	pwalletMain->GetKeyFromPool(newDefaultKey, false);
	CScript scriptPubKeyOrig;
	scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_ALIAS_NEW) << hash << OP_2DROP;
	scriptPubKey += scriptPubKeyOrig;
	{
		EnsureWalletIsUnlocked();
		string strError = pwalletMain->SendMoney(scriptPubKey, MIN_AMOUNT, wtx,
				false);
		if (strError != "")
			throw JSONRPCError(RPC_WALLET_ERROR, strError);
		mapMyAliases[vchName] = wtx.GetHash();
	}
	printf("aliasnew : name=%s, guid=%s, tx=%s\n",
			stringFromVch(vchName).c_str(), HexStr(vchRand).c_str(),
			wtx.GetHash().GetHex().c_str());

	vector<Value> res;
	res.push_back(wtx.GetHash().GetHex());
	res.push_back(HexStr(vchRand));

	return res;
}

Value aliasactivate(const Array& params, bool fHelp) {
	if (fHelp || params.size() < 3 || params.size() > 4)
		throw runtime_error(
				"aliasactivate <aliasname> <guid> [<tx>] <value>\n"
						"<aliasname> alias name.\n"
						"<guid> alias guid key.\n"
						"<tx> txid of aliasnew for this alias, required if daemon restarted.\n"
						"<value> alias value, 1023 chars max.\n"
						"Perform a first update after an aliasnew reservation.\n"
						"Note that the first update will go into a block 12 blocks after the aliasnew, at the soonest."
						+ HelpRequiringPassphrase());

	vector<unsigned char> vchName = vchFromValue(params[0]);
	vector<unsigned char> vchRand = ParseHex(params[1].get_str());
	vector<unsigned char> vchValue;

	if (params.size() == 3)
		vchValue = vchFromValue(params[2]);
	else
		vchValue = vchFromValue(params[3]);
	if (vchValue.size() > 1023)
		throw runtime_error("alias value > 1023 bytes!\n");

	CWalletTx wtx;
	wtx.nVersion = SYSCOIN_TX_VERSION;

	{

		if (mapAliasesPending.count(vchName)
				&& mapAliasesPending[vchName].size()) {
			error(
					"aliasactivate() : there are %d pending operations on that alias, including %s",
					(int) mapAliasesPending[vchName].size(),
					mapAliasesPending[vchName].begin()->GetHex().c_str());
			throw runtime_error("there are pending operations on that alias");
		}

		CTransaction tx;
		if (GetTxOfAlias(*paliasdb, vchName, tx)) {
			error("aliasactivate() : this alias is already active with tx %s",
					tx.GetHash().GetHex().c_str());
			throw runtime_error("this alias is already active");
		}

		EnsureWalletIsUnlocked();

		// Make sure there is a previous aliasnew tx on this name and that the random value matches
		uint256 wtxInHash;
		if (params.size() == 3) {
			if (!mapMyAliases.count(vchName))
				throw runtime_error(
						"could not find a coin with this alias, try specifying the aliasnew transaction id");
			wtxInHash = mapMyAliases[vchName];
		} else
			wtxInHash.SetHex(params[2].get_str());

		if (!pwalletMain->mapWallet.count(wtxInHash))
			throw runtime_error("previous transaction is not in the wallet");

		CPubKey newDefaultKey;
		pwalletMain->GetKeyFromPool(newDefaultKey, false);
		CScript scriptPubKeyOrig;
		scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
		CScript scriptPubKey;
		scriptPubKey << CScript::EncodeOP_N(OP_ALIAS_ACTIVATE) << vchName
				<< vchRand << vchValue << OP_2DROP << OP_2DROP;
		scriptPubKey += scriptPubKeyOrig;

		CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];
		vector<unsigned char> vchHash;
		bool found = false;
		BOOST_FOREACH(CTxOut& out, wtxIn.vout) {
			vector<vector<unsigned char> > vvch;
			int op;
			if (DecodeAliasScript(out.scriptPubKey, op, vvch)) {
				if (op != OP_ALIAS_NEW)
					throw runtime_error(
							"previous transaction wasn't a aliasnew");
				vchHash = vvch[0];
				found = true;
				break;
			}
		}

		if (!found)
			throw runtime_error("previous tx on alias name is not an alias tx");

		vector<unsigned char> vchToHash(vchRand);
		vchToHash.insert(vchToHash.end(), vchName.begin(), vchName.end());
		uint160 hash = Hash160(vchToHash);
		if (uint160(vchHash) != hash) {
			throw runtime_error("previous tx used a different random value");
		}

		int64 nNetFee = GetAliasNetworkFee(1, pindexBest->nHeight);
		// Round up to CENT
		nNetFee += CENT - 1;
		nNetFee = (nNetFee / CENT) * CENT;

		string strError = SendMoneyWithInputTx(iface,
        scriptPubKey, MIN_AMOUNT,
        nNetFee, wtxIn, wtx, false);
		if (strError != "")
			throw JSONRPCError(RPC_WALLET_ERROR, strError);
	}
	return wtx.GetHash().GetHex();
}

Value aliasupdate(const Array& params, bool fHelp) {
	if (fHelp || 2 > params.size() || 3 < params.size())
		throw runtime_error(
				"aliasupdate <aliasname> <value> [<toaddress>]\n"
						"Update and possibly transfer an alias.\n"
						"<aliasname> alias name.\n"
						"<value> alias value, 1023 chars max.\n"
                        "<toaddress> receiver syscoin address, if transferring alias.\n"
						+ HelpRequiringPassphrase());

	vector<unsigned char> vchName = vchFromValue(params[0]);
	vector<unsigned char> vchValue = vchFromValue(params[1]);
	if (vchValue.size() > 519)
		throw runtime_error("alias value > 1023 bytes!\n");
	CWalletTx wtx;
	wtx.nVersion = SYSCOIN_TX_VERSION;
	CScript scriptPubKeyOrig;

    if (params.size() == 3) {
		string strAddress = params[2].get_str();
		CBitcoinAddress myAddress = CBitcoinAddress(strAddress);
		if (!myAddress.IsValid())
			throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
					"Invalid syscoin address");
		scriptPubKeyOrig.SetDestination(myAddress.Get());
	} else {
		CPubKey newDefaultKey;
		pwalletMain->GetKeyFromPool(newDefaultKey, false);
		scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
	}

	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << vchName << vchValue
			<< OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;

	{

		if (mapAliasesPending.count(vchName)
				&& mapAliasesPending[vchName].size()) {
			error(
					"aliasupdate() : there are %d pending operations on that alias, including %s",
					(int) mapAliasesPending[vchName].size(),
					mapAliasesPending[vchName].begin()->GetHex().c_str());
			throw runtime_error("there are pending operations on that alias");
		}

		EnsureWalletIsUnlocked();

		CTransaction tx;
		if (!GetTxOfAlias(*paliasdb, vchName, tx))
			throw runtime_error("could not find an alias with this name");
		if (tx.GetData().size())
			throw runtime_error("cannot modify this data alias."
					" use dataupdate");
        if(!IsAliasMine(tx)) {
			throw runtime_error("Cannot modify a transferred alias");
        }
		uint256 wtxInHash = tx.GetHash();

		if (!pwalletMain->mapWallet.count(wtxInHash)) {
			error("aliasupdate() : this alias is not in your wallet %s",
					wtxInHash.GetHex().c_str());
			throw runtime_error("this alias is not in your wallet");
		}
		int64 nNetFee = GetAliasNetworkFee(2, pindexBest->nHeight);
		// Round up to CENT
		nNetFee += CENT - 1;
		nNetFee = (nNetFee / CENT) * CENT;

		CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];
		string strError = SendMoneyWithInputTx(scriptPubKey, MIN_AMOUNT,
				nNetFee, wtxIn, wtx, false);
		if (strError != "")
			throw JSONRPCError(RPC_WALLET_ERROR, strError);
	}

	return wtx.GetHash().GetHex();
}

Value aliaslist(const Array& params, bool fHelp) {
	if (fHelp || 1 < params.size())
		throw runtime_error("aliaslist [<aliasname>]\n"
				"list my own aliases.\n"
				"<aliasname> alias name to use as filter.\n");
	
	vector<unsigned char> vchName;

	if (params.size() == 1)
		vchName = vchFromValue(params[0]);

	vector<unsigned char> vchNameUniq;
	if (params.size() == 1)
		vchNameUniq = vchFromValue(params[0]);
	Array oRes;
	map<vector<unsigned char>, int> vNamesI;
	map<vector<unsigned char>, Object> vNamesO;

	{
		uint256 blockHash;
		uint256 hash;
		CTransaction tx, dbtx;
	
		vector<unsigned char> vchValue;
		int nHeight;
		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
			// get txn hash, read txn index
			hash = item.second.GetHash();
			if (!GetTransaction(hash, tx, blockHash, true))
				continue;

			// skip non-syscoin txns
			if (tx.nVersion != SYSCOIN_TX_VERSION)
				continue;

			// don't show aliases that are transferred. Sanity check, wallet tx's are always "yours" by definition anyways.
//			if(!IsAliasMine(tx)) {
//				continue;
//			}

			// decode txn, skip non-alias txns
			vector<vector<unsigned char> > vvch;
			int op, nOut;
			if (!DecodeAliasTx(tx, op, nOut, vvch, -1))
				continue;
			if(!IsAliasOp(op))
				continue;
			// get the txn height
			nHeight = GetAliasTxHashHeight(hash);

			// get the txn alias name
			if (op==OP_ALIAS_NEW || !GetAliasOfTx(tx, vchName))
				continue;

			// skip this alias if it doesn't match the given filter value
			if (vchNameUniq.size() > 0 && vchNameUniq != vchName)
				continue;
			// get last active name only
			if (vNamesI.find(vchName) != vNamesI.end() && (nHeight < vNamesI[vchName] || vNamesI[vchName] < 0))
				continue;

			// Read the database for the latest alias (vtxPos.back()) and ensure it is not transferred (isaliasmine).. 
			// if it IS transferred then skip over this alias whenever it is found(above vNamesI check) in your mapwallet
			// check for alias existence in DB
			// will only read the alias from the db once per name to ensure that it is not mine.
			vector<CAliasIndex> vtxPos;
			if (vNamesI.find(vchName) == vNamesI.end() && paliasdb->ReadAlias(vchName, vtxPos))
			{
				if (vtxPos.size() > 0)
				{
					// get transaction pointed to by alias
					uint256 txHash = vtxPos.back().txHash;
					if(GetTransaction(txHash, dbtx, blockHash, true))
					{
					
						nHeight = GetAliasTxHashHeight(txHash);
						// Is the latest alais in the db transferred?
						if(!IsAliasMine(dbtx))
						{	
							// by setting this to -1, subsequent aliases with the same name won't be read from disk (optimization) 
							// because the latest alias tx doesn't belong to us anymore
							vNamesI[vchName] = -1;
							continue;
						}
						else
						{
							// get the value of the alias txn of the latest alias (from db)
							GetValueOfAliasTx(dbtx, vchValue);
						}
					}
					
				}
			}
			else
			{
				GetValueOfAliasTx(tx, vchValue);
			}
			// build the output object
			Object oName;
			oName.push_back(Pair("name", stringFromVch(vchName)));
			oName.push_back(Pair("value", stringFromVch(vchValue)));
			oName.push_back(Pair("lastupdate_height", nHeight));
			oName.push_back(Pair("expires_on", nHeight + GetAliasDisplayExpirationDepth(nHeight)));
			oName.push_back(Pair("expires_in", nHeight + GetAliasDisplayExpirationDepth(nHeight)- pindexBest->nHeight ));

			if (nHeight + GetAliasDisplayExpirationDepth(nHeight)
					- pindexBest->nHeight <= 0)
				oName.push_back(Pair("expired", 1));
			vNamesI[vchName] = nHeight;
			vNamesO[vchName] = oName;					

		}
	}

	BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, Object)& item, vNamesO)
		oRes.push_back(item.second);

	return oRes;
}

/**
 * [aliasinfo description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
Value aliasinfo(const Array& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("aliasinfo <aliasname>\n"
				"Show values of an alias.\n");
	vector<unsigned char> vchName = vchFromValue(params[0]);
	CTransaction tx;
	Object oShowResult;

	{

		// check for alias existence in DB
		vector<CAliasIndex> vtxPos;
		if (!paliasdb->ReadAlias(vchName, vtxPos))
			throw JSONRPCError(RPC_WALLET_ERROR,
					"failed to read from alias DB");
		if (vtxPos.size() < 1)
			throw JSONRPCError(RPC_WALLET_ERROR, "no result returned");

		// get transaction pointed to by alias
		uint256 blockHash;
		uint256 txHash = vtxPos.back().txHash;
		if (!GetTransaction(txHash, tx, blockHash, true))
			throw JSONRPCError(RPC_WALLET_ERROR,
					"failed to read transaction from disk");

		Object oName;
		vector<unsigned char> vchValue;
		int nHeight;

		uint256 hash;
		if (GetValueOfAliasTxHash(txHash, vchValue, hash, nHeight)) {
			oName.push_back(Pair("name", stringFromVch(vchName)));
			string value = stringFromVch(vchValue);
			oName.push_back(Pair(tx.data.size() ? "filename" : "value", value));
			oName.push_back(Pair("txid", tx.GetHash().GetHex()));
			string strAddress = "";
			GetAliasAddress(tx, strAddress);
			oName.push_back(Pair("address", strAddress));
			bool fAliasMine = IsAliasMine(tx)? true:  false;
			oName.push_back(Pair("isaliasmine", fAliasMine));
			bool fMine = pwalletMain->IsMine(tx)? true:  false;
			oName.push_back(Pair("ismine", fMine));
            oName.push_back(Pair("lastupdate_height", nHeight));
            oName.push_back(Pair("expires_on", nHeight + GetAliasDisplayExpirationDepth(nHeight)));
            oName.push_back(Pair("expires_in", nHeight + GetAliasDisplayExpirationDepth(nHeight)- pindexBest->nHeight ));
			if (nHeight + GetAliasDisplayExpirationDepth(nHeight)
					- pindexBest->nHeight <= 0) {
				oName.push_back(Pair("expired", 1));
			}
			if (tx.data.size())
				oName.push_back(Pair("data", tx.GetBase64Data()));

			oShowResult = oName;
		}
	}
	return oShowResult;
}

/**
 * [aliashistory description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
Value aliashistory(const Array& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("aliashistory <aliasname>\n"
				"List all stored values of an alias.\n");
	Array oRes;
	vector<unsigned char> vchName = vchFromValue(params[0]);
	string name = stringFromVch(vchName);

	{
		vector<CAliasIndex> vtxPos;
		if (!paliasdb->ReadAlias(vchName, vtxPos))
			throw JSONRPCError(RPC_WALLET_ERROR,
					"failed to read from alias DB");

		CAliasIndex txPos2;
		uint256 txHash;
		uint256 blockHash;
		BOOST_FOREACH(txPos2, vtxPos) {
			txHash = txPos2.txHash;
			CTransaction tx;
			if (!GetTransaction(txHash, tx, blockHash, true)) {
				error("could not read txpos");
				continue;
			}

			Object oName;
			vector<unsigned char> vchValue;
			int nHeight;
			uint256 hash;
			if (GetValueOfAliasTxHash(txHash, vchValue, hash, nHeight)) {
				oName.push_back(Pair("name", name));
				string value = stringFromVch(vchValue);
				oName.push_back(Pair("value", value));
				oName.push_back(Pair("txid", tx.GetHash().GetHex()));
				string strAddress = "";
				GetAliasAddress(tx, strAddress);
				oName.push_back(Pair("address", strAddress));
	            oName.push_back(Pair("lastupdate_height", nHeight));
	            oName.push_back(Pair("expires_on", nHeight + GetAliasDisplayExpirationDepth(nHeight)));
	            oName.push_back(Pair("expires_in", nHeight + GetAliasDisplayExpirationDepth(nHeight)- pindexBest->nHeight ));
				if (nHeight + GetAliasDisplayExpirationDepth(nHeight)
						- pindexBest->nHeight <= 0) {
					oName.push_back(Pair("expired", 1));
				}
				oRes.push_back(oName);
			}
		}
	}
	return oRes;
}

/**
 * [aliasfilter description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
Value aliasfilter(const Array& params, bool fHelp) {
	if (fHelp || params.size() > 5)
		throw runtime_error(
				"aliasfilter [[[[[regexp] maxage=36000] from=0] nb=0] stat]\n"
						"scan and filter aliases\n"
						"[regexp] : apply [regexp] on aliases, empty means all aliases\n"
						"[maxage] : look in last [maxage] blocks\n"
						"[from] : show results from number [from]\n"
						"[nb] : show [nb] results, 0 means all\n"
						"[stat] : show some stats instead of results\n"
						"aliasfilter \"\" 5 # list aliases updated in last 5 blocks\n"
						"aliasfilter \"^name\" # list all aliases starting with \"name\"\n"
						"aliasfilter 36000 0 0 stat # display stats (number of names) on active aliases\n");

	string strRegexp;
	int nFrom = 0;
	int nNb = 0;
	int nMaxAge = 36000;
	bool fStat = false;
	int nCountFrom = 0;
	int nCountNb = 0;
	/* when changing this to match help, review bitcoinrpc.cpp RPCConvertValues() */
	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
		nMaxAge = params[1].get_int();

	if (params.size() > 2)
		nFrom = params[2].get_int();

	if (params.size() > 3)
		nNb = params[3].get_int();

	if (params.size() > 4)
		fStat = (params[4].get_str() == "stat" ? true : false);

	Array oRes;

	vector<unsigned char> vchName;
	vector<pair<vector<unsigned char>, CAliasIndex> > nameScan;
	if (!paliasdb->ScanNames(vchName, 100000000, nameScan))
		throw JSONRPCError(RPC_WALLET_ERROR, "scan failed");

	pair<vector<unsigned char>, CAliasIndex> pairScan;
	BOOST_FOREACH(pairScan, nameScan) {
		string name = stringFromVch(pairScan.first);

		// regexp
		using namespace boost::xpressive;
		smatch nameparts;
		sregex cregex = sregex::compile(strRegexp);
		if (strRegexp != "" && !regex_search(name, nameparts, cregex))
			continue;

		CAliasIndex txName = pairScan.second;
		int nHeight = txName.nHeight;

		// max age
		if (nMaxAge != 0 && pindexBest->nHeight - nHeight >= nMaxAge)
			continue;

		// from limits
		nCountFrom++;
		if (nCountFrom < nFrom + 1)
			continue;



		Object oName;
		oName.push_back(Pair("name", name));
		CTransaction tx;
		uint256 blockHash;
		uint256 txHash = txName.txHash;
		if ((nHeight + GetAliasDisplayExpirationDepth(nHeight)
				- pindexBest->nHeight <= 0)
				|| !GetTransaction(txHash, tx, blockHash, true)) {
			oName.push_back(Pair("expired", 1));
		} else {
			vector<unsigned char> vchValue;
			GetValueOfAliasTx(tx, vchValue);
			string value = stringFromVch(vchValue);
			oName.push_back(Pair("value", value));
			oName.push_back(Pair("txid", txHash.GetHex()));
            oName.push_back(Pair("lastupdate_height", nHeight));
            oName.push_back(Pair("expires_on", nHeight + GetAliasDisplayExpirationDepth(nHeight)));
            oName.push_back(Pair("expires_in", nHeight + GetAliasDisplayExpirationDepth(nHeight)- pindexBest->nHeight ));
		}
		oRes.push_back(oName);

		nCountNb++;
		// nb limits
		if (nNb > 0 && nCountNb >= nNb)
			break;
	}

	if (fStat) {
		Object oStat;
		oStat.push_back(Pair("blocks", (int) nBestHeight));
		oStat.push_back(Pair("count", (int) oRes.size()));
		return oStat;
	}

	return oRes;
}

/**
 * [aliasscan description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
Value aliasscan(const Array& params, bool fHelp) {
	if (fHelp || 2 > params.size())
		throw runtime_error(
				"aliasscan [<start-name>] [<max-returned>]\n"
						"scan all aliases, starting at start-name and returning a maximum number of entries (default 500)\n");

	vector<unsigned char> vchName;
	int nMax = 500;
	if (params.size() > 0)
		vchName = vchFromValue(params[0]);
	if (params.size() > 1) {
		Value vMax = params[1];
		ConvertTo<double>(vMax);
		nMax = (int) vMax.get_real();
	}

	Array oRes;

	vector<pair<vector<unsigned char>, CAliasIndex> > nameScan;
	if (!paliasdb->ScanNames(vchName, nMax, nameScan))
		throw JSONRPCError(RPC_WALLET_ERROR, "scan failed");

	pair<vector<unsigned char>, CAliasIndex> pairScan;
	BOOST_FOREACH(pairScan, nameScan) {
		Object oName;
		string name = stringFromVch(pairScan.first);
		oName.push_back(Pair("name", name));
		CTransaction tx;
		CAliasIndex txName = pairScan.second;
		uint256 blockHash;

		int nHeight = txName.nHeight;
		vector<unsigned char> vchValue = txName.vValue;
		if ((nHeight + GetAliasDisplayExpirationDepth(nHeight)
				- pindexBest->nHeight <= 0)
				|| !GetTransaction(txName.txHash, tx, blockHash, true)) {
			oName.push_back(Pair("expired", 1));
		} else {
			string value = stringFromVch(vchValue);
			oName.push_back(Pair("txid", txName.txHash.GetHex()));
			oName.push_back(Pair("value", value));
            oName.push_back(Pair("lastupdate_height", nHeight));
            oName.push_back(Pair("expires_on", nHeight + GetAliasDisplayExpirationDepth(nHeight)));
            oName.push_back(Pair("expires_in", nHeight + GetAliasDisplayExpirationDepth(nHeight)- pindexBest->nHeight ));
		}
		oRes.push_back(oName);
	}

	return oRes;
}

void UnspendInputs(CWalletTx& wtx) {
	set<CWalletTx*> setCoins;
	BOOST_FOREACH(const CTxIn& txin, wtx.vin) {
		if (!pwalletMain->IsMine(txin)) {
			printf("UnspendInputs(): !mine %s", txin.ToString().c_str());
			continue;
		}
		CWalletTx& prev = pwalletMain->mapWallet[txin.prevout.hash];
		unsigned int nOut = txin.prevout.n;

		printf("UnspendInputs(): %s:%d spent %d\n",
				prev.GetHash().ToString().c_str(), nOut, prev.IsSpent(nOut));

		if (nOut >= prev.vout.size())
			throw runtime_error("CWalletTx::MarkSpent() : nOut out of range");
		prev.vfSpent.resize(prev.vout.size());
		if (prev.vfSpent[nOut]) {
			prev.vfSpent[nOut] = false;
			prev.fAvailableCreditCached = false;
			prev.WriteToDisk();
		}
#ifdef GUI
		//pwalletMain->vWalletUpdated.push_back(prev.GetHash());
		pwalletMain->NotifyTransactionChanged(pwalletMain, prev.GetHash(), CT_DELETED);

#endif
	}
}

Value aliasclean(const Array& params, bool fHelp) {
	if (fHelp || params.size())
		throw runtime_error(
				"aliasclean\nClean unsatisfiable alias transactions from the wallet - including aliasactivate on an already taken alias\n");
	{
		EnsureWalletIsUnlocked();
		map<uint256, CWalletTx> mapRemove;

		printf("-----------------------------\n");
		{
			BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
				CWalletTx& wtx = item.second;
				vector<unsigned char> vchName;
				if (wtx.GetDepthInMainChain() < 1
						&& IsConflictedAliasTx(*pblocktree, wtx, vchName)) {
					uint256 hash = wtx.GetHash();
					mapRemove[hash] = wtx;
				}
			}
		}

		bool fRepeat = true;
		while (fRepeat) {
			fRepeat = false;
			BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
				CWalletTx& wtx = item.second;
				BOOST_FOREACH(const CTxIn& txin, wtx.vin) {
					uint256 hash = wtx.GetHash();

					// If this tx depends on a tx to be removed, remove it too
					if (mapRemove.count(txin.prevout.hash)
							&& !mapRemove.count(hash)) {
						mapRemove[hash] = wtx;
						fRepeat = true;
					}
				}
			}
		}

		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapRemove) {
			CWalletTx& wtx = item.second;

			UnspendInputs(wtx);
			wtx.RemoveFromMemoryPool();
			pwalletMain->EraseFromWallet(wtx.GetHash());
			vector<unsigned char> vchName;
			if (GetAliasOfTx(wtx, vchName)
					&& mapAliasesPending.count(vchName)) {
				string name = stringFromVch(vchName);
				printf("name_clean() : erase %s from pending of name %s",
						wtx.GetHash().GetHex().c_str(), name.c_str());
				if (!mapAliasesPending[vchName].erase(wtx.GetHash()))
					error("name_clean() : erase but it was not pending");
			}
			wtx.print();
		}
		printf("-----------------------------\n");
	}
	return true;
}
/*
 Value deletetransaction(const Array& params, bool fHelp)
 {
 if (fHelp || params.size() != 1)
 throw runtime_error(
 "deletetransaction <txid>\nNormally used when a transaction cannot be confirmed due to a double spend.\nRestart the program after executing this call.\n"
 );

 {
 LOCK2(cs_main, pwalletMain->cs_wallet);

 // look for txn in wallet
 uint256 hash;
 hash.SetHex(params[0].get_str());
 if (!pwalletMain->mapWallet.count(hash))
 throw runtime_error("transaction not in wallet");

 if (!mapTransactions.count(hash)) {
 //throw runtime_error("transaction not in memory - is already in blockchain?");
 CTransaction tx;
 uint256 hashBlock = 0;
 if (GetTransaction(hash, tx, hashBlock) && hashBlock != 0)
 throw runtime_error("transaction is already in blockchain");
 }
 CWalletTx wtx = pwalletMain->mapWallet[hash];
 UnspendInputs(wtx);

 // We are not removing from mapTransactions because this can cause memory corruption
 // during mining.  The user should restart to clear the tx from memory.
 wtx.RemoveFromMemoryPool();
 pwalletMain->EraseFromWallet(wtx.GetHash());
 vector<unsigned char> vchName;
 if (GetAliasOfTx(wtx, vchName) && mapAliasesPending.count(vchName)) {
 printf("deletetransaction() : remove from pending");
 mapAliasesPending[vchName].erase(wtx.GetHash());
 }
 return "success, please restart program to clear memory";
 }
 }
 */

/**
 * [aliasscan description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
Value getaliasfees(const Array& params, bool fHelp) {
	if (fHelp || 0 != params.size())
		throw runtime_error(
				"getaliasfees\n"
						"get current service fees for alias transactions\n");
	Object oRes;
	oRes.push_back(Pair("height", nBestHeight ));
	oRes.push_back(Pair("subsidy", ValueFromAmount(GetAliasFeeSubsidy(nBestHeight) )));
	oRes.push_back(Pair("new_fee", (double)1.0));
	oRes.push_back(Pair("activate_fee", ValueFromAmount(GetAliasNetworkFee(1, nBestHeight) )));
	oRes.push_back(Pair("update_fee", ValueFromAmount(GetAliasNetworkFee(2, nBestHeight) )));
	return oRes;

}


Value dataactivate(const Array& params, bool fHelp) {
	if (fHelp || params.size() < 4 || params.size() > 5)
		throw runtime_error(
				"dataactivate <dataName> <guid> [<tx>] <filename> <data>\n"
						"Perform a data activate after a datanew reservation.\n"
						"Note that the activate will go into a block 120 blocks after the datanew, at the soonest."
						+ HelpRequiringPassphrase());

	vector<unsigned char> vchName = vchFromValue(params[0]);
	vector<unsigned char> vchRand = ParseHex(params[1].get_str());
	vector<unsigned char> vchFilename;
	string baSig;

	// Transaction data
	std::string txdata;
	if (params.size() == 5) {
		vchFilename = vchFromValue(params[3]);
		txdata = params[4].get_str();
	} else {
		vchFilename = vchFromValue(params[2]);
		txdata = params[3].get_str();
	}
	if (txdata.length() > MAX_TX_DATA_SIZE)
		throw JSONRPCError(RPC_INVALID_PARAMETER, "Data chunk is too long.");

//    // sign using the first key in wallet
//    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
//        if (IsMine(*pwalletMain, entry.first)) {
//            // sign the data and store it as the alias value
//            CKeyID keyID;
//            CBitcoinAddress address;
//            address.Set(entry.first);
//            if (!address.GetKeyID(keyID))
//                throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
//            CKey key;
//            if (!pwalletMain->GetKey(keyID, key))
//                throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");
//            CHashWriter ss(SER_GETHASH, 0);
//            ss << strMessageMagic;
//            ss << txdata;
//            vector<unsigned char> vchSig;
//            if (!key.SignCompact(ss.GetHash(), vchSig))
//                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");
//            baSig = EncodeBase64(vchSig.data(), vchSig.size());
//            vchValue = vchFromString(baSig);
//            break;
//        }
//    }

	// this is a syscoin transaction
	CWalletTx wtx;
	wtx.nVersion = SYSCOIN_TX_VERSION;

	{
		if (mapAliasesPending.count(vchName)
				&& mapAliasesPending[vchName].size()) {
			error(
					"dataactivate() : there are %d pending operations on that data, including %s",
					(int) mapAliasesPending[vchName].size(),
					mapAliasesPending[vchName].begin()->GetHex().c_str());
			throw runtime_error("there are pending operations on that data");
		}

		CTransaction tx;
		if (GetTxOfAlias(*paliasdb, vchName, tx)) {
			error("dataactivate() : this data is already active with tx %s",
					tx.GetHash().GetHex().c_str());
			throw runtime_error("this data is already active");
		}

		{
			EnsureWalletIsUnlocked();

			// Make sure there is a previous aliasnew tx on this name and that the random value matches
			uint256 wtxInHash;
			if (params.size() == 4) {
				if (!mapMyAliases.count(vchName))
					throw runtime_error(
							"could not find any data with this name, try specifying the datanew transaction id");
				wtxInHash = mapMyAliases[vchName];
			} else
				wtxInHash.SetHex(params[2].get_str());

			if (!pwalletMain->mapWallet.count(wtxInHash))
				throw runtime_error(
						"previous transaction is not in the wallet");

			CPubKey newDefaultKey;
			pwalletMain->GetKeyFromPool(newDefaultKey, false);
			CScript scriptPubKeyOrig;
			scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
			// create a syscoin DATA_FIRSTUPDATE transaction
			CScript scriptPubKey;
			scriptPubKey << CScript::EncodeOP_N(OP_ALIAS_ACTIVATE) << vchName
					<< vchRand << vchFilename << OP_2DROP << OP_2DROP;
			scriptPubKey += scriptPubKeyOrig;

			CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];
			vector<unsigned char> vchHash;
			bool found = false;
			BOOST_FOREACH(CTxOut& out, wtxIn.vout) {
				vector<vector<unsigned char> > vvch;
				int op;
				if (DecodeAliasScript(out.scriptPubKey, op, vvch)) {
					if (op != OP_ALIAS_NEW)
						throw runtime_error(
								"previous transaction was not a datanew");
					vchHash = vvch[0];
					found = true;
					break;
				}
			}

			if (!found)
				throw runtime_error(
						"previous tx on this data is not a syscoin tx");

			vector<unsigned char> vchToHash(vchRand);
			vchToHash.insert(vchToHash.end(), vchName.begin(), vchName.end());
			uint160 hash = Hash160(vchToHash);
			if (uint160(vchHash) != hash)
				throw runtime_error(
						"previous tx used a different random value");

			int64 nNetFee = GetAliasNetworkFee(1, pindexBest->nHeight);
			// Round up to CENT
			nNetFee += CENT - 1;
			nNetFee = (nNetFee / CENT) * CENT;

			string strError = SendMoneyWithInputTx(scriptPubKey, MIN_AMOUNT,
					nNetFee, wtxIn, wtx, false, txdata);
			if (strError != "")
				throw JSONRPCError(RPC_WALLET_ERROR, strError);
		}
	}
	baSig += "\n" + wtx.GetHash().GetHex();
	return baSig;
}

Value dataupdate(const Array& params, bool fHelp) {
	if (fHelp || params.size() < 3 || params.size() > 4)
		throw runtime_error(
				"dataupdate <dataName> <filename> <data> [<toaddress>]\n"
						"Update and possibly transfer a data alias."
						+ HelpRequiringPassphrase());

	vector<unsigned char> vchName = vchFromValue(params[0]);
	vector<unsigned char> vchValue = vchFromValue(params[1]);
	std::string txdata = params[2].get_str();
	if (txdata.length() > MAX_TX_DATA_SIZE)
		throw JSONRPCError(RPC_INVALID_PARAMETER,
				"Data chunk is too long.  Split the payload to several transactions.");

	CWalletTx wtx;
	wtx.nVersion = SYSCOIN_TX_VERSION;
	CScript scriptPubKeyOrig;

	if (params.size() == 4) {
		string strAddress = params[3].get_str();
		CBitcoinAddress myAddress = CBitcoinAddress(strAddress);
		if (!myAddress.IsValid())
			throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
					"Invalid syscoin address");
		scriptPubKeyOrig.SetDestination(myAddress.Get());
	} else {
		CPubKey newDefaultKey;
		pwalletMain->GetKeyFromPool(newDefaultKey, false);
		scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
	}

	// create a syscoind DATA_UPDATE transaction
	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << vchName << vchValue
			<< OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;

	{

		if (mapAliasesPending.count(vchName)
				&& mapAliasesPending[vchName].size()) {
			error(
					"dataupdate() : there are %d pending operations on that data, including %s",
					(int) mapAliasesPending[vchName].size(),
					mapAliasesPending[vchName].begin()->GetHex().c_str());
			throw runtime_error("there are pending operations on that data");
		}

		EnsureWalletIsUnlocked();

		CTransaction tx;
		if (!GetTxOfAlias(*paliasdb, vchName, tx))
			throw runtime_error("could not find this data alias"
					" in your wallet");
		if (tx.GetData().size() == 0)
			throw runtime_error("cannot modify this non-data alias."
					" use aliasupdate");

		uint256 wtxInHash = tx.GetHash();

		if (!pwalletMain->mapWallet.count(wtxInHash)) {
			error("aliasupdate() : this data is not in your wallet %s",
					wtxInHash.GetHex().c_str());
			throw runtime_error("this data is not in your wallet");
		}

		int64 nNetFee = GetAliasNetworkFee(2, pindexBest->nHeight);
		// Round up to CENT
		nNetFee += CENT - 1;
		nNetFee = (nNetFee / CENT) * CENT;

		CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];
		string strError = SendMoneyWithInputTx(iface,
        scriptPubKey, MIN_AMOUNT,
        nNetFee, wtxIn, wtx, false, txdata);
    if (strError != "")
      throw JSONRPCError(RPC_WALLET_ERROR, strError);

  }
  return wtx.GetHash().GetHex();
}

Value datalist(const Array& params, bool fHelp) {
  return aliaslist(params, fHelp);
}

Value datainfo(const Array& params, bool fHelp) {
	return aliasinfo(params, fHelp);
}

Value datahistory(const Array& params, bool fHelp) {
	return aliashistory(params, fHelp);
}

Value datafilter(const Array& params, bool fHelp) {
	return aliasfilter(params, fHelp);
}
#endif




bool IsAliasOp(int op) {
	return (op == OP_ALIAS);
}


string aliasFromOp(int op) {
	switch (op) {
	case OP_EXT_ACTIVATE:
		return "aliasactivate";
	case OP_EXT_UPDATE:
		return "aliasupdate";
	default:
		return "<unknown alias op>";
	}
}

bool DecodeAliasScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) 
{
	opcodetype opcode;
  int mode;

	if (!script.GetOp(pc, opcode))
		return false;
  mode = opcode; /* extension mode (new/activate/update) */

	if (!script.GetOp(pc, opcode))
		return false;
	if (opcode < OP_1 || opcode > OP_16)
		return false;

	op = CScript::DecodeOP_N(opcode); /* extension type (alias) */
  if (op != OP_ALIAS)
    return false;

	for (;;) {
		vector<unsigned char> vch;
		if (!script.GetOp(pc, opcode, vch))
			return false;
		if (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP)
			break;
		if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
			return false;
		vvch.push_back(vch);
	}

	// move the pc to after any DROP or NOP
	while (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP) {
		if (!script.GetOp(pc, opcode))
			break;
	}

	pc--;

	if ((mode == OP_EXT_ACTIVATE && vvch.size() == 2) ||
      (mode == OP_EXT_UPDATE && vvch.size() >= 1) ||
      (mode == OP_EXT_TRANSFER && vvch.size() >= 1) ||
      (mode == OP_EXT_REMOVE && vvch.size() >= 1))
    return (true);

	return false;
}

bool DecodeAliasScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeAliasScript(script, op, vvch, pc);
}

CScript RemoveAliasScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeAliasScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveAliasScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetAliasOpFee(CIface *iface, int nHeight) 
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5000 / base * COIN;
  double nDif = 4982 /base * COIN;
  int64 fee = (int64)(nRes - nDif);
  return (MAX(iface->min_tx_fee, fee));
}


int64 GetAliasReturnFee(const CTransaction& tx) 
{
	int64 nFee = 0;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
			nFee += out.nValue;
	}
	return nFee;
}

bool IsAliasTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_ALIAS)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeAliasHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

/**
 * Obtain the tx that defines this alias.
 */
bool GetTxOfAlias(CIface *iface, const std::string strTitle, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  alias_list *aliases = GetAliasTable(ifaceIndex);
  bool ret;

  if (aliases->count(strTitle) == 0) {
    return false; /* nothing by that name, sir */
  }

  uint256 hashBlock;
  uint256 hashTx = (*aliases)[strTitle];
  CTransaction txIn;
  ret = GetTransaction(iface, hashTx, txIn, NULL);
  if (!ret) {
    return false;
  }

  if (!IsAliasTx(txIn)) 
    return false; /* inval; not an alias tx */

  if (txIn.alias.IsExpired()) {
    return false;
  }

  tx.Init(txIn);
  return true;
}

bool IsLocalAlias(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalAlias(CIface *iface, const CTransaction& tx)
{
  if (!IsAliasTx(tx))
    return (false); /* not a alias */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalAlias(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an alias transaction.
 */
bool VerifyAlias(CTransaction& tx)
{
  uint160 hashAlias;
  int nOut;


  /* core verification */
  if (!IsAliasTx(tx)) {
fprintf(stderr, "DEBUG: VerifyAlias: is not alias tx\n");
    return (false); /* tx not flagged as alias */
}

  /* verify hash in pub-script matches alias hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1) {
fprintf(stderr, "DEBUG: VerifyAlias: has no extension output\n");
    return (false); /* no extension output */
}

  int mode;
  if (!DecodeAliasHash(tx.vout[nOut].scriptPubKey, mode, hashAlias)) {
fprintf(stderr, "DEBUG: VerifyAlias: !DecodeAliasHash: %s\n", tx.vout[nOut].scriptPubKey.ToString().c_str());
    return (false); /* no alias hash in output */
}

  if (mode != OP_EXT_ACTIVATE && 
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_REMOVE) {
fprintf(stderr, "DEBUG: VerifyAlias: invalid mode %d\n", mode);
    return (false);
}

  CAlias *alias = tx.GetAlias();
  if (hashAlias != alias->GetHash()) {
fprintf(stderr, "DEBUG: VerifyAlias: alias hash mismatch: hashAlias(%s) txAlias(%s)\n", hashAlias.GetHex().c_str(), alias->GetHash().GetHex().c_str());
    return (false); /* alias hash mismatch */
}

  return (true);
}



int init_alias_addr_tx(CIface *iface, const char *title, CCoinAddr& addr, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strTitle(title);

  if(strlen(title) == 0)
    return (SHERR_INVAL);
  if(strlen(title) > 135)
    return (SHERR_INVAL);

  if (wallet->mapAlias.count(strTitle) != 0)
    return (SHERR_NOTUNIQ);

  bool found = false;
  string strAccount;
  BOOST_FOREACH(const PAIRTYPE(CCoinAddr, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = item.first;
    const string& account = item.second;
    if (address == addr) {
      addr = address;
      strAccount = account;
      found = true;
      break;
    }
  }
  if (!found) {
    return (SHERR_NOENT);
  }

  CKeyID key_id;
  if (!addr.GetKeyID(key_id)) {
    return (SHERR_OPNOTSUPP);
  }

  CAlias *alias;

  /* embed alias content into transaction */
  wtx.SetNull();
  alias = wtx.CreateAlias(strTitle, key_id);
  alias->SetActive(true); /* auto-activate */
  wtx.strFromAccount = strAccount; /* originating account for payment */

  int64 nFee = GetAliasOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (SHERR_AGAIN);
  }

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  uint160 aliasHash = alias->GetHash();
  CScript scriptPubKey;

  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);
  if (!extAddr.IsValid()) {
fprintf(stderr, "DEBUG: error obtaining address for '%s'\n", strExtAccount.c_str());
    return (SHERR_INVAL);
}

  scriptPubKeyOrig.SetDestination(extAddr.Get());
  scriptPubKey << OP_EXT_ACTIVATE << CScript::EncodeOP_N(OP_ALIAS) << OP_HASH160 << aliasHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  // send transaction
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  /* todo: add to pending instead */
  wallet->mapAlias[strTitle] = wtx.GetHash();

  Debug("SENT:ALIASNEW : title=%s, ref=%s, aliashash=%s, tx=%s\n", title, key_id.GetHex().c_str(), alias->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}



int update_alias_addr_tx(CIface *iface, const char *title, CCoinAddr& addr, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
  string strTitle(title);

  if (strlen(title) > MAX_SHARE_NAME_LENGTH)
    return (SHERR_INVAL);
  if (!addr.IsValid())
    return (SHERR_INVAL);

  CKeyID key_id;
  if (!addr.GetKeyID(key_id))
    return (SHERR_OPNOTSUPP);

  /* verify original alias */
  CTransaction tx;
  if (!GetTxOfAlias(iface, strTitle, tx))
    return (SHERR_NOENT);
  if(!IsLocalAlias(iface, tx))
    return (SHERR_REMOTE);

  if (wallet->mapAlias.count(strTitle) != 0 && /* unique new name */
      tx.alias.GetLabel() != strTitle) /* or just the same name */
    return (SHERR_NOTUNIQ);

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0)
    return (SHERR_REMOTE);

  /* establish account */
  CCoinAddr extAddr;
  string strAccount;
  if (!GetCoinAddr(wallet, addr, strAccount)) 
    return (SHERR_INVAL);

  /* generate new coin address */
  string strExtAccount = "@" + strAccount;
  extAddr = GetAccountAddress(wallet, strExtAccount, true);

  /* generate tx */
  CAlias *alias;
	CScript scriptPubKey;
  wtx.SetNull();
  alias = wtx.CreateAlias(strTitle, key_id);
  uint160 aliasHash = alias->GetHash();

  vector<pair<CScript, int64> > vecSend;
  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_ALIAS) << OP_HASH160 << aliasHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  int64 nNetFee = GetAliasOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }
  if (nNetFee) { /* supplemental tx payment */
    CScript scriptFee;
    scriptFee << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_ALIAS) << OP_HASH160 << aliasHash << OP_2DROP << OP_RETURN;
    vecSend.push_back(make_pair(scriptFee, nNetFee));
  }

  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend))
    return (SHERR_INVAL);

/* todo: add to pending instead */
  wallet->mapAlias[strTitle] = wtx.GetHash();

#if 0
  BOOST_FOREACH(const CTxOut& out, wtx.vout) 
  {
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    const CScript& script = out.scriptPubKey;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end())
    {
      if (!str.empty())
        str += "<blank>";
      if (!script.GetOp(pc, opcode, vch))
      {
        str += "<error>";
        break;
      }
      if (0 <= opcode && opcode <= OP_PUSHDATA4) {
        str += "\"";
        str += ValueString(vch);
        str += "\"";
      } else {
        str += "(";
        str += GetOpName(opcode);
        str += ")";
      }
    }
fprintf(stderr, "DEBUG: WTX.VOUT: %s\n", str.c_str());
  }
#endif


	return (0);
}

/*
const uint160 CAlias::GetHash()
{
  SHAlias ref;
  FillReference(&ref);
  unsigned char *data = (unsigned char *)&ref;
fprintf(stderr, "DEBUG: CAlias::GetHash: ref [name(%s) hash(%s) peer(%s) expire(%llu) type(%u) level(%u)\n", ref.ref_name, ref.ref_hash, shkey_print(&ref.ref_peer), ref.ref_expire, ref.ref_type, ref.ref_level);
  cbuff buff(data, data + sizeof(ref));
  return (Hash160(buff));
}
*/

/*
const char *CAlias::ToString()
{
  const char ret_str[1024];

  sprintf(ret_str, "Alias(name='%s', hash='%s', peer='%s', type=%d, expire=%-24.24s)",
      ref.ref_name, ref.ref_hash, shkey_print(&ref.ref_peer), 
      ref.ref_type, shctime(ref.ref_expire)); 

  return (ret_str);
}

*/
std::string CAlias::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CAlias::ToValue()
{
  return (CIdent::ToValue());
}


