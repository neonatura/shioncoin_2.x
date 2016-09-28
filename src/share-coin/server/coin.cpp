
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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
#include "block.h"
#include "db.h"
#include <vector>

using namespace std;

/**
 * Write specific amount of available coins per transaction output.
 */
bool CTransaction::WriteCoins(int ifaceIndex, const vector<int64>& vAmount)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockCoinChain(iface);
  uint256 hash = GetHash();
  int64 *data;
  char errbuf[1024];
  int64 blockPos;
  size_t data_len;
  int txPos;
  int err;

  if (!bc) {
    error(SHERR_IO, "CTransaction::WriteCoinSpent: error opening coin chain.");
    return (false);
  }
  if (vAmount.size() < vout.size()) {
    return (false); /* nerp */
  }

  txPos = 0;
  data_len = 0;
  err = bc_idx_find(bc, hash.GetRaw(), NULL, &txPos);
  if (!err) { /* exists */
    err = bc_get(bc, txPos, &data, &data_len);
    if (err) {
      return (error(err, "CTransaction.WriteCoinSpent: error obtaining data for db-index #%u.", (unsigned int)txPos));
    }
    if (data_len < (sizeof(int64) * vout.size())) {
      free(data);
      return (error(err, "CTransaction.WriteCoinSpent: data content truncated <%d bytse> for db-index #%u.", data_len, (unsigned int)txPos));
    }
  } else { /* fresh */
    data_len = (vout.size() * sizeof(int64));
    data = (int64 *)calloc(vout.size(), sizeof(int64));
    if (!data) {
      return (error(SHERR_NOMEM, "CTransaction.WriteCoinSpent: unable to allocate <%u bytes>", (unsigned int)data_len));
    }
  }

  for (idx = 0; idx < vout.size(); idx++) {
    if (data[idx] != vAmount[idx])
      break;
  }
  if (idx == vout.size())
    return (true); /* nothing changed */

  for (idx = 0; idx < vout.size(); idx++) {
    data[idx] = vAmount[idx];
  }

  /* store new coin outputs */
  err = bc_write(bc, txPos, hash.GetRaw(), data, data_len);
  if (err) {
    free(data);
    return (error(err, "CTransaction.WriteCoinSpent: error writing <%d bytes> to db-index #%u.", data_len, (unsigned int)txPos));
  }

  /* cleanup */
  free(data);

  return (true);
}

/**
 * Mark a transaction output as being spent.
 * @param fUnspend Set to 'true' to indicate a block disconnect.
 * @note Called from the originating (input) transaction.
 */
bool CTransaction::WriteCoins(int ifaceIndex, int nOut, bool fUnspend)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockCoinChain(iface);
  uint256 hash = GetHash();
  int64 *data;
  char errbuf[1024];
  int64 blockPos;
  size_t data_len;
  int txPos;
  int err;

  if (!bc) {
    error(SHERR_IO, "CTransaction::WriteCoinSpent: error opening coin chain.");
    return (false);
  }
  if (nOut < 0 || nOut >= vout.size()) {
    return (false); /* nerp */
  }

  txPos = 0;
  data_len = 0;
  err = bc_idx_find(bc, hash.GetRaw(), NULL, &txPos);
  if (!err) { /* exists */
    err = bc_get(bc, txPos, &data, &data_len);
    if (err) {
      return (error(err, "CTransaction.WriteCoinSpent: error obtaining data for db-index #%u.", (unsigned int)txPos));
    }
    if (data_len < (sizeof(int64) * vout.size())) {
      free(data);
      return (error(err, "CTransaction.WriteCoinSpent: data content truncated <%d bytse> for db-index #%u.", data_len, (unsigned int)txPos));
    }
  } else { /* fresh */
    data_len = (vout.size() * sizeof(int64));
    data = (int64 *)calloc(vout.size(), sizeof(int64));
    if (!data) {
      return (error(SHERR_NOMEM, "CTransaction.WriteCoinSpent: unable to allocate <%u bytes>", (unsigned int)data_len));
    }

    /* assign initial coin values */
    for (idx = 0; idx < vout.size(); idx++) {
      data[idx] = vout[idx].nValue;
    }
  }
  if (data[nOut] == 0)
    return (true); /* already marked as spent. */

  uint64 nValue = 0;
  if (fUnspend) {
    nValue = vout[nOut].nValue;
  } else {
    /* assign spent coin as non-avail */
  }
  memcpy(data + nOut, &nValue, sizeof(int64));

  /* store new coin outputs */
  err = bc_write(bc, txPos, hash.GetRaw(), data, data_len);
  if (err) {
    free(data);
    return (error(err, "CTransaction.WriteCoinSpent: error writing <%d bytes> to db-index #%u.", data_len, (unsigned int)txPos));
  }

  /* cleanup */
  free(data);

  return (true);
}

bool CTransaction::WriteCoins(int ifaceIndex, const vector<char>& vfSpent)
{

  if (vfSpent.size() == 0)
    return (true); /* all done */

  if (vfSpent.size() != vout.size())
    return (false); /* factory mishap */

  for (idx = 0; idx < vout.size(); idx++) {
    if (!vfSpent[idx])
      continue;

    if (!WriteCoinSpent(ifaceIndex, idx)) {
      return (error(SHERR_INVAL, "WirteCoinSpent: error marking coin as spent."));
    }
  }

  return (true);
}

/**
 * Obtain all of the unspent outputs for a transaction.
 * @note Called from the originating (input) transaction.
 */
bool CTransaction::ReadCoins(int ifaceIndex, vector<int64>& vAmount, int64& nTotalValue)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockCoinChain(iface);
  const int64 nMinInput = (const int64)iface->min_input;
  uint256 hash = GetHash();
  int64 *data;
  char errbuf[1024];
  int64 blockPos;
  size_t data_len;
  int txPos;
  int idx;
  int err;

  if (!bc) {
    unet_log(ifaceIndex, "CTransaction::ReadCoins: error opening coin chain.");
    return (false);
  }

  txPos = -1;
  data_len = 0;
  data = NULL;
  err = bc_idx_find(bc, hash.GetRaw(), NULL, &txPos);
  if (!err) { /* exists */
    err = bc_get(bc, txPos, &data, &data_len);
    if (err) {
      return (error(err, "CTransaction.ReadCoins: error obtaining data for db-index #%u.", (unsigned int)txPos));
    }
    if (data_len < (sizeof(int64) * vout.size())) {
      free(data);
      return (error(err, "CTransaction.ReadCoins: data content truncated <%d bytse> for db-index #%u.", data_len, (unsigned int)txPos));
    }
  } else {
    /* all coins are still available. */
  }

  /* assign spent coin as non-avail */
  nTotalValue = 0;
  vAmount.resize(vout.size());
  for (idx = 0; idx < vout.size(); idx++) {
    int64 nValue;
    if (data) {
      nValue = data[idx];
    } else {
      nValue = vout[idx].nValue;
    }
    if (nValue >= nMinInput) {
      vAmount[idx] = nValue;
      nTotalValue += nValue;
    } else {
      vAmount[idx] = nValue;
    }
  }
  if (!MoneyRange(iface, nTotalValue)) {
    return (error(SHERR_INVAL, "CTransaction.ReadCoins: total coin value for transaction is out of bounds (%-8.8f coins).", ((double)nTotalValue/(double)COIN)));
  }
  
  if (data) {
    /* cleanup */
    free(data);
  }

  return (true);
}

bool CTransaction::ReadCoins(int ifaceIndex, vector<CTxOut>& vOut, uint64& nTotalValue)
{
  vector<int64> vAmount;
  int idx;

  vOut.clear();

  if (!ReadCoins(ifaceIndex, vAmount, nTotalValue))
    return (false);

  if (vAmount.size() != vout.size())
    return (false);

  for (idx = 0; idx < vout.size(); idx++) {
    if (vAmount[idx] != 0)
      vOut.push_back(vout[idx]);
  }

  return (true);
}

bool CTransaction::ReadCoins(int ifaceIndex, vector<char>& vfSpent)
{
  vector<int64> vAmount;
  int idx;

  if (!ReadCoins(ifaceIndex, vAmount, nTotalValue))
    return (false);

  vfSpent.resize(vout.size());
  for (idx = 0; idx < vout.size(); idx++) {
    vfSpent[idx] = (vAmount[idx] == 0);
  }

  return (true);
}




