
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
#include "block.h"
#include "wallet.h"


#if 0
void CTxMatrix::ClearCells()
{
  int row, col;

  for (row = 0; row < nSize; row++) {
    for (col = 0; col < nSize; col++) {
      SetCell(row, col, 0);
    }
  }
}
#endif

void CTxMatrix::Append(int heightIn, uint256 hash)
{
  nHeight = heightIn;

  int idx = (nHeight / 27) % 9;
  int row = (idx / 3) % 3;
  int col = idx % 3;
  unsigned int crc = (unsigned int)shcrc(hash.GetRaw(), 32);
  AddCell(row, col, crc);
fprintf(stderr, "DEBUG: CTxMatrix::Append: data[%d][%d] = %x (%x) [hash %s]\n", row, col, GetCell(row, col), crc, hash.GetHex().c_str());
}

void CTxMatrix::Retract(int heightIn, uint256 hash)
{

  if (heightIn > nHeight)
    return;

  nHeight = heightIn - 27;

  int idx = (heightIn / 27) % 9;
  int row = (idx / 3) % 3;
  int col = idx % 3;
  SubCell(row, col, (unsigned int)shcrc(hash.GetRaw(), 32));
fprintf(stderr, "DEBUG: CTxMatrix::Retract: data[%d][%d] += %d\n", row, col, GetCell(row, col));
}



/* 'zero transactions' penalty. */
bool BlockGenerateValidateMatrix(CIface *iface, ValidateMatrix *matrixIn, CTransaction& tx, int64& nReward)
{

  int64 nFee = MAX(0, MIN(COIN, nReward - iface->min_tx_fee));
  if (nFee < iface->min_tx_fee)
    return (false); /* reward too small */

  CTxMatrix *m = tx.GenerateValidateMatrix(TEST_COIN_IFACE, (CTxMatrix *)matrixIn);
  if (!m)
    return (false); /* not applicable */

  uint160 hashMatrix = m->GetHash();
  int64 min_tx = (int64)iface->min_tx_fee;
  CScript scriptMatrix;
  scriptMatrix << OP_EXT_VALIDATE << CScript::EncodeOP_N(OP_MATRIX) << OP_HASH160 << hashMatrix << OP_2DROP << OP_RETURN;
  tx.vout.push_back(CTxOut(nFee, scriptMatrix));

  /* deduct from reward. */
  nReward -= nFee;

  Debug("BlockGenerateValidateMatrix: (matrix hash %s) proposed: %s\n", hashMatrix.GetHex().c_str(), m->ToString().c_str());

  return (true);
}

bool BlockAcceptValidateMatrix(ValidateMatrix *matrixIn,
    ValidateMatrix& matrix, CTransaction& tx, bool& fCheck)
{
  bool fMatrix = false;
  int mode;

  if (VerifyMatrixTx(tx, mode) && mode == OP_EXT_VALIDATE) {
    CBlockIndex *pindex = GetBestBlockIndex(TEST_COIN_IFACE);
    CTxMatrix& matrix = *tx.GetMatrix();
    if (matrix.GetType() == CTxMatrix::M_VALIDATE &&
        matrix.GetHeight() > matrixIn->GetHeight()) {
      if (!tx.VerifyValidateMatrix(matrixIn, matrix, pindex)) {
        fCheck = false;
      } else {
        fCheck = true;
        Debug("TESTBlock::AcceptBlock: Validate verify success: (seed %s) (new %s)\n", matrixIn->ToString().c_str(), matrix.ToString().c_str());
      }
      return (true); /* matrix was found */
    }
  }

  return (false); /* no matrix was present */
}


#if 0
void LargeMatrix::compress(CTxMatrix& matrixIn)
{
  int row, col;
  int n_row, n_col;
  double deg;

  matrixIn.ClearCells();

  deg = nSize / matrixIn.nSize; 
  for (row = 0; row < nSize; row++) {
    for (col = 0; col < nSize; col++) {
      n_row = (row / deg); 
      n_col = (col / deg); 
      matrixIn.AddCell(n_row, n_col, GetCell(row, col)); 
    }
  }

}
#endif

shgeo_t *GetMatrixOrigin(CTransaction& tx)
{
  static shgeo_t geo;
memset(&geo, 0, sizeof(geo));
return (&geo);
}
