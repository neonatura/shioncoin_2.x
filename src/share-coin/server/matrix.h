
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


#ifndef __MATRIX_H__
#define __MATRIX_H__


class CTxMatrix
{
  public:
    static const int PROTO_VERSION = 1;

    static const int M_VALIDATE = 1;
    static const int M_SPRING = 2;

    unsigned int nVersion;
    unsigned int nType;
    unsigned int nHeight; 
    unsigned int __reserved_0__;
    uint160 hRef;
    uint32_t vData[3][3];

    CTxMatrix()
    {
      SetNull();
    }

    CTxMatrix(const CTxMatrix& matrix)
    {
      SetNull();
      Init(matrix);
    }

    IMPLEMENT_SERIALIZE
      (
       READWRITE(this->nVersion);
       READWRITE(this->nHeight);
       READWRITE(this->nType);
       READWRITE(this->__reserved_0__);
       READWRITE(this->hRef);
       READWRITE(FLATDATA(this->vData));
      )

    friend bool operator==(const CTxMatrix& a, const CTxMatrix& b)
    {
      return (
          a.nVersion == b.nVersion &&
          a.nHeight == b.nHeight &&
          a.nType == b.nType &&
          a.hRef == b.hRef &&
          0 == memcmp(a.vData, b.vData, sizeof(uint32_t) * 9)
      );
    }

    friend bool operator!=(const CTxMatrix& a, const CTxMatrix& b)
    {
      return !(a == b);
    }

    CTxMatrix operator=(const CTxMatrix &b)
    {
      Init(b);
      return (*this);
    }

    void SetNull()
    {
      nVersion = PROTO_VERSION;
      nHeight = 0;
      nType = 0;
      __reserved_0__ = 0;
      hRef = 0;
      memset(vData, 0, sizeof(uint32_t) * 9);
    }

    void Init(const CTxMatrix& b)
    {
      nVersion = b.nVersion;
      nHeight = b.nHeight;
      nType = b.nType;
      hRef = b.hRef;
      memcpy(vData, b.vData, sizeof(uint32_t) * 9);
    }

    unsigned int GetHeight()
    {
      return (nHeight);
    }

    unsigned int GetSize()
    {
      return (3);
    }

    unsigned int GetType()
    {
      return (nType);
    }

    void SetType(int nTypeIn)
    {
      nType = nTypeIn;
    }

    uint160 GetReferenceHash()
    {
      return (hRef);
    }

    unsigned int GetCell(int row, int col)
    {
      if (row < 0 || row >= 3 ||
          col < 0 || col >= 3)
        return (0);
      return (vData[row][col]);
    }

    void SetCell(int row, int col, unsigned int val)
    {
      if (row < 0 || row >= 3 ||
          col < 0 || col >= 3)
        return;
      vData[row][col] = val;
    }

    void AddCell(int row, int col, unsigned int val)
    {
      if (row < 0 || row >= 3 ||
          col < 0 || col >= 3)
        return;
      vData[row][col] += val;
    }

    void SubCell(int row, int col, unsigned int val)
    {
      if (row < 0 || row >= 3 ||
          col < 0 || col >= 3)
        return;
      vData[row][col] -= val;
    }

    string ToString()
    {
      char buf[1024];
      int row;
      int col;

      memset(buf, 0, sizeof(buf));
      sprintf(buf, "CTxMatrix(height %u", this->nHeight);
      for (row = 0; row < GetSize(); row++) {
        sprintf(buf+strlen(buf), " [#%d:", (row+1));
        for (col = 0; col < GetSize(); col++) {
          sprintf(buf+strlen(buf), " %x", GetCell(row, col));
        }
        strcat(buf, "]");
      }
      strcat(buf, ")");

      return string(buf);
    }

    const uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    /** Add in a block height and hash to the matrix. */
    void Append(int heightIn, uint256 hash);

    /** Retract a block hash & height from matrix. */
    void Retract(int heightIn, uint256 hash);
};


class ValidateMatrix : public CTxMatrix
{
  public:
    ValidateMatrix()
    {
      CTxMatrix::SetNull();
      CTxMatrix::SetType(M_VALIDATE);
    }

    ValidateMatrix(CTxMatrix& matrix)
    {
      CTxMatrix::SetNull();
      CTxMatrix::Init(matrix);
      CTxMatrix::SetType(M_VALIDATE);
    }

    IMPLEMENT_SERIALIZE
    (
      READWRITE(*(CTxMatrix*)this);
    )

    friend bool operator==(const ValidateMatrix& a, const ValidateMatrix& b)
    {
      return (
          ((CTxMatrix&) a) == ((CTxMatrix&) b)
          );
    }

    friend bool operator!=(const ValidateMatrix& a, const ValidateMatrix& b)
    {
      return !(a == b);
    }

    ValidateMatrix operator=(const ValidateMatrix &b)
    {
      Init(b);
      return (*this);
    }

    void Init(const ValidateMatrix& b)
    {
      CTxMatrix::Init(b);
    }

};



class CBlock;

bool BlockGenerateValidateMatrix(CIface *iface, ValidateMatrix *matrixIn, CTransaction& tx, int64& nReward);

bool BlockGenerateSpringMatrix(CIface *iface, CTxMatrix *matrixIn, CTransaction& tx, int64& nReward);

bool BlockAcceptValidateMatrix(ValidateMatrix *matrixIn, ValidateMatrix& matrix, CTransaction& tx, bool& fCheck);

bool BlockAcceptSpringMatrix(CIface *iface, CTxMatrix *matrixIn, CTransaction& tx, bool& fCheck);

void BlockRetractSpringMatrix(CIface *iface, CTxMatrix *matrixIn, CTransaction& tx, CBlockIndex *pindex);





#endif /* ndef __MATRIX_H__ */


