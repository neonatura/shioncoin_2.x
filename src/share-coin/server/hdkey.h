
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

#ifndef __SERVER__HDKEY_H__
#define __SERVER__HDKEY_H__


#include "shcoind.h"


class HDPrivKey : public CKey
{
  public:
    unsigned int depth;
    unsigned int index;
    cbuff vchChain;
    cbuff vchMasterChain;
    cbuff vchKey;
    cbuff vchMasterKey;

    HDPrivKey()
    {
      SetNull();
    }

    HDPrivKey(const HDPrivKey& b)
    {
      SetNull();
      Init(b);
    }

    HDPrivKey(cbuff vchKeyIn)
    {
      SetNull();
      vchKey = vchKeyIn;

      CSecret secret(vchKey.begin(), vchKey.end());
      SetSecret(secret, false);

      fSet = true;
    }

    HDPrivKey(const HDPrivKey& parent, cbuff vchKeyIn, cbuff vchChainIn, int indexIn)
    {
      SetNull();
      vchKey = vchKeyIn;
      vchChain = vchChainIn;

      CSecret secret(vchKey.begin(), vchKey.end());
      SetSecret(secret, false);

      fSet = true;

      vchMasterKey = parent.vchKey;
      vchMasterChain = parent.vchChain;
//fprintf(stderr, "DEBUG: HDPrivKey alloc: vchMasterKey = '%s'\n", HexStr(vchMasterKey).c_str()); 

      depth = parent.depth + 1;
      index = indexIn;
    }
/*
    HDPrivKey(CKey key) : CKey(key)
    {
    
    }
*/

    void SetNull()
    {
      pkey = NULL;
      CKey::Reset();

      depth = 0;
      index = 0;

      vchKey.clear();
      vchChain.clear();

      vchMasterKey.clear();
      vchMasterKey.resize(32);

      vchMasterChain.clear();
      vchMasterChain.resize(32);
    }

    friend bool operator==(const HDPrivKey &a, const HDPrivKey &b) 
    {
      return (
          a.vchKey == b.vchKey &&
          a.vchChain == b.vchChain
          );
    }

    friend bool operator!=(const HDPrivKey &a, const HDPrivKey &b) {
      return ( 
          a.vchKey != b.vchKey ||
          a.vchChain != b.vchChain
          );
    }

    HDPrivKey operator=(const HDPrivKey &b)
    {
      Init(b);
      return *this;
    }

    void Init(const HDPrivKey& b)
    {
      depth = b.depth;
      index = b.index;
      vchKey = b.vchKey;
      vchMasterKey = b.vchMasterKey;
      vchChain = b.vchChain;
      vchMasterChain = b.vchMasterChain;
    }

    CPubKey GetPubKey() const;

    void MakeNewKey(bool fCompressed);

    bool SetSeed(cbuff seed);

    cbuff Raw() const
    {
      return (vchKey);
    }

    bool derive(HDPrivKey& privkey, cbuff pubkey, uint32_t i);

};

class HDPubKey : public CPubKey
{
  public:
  
    unsigned int depth;
    unsigned int index;
    cbuff vchChain;

    HDPubKey()
    {
      SetNull();
    }

    HDPubKey(const HDPubKey& b)
    {
      SetNull();
      Init(b);
    }

    HDPubKey(cbuff vchPubKeyIn, cbuff vchChainIn, int depthIn, int indexIn)
    {
      SetNull();
      
      vchPubKey = vchPubKeyIn;
      vchChain = vchChainIn;
      depth = depthIn;
      index = indexIn;
    }

/*
    HDPubKey(CPubKey key) : CPubKey(key)
    {
    
    }
*/

    void SetNull()
    {

      depth = 0;
      index = 0;

      vchPubKey.clear();

      vchChain.clear();
      vchChain.resize(32);
    }

    friend bool operator==(const HDPubKey &a, const HDPubKey &b) 
    {
      return (
          a.vchPubKey == b.vchPubKey &&
          a.vchChain == b.vchChain
          );
    }

    friend bool operator!=(const HDPubKey &a, const HDPubKey &b) {
      return ( 
          a.vchPubKey != b.vchPubKey ||
          a.vchChain != b.vchChain
          );
    }

    HDPubKey operator=(const HDPubKey &b)
    {
      Init(b);
      return *this;
    }

    void Init(const HDPubKey& b)
    {
      vchPubKey = b.vchPubKey;
      depth = b.depth;
      index = b.index;
      vchChain = b.vchChain;
    }

    bool derive(HDPubKey& pubkey, unsigned int i);

};


#endif /* ndef __SERVER__HDKEY_H__ */

