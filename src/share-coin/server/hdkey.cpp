
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

#include <string>
#include <vector>
#include <map>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <queue>
#include <vector>

#include "key.h"
#include "base58.h"
#include "uint256.h"
#include "util.h"
#include "mnemonic.h"

#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include "hdkey.h"


using namespace std;


void HDPrivKey::MakeNewKey(bool fCompressed)
{
  fCompressed = false;

  CKey::MakeNewKey(fCompressed);

  CSecret secret = GetSecret(fCompressed);
  cbuff seed(secret.begin(), secret.end());
  SetSeed(seed);
}

bool HDPrivKey::SetSeed(cbuff seed)
{
  char secret_hex[256];
  char m_chain[256];

  if (seed.size() != 32)
    return (false);

  string master_seed = HexStr(seed);
  strcpy(secret_hex, shecdsa_hd_seed((char *)master_seed.c_str(), m_chain));
  vchKey = ParseHex(secret_hex);

  CSecret secret(vchKey.begin(), vchKey.end());
  SetSecret(secret, false);
  vchChain = ParseHex(m_chain);


  return (true);
}

bool HDPrivKey::derive(HDPrivKey& privkey, cbuff pubkey, uint32_t i)
{
  char privkey_hex[256];
  char chain_hex[256];
  char pubkey_hex[256];
  char secret_hex[256];

  string hex = HexStr(vchChain);
  memset(chain_hex, 0, sizeof(chain_hex));
  strcpy(chain_hex, hex.c_str());

  strcpy(secret_hex, HexStr(vchKey).c_str());

  strcpy(pubkey_hex, HexStr(pubkey).c_str());

  strcpy(privkey_hex, shecdsa_hd_privkey(pubkey_hex,
        chain_hex, secret_hex, i));

  cbuff secret = ParseHex(privkey_hex); 
  privkey = HDPrivKey(*this, secret, ParseHex(chain_hex), i);

  return (true);
}

CPubKey HDPrivKey::GetPubKey() const
{
  char m_key[256];
  char m_chain[256];

  strcpy(m_key, HexStr(vchMasterKey).c_str());
  strcpy(m_chain, HexStr(vchMasterChain).c_str());
  string ret_hex = shecdsa_hd_priv2pub(m_key, m_chain, index);

  cbuff buff = ParseHex(ret_hex);
  CPubKey pubkey(buff);

  return (pubkey);
}

bool HDPubKey::derive(HDPubKey& pubkey, unsigned int i)
{
  char m_chain[256];
  char m_pubkey[256];
  char *pubkey_hex;

  if (!IsValid())
    return (false);

  strcpy(m_chain, HexStr(vchChain).c_str());
  strcpy(m_pubkey, HexStr(vchPubKey).c_str());
  pubkey_hex = shecdsa_hd_pubkey(m_pubkey, m_chain, i);

  pubkey = HDPubKey(ParseHex(pubkey_hex), ParseHex(m_chain), (depth + 1), i);
  if (!pubkey.IsValid())
    return (false);

  return (true);
}




