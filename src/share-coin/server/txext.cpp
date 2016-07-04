
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

#include "share.h"
#include "shcoind.h"
#include "wallet.h"

using namespace std;
using namespace boost;



/**
 * Apply a signature that is unique for the local machine and specified coin address.
 */
bool CExtCore::SignOrigin(int ifaceIndex, CCoinAddr& addr)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (false);

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    return error(SHERR_INVAL, "Address does not refer to key");

  CKey key;
  if (!wallet->GetKey(keyID, key))
    return error(SHERR_INVAL, "Private key not available");

  shpeer_t *peer = sharenet_peer();
  shkey_t s_key;
  memcpy(&s_key, shpeer_kpriv(peer), sizeof(s_key));
  unsigned char *raw = (unsigned char *)&s_key;
  cbuff vchPeer(raw, raw + sizeof(shkey_t));
  uint256 hashPeer = uint256(vchPeer);

  vector<unsigned char> vchSig;
  if (!key.SignCompact(hashPeer, vchSig))
    return error(SHERR_INVAL, "Sign failed");

  origin = vchSig;
  return (true);
}

/**
 * Verify whether a particular extended transaction originated from the local machine.
 * @note addr The original address used to sign the extended transaction.
 */
bool CExtCore::VerifyOrigin(int ifaceIndex, CCoinAddr& addr)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (false);

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    return error(SHERR_INVAL, "Address does not refer to key");

  shpeer_t *peer = sharenet_peer();
  shkey_t s_key;
  memcpy(&s_key, shpeer_kpriv(peer), sizeof(s_key));
  unsigned char *raw = (unsigned char *)&s_key;
  cbuff vchPeer(raw, raw + sizeof(shkey_t));
  uint256 hashPeer = uint256(vchPeer);

  CKey key;
  if (!key.SetCompactSignature(hashPeer, origin))
    return error(SHERR_INVAL, "Sign failed");

  return (key.GetPubKey().GetID() == keyID);
}


/**
 * Obtains a 256-bit hash representation of the origin signature.
 */
const uint256 CExtCore::GetOrigin()
{
  return (Hash(origin.begin(), origin.end()));
}


