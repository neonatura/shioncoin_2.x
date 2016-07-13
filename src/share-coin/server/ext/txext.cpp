
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



#if 0

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
#endif


std::string CExtCore::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CExtCore::ToValue()
{
  Object obj;
  char tbuf[256];

  obj.push_back(Pair("version", (int64_t)nVersion));

  if (vchLabel.size() != 0)
    obj.push_back(Pair("label", stringFromVch(vchLabel)));

  sprintf(tbuf, "%-20.20s", shctime(tExpire));
  obj.push_back(Pair("expire", string(tbuf)));

  obj.push_back(Pair("signature", signature.GetHash().GetHex()));

  return (obj);
}


bool CSign::SignContext(unsigned char *data, size_t data_len)
{
  shkey_t *priv_key;
  shkey_t *pub_key;
  shkey_t *kpriv;
  char pub_key_hex[1024];
  char priv_key_hex[1024];
  char sig_r[1024];
  char sig_s[1024];

  if (!data || !data_len)
    return (error(SHERR_INVAL, "CSign::SignContext: no context specified."));

  if (nAlg & ALG_ECDSA)
    return error(SHERR_INVAL, "CSign:SignAddress: address signature is already signed.");

  nAlg = ALG_ECDSA; 

  /* generate private key */
  kpriv = shpeer_kpriv(ashpeer());
  memset(priv_key_hex, 0, sizeof(priv_key_hex));
  strncpy(priv_key_hex, shkey_hex(kpriv), sizeof(priv_key_hex)-1);
  priv_key = shecdsa_key_priv(priv_key_hex);
  if (!priv_key) {
    return error(SHERR_INVAL, "CSign::SignContenxt: error generating private key.");
  }

  /* generate public key */
  pub_key = shecdsa_key_pub(priv_key);
  if (!pub_key) {
    shkey_free(&priv_key);
    return error(SHERR_INVAL, "CSign::SignContenxt: error generating public key.");
  }

  /* stow pub-key into sign object */
  memset(pub_key_hex, 0, sizeof(pub_key_hex));
  strncpy(pub_key_hex, shkey_hex(pub_key), sizeof(pub_key_hex)-1);
  string strPubKey(pub_key_hex);
  vPubKey = vchFromString(strPubKey); 

  /* sign content */
  shecdsa_sign(priv_key, sig_r, sig_s, data, data_len);

  vSig.push_back(vchFromString(string(sig_r)));
  vSig.push_back(vchFromString(string(sig_s)));
  
  shkey_free(&priv_key);
  shkey_free(&pub_key);

  return (true);
}

bool CSign::VerifyContext(unsigned char *data, size_t data_len)
{
  shkey_t *pub_key;
  char sig_r[256];
  char sig_s[256];
  char pub_key_hex[256];
  int err;

  if (!(nAlg & ALG_ECDSA))
    return error(SHERR_INVAL, "CSign:VerifyContext: empty ecdsa signature.");

  if (vPubKey.size() == 0) {
    return (error(SHERR_INVAL, "CSign::Verify: no public key established."));
  }

  /* verify content */
  memset(pub_key_hex, 0, sizeof(pub_key_hex));
  strncpy(pub_key_hex, stringFromVch(vPubKey).c_str(), sizeof(pub_key_hex)-1);
  pub_key = shecdsa_key(pub_key_hex);

  strncpy(sig_r, stringFromVch(vSig[0]).c_str(), sizeof(sig_r)-1);
  strncpy(sig_s, stringFromVch(vSig[1]).c_str(), sizeof(sig_s)-1);
  err = shecdsa_verify(pub_key, sig_r, sig_s, data, data_len);
  shkey_free(&pub_key);
  if (err)
    return (error(err, "CSign::Verify"));

  return (true);
}

bool CSign::SignAddress(int ifaceIndex, CCoinAddr& addr, unsigned char *data, size_t data_len)
{

  if (nAlg & ALG_U160)
    return error(SHERR_INVAL, "CSign:SignAddress: address signature is already signed.");

  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (false);

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    return error(SHERR_INVAL, "Address does not refer to key");

  CKey key;
  if (!wallet->GetKey(keyID, key))
    return error(SHERR_INVAL, "Private key not available");

  cbuff vchData(data, data + data_len);
  uint256 hashData = uint256(vchData);

  vector<unsigned char> vchSig;
  if (!key.SignCompact(hashData, vchSig))
    return error(SHERR_INVAL, "Sign failed");

  nAlg |= ALG_U160;
  vAddrKey = vchSig;

  return (true);
}

bool CSign::VerifyAddress(CCoinAddr& addr, unsigned char *data, size_t data_len)
{

  if (!(nAlg & ALG_U160))
    return error(SHERR_INVAL, "CSign:VerifyAddress: empty address signature.");

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    return error(SHERR_INVAL, "Address does not refer to key");

  cbuff vchData(data, data + data_len);
  uint256 hashData = uint256(vchData);

  CKey key;
  if (!key.SetCompactSignature(hashData, vAddrKey))
    return error(SHERR_INVAL, "Sign failed");

  return (key.GetPubKey().GetID() == keyID);
}

bool CSign::SignOrigin(int ifaceIndex, CCoinAddr& addr)
{

  shpeer_t *peer = sharenet_peer();
  shkey_t s_key;
  memcpy(&s_key, shpeer_kpriv(peer), sizeof(s_key));
  unsigned char *raw = (unsigned char *)&s_key;

  return (SignAddress(ifaceIndex, addr, raw, sizeof(shkey_t)));
}

bool CSign::VerifyOrigin(CCoinAddr& addr)
{
  shpeer_t *peer = sharenet_peer();
  shkey_t s_key;

  memcpy(&s_key, shpeer_kpriv(peer), sizeof(s_key));
  unsigned char *raw = (unsigned char *)&s_key;
  
  return (VerifyAddress(addr, raw, sizeof(shkey_t)));
}

bool CSign::SignContext(uint160 hash)
{
  shkey_t *kHash;
  kHash = hash.GetKey();
  return (SignContext((unsigned char *)kHash, sizeof(shkey_t)));
}


bool CSign::VerifyContext(uint160 hash)
{
  shkey_t *kHash;
  kHash = hash.GetKey();
  return (VerifyContext((unsigned char *)kHash, sizeof(shkey_t)));
}

bool CSign::Sign(int ifaceIndex, CCoinAddr& addr, unsigned char *data, size_t data_len)
{
  bool ret;

  ret = SignContext(data, data_len);
  if (!ret)
    return false;

  ret = SignAddress(ifaceIndex, addr, data, data_len);
  if (!ret)
    return false;
 
  return true;
}

bool CSign::Verify(CCoinAddr& addr, unsigned char *data, size_t data_len)
{
  bool ret;

  ret = VerifyContext(data, data_len);
  if (!ret)
    return false;

  ret = VerifyAddress(addr, data, data_len);
  if (!ret)
    return (false);

  return (true);
}

std::string CSign::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CSign::ToValue()
{
  Object obj;
  return (obj);
}


