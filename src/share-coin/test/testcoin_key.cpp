
#include "test_shcoind.h"
#include <string>
#include <vector>

#include "key.h"
#include "base58.h"
#include "uint256.h"
#include "util.h"
#include "mnemonic.h"





#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <queue>
#include <vector>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>


#include "hdkey.h"






using namespace std;




#ifdef __cplusplus
extern "C" {
#endif



static const string strSecret3     ("6bMUHP9bBRR5dQcnrAzyoB3nsYTK69LC5LEgzUBiPz9Fqwe4vry");
static const string strSecret3C    ("RgdMRJkurzmHRhEyN38ugoMKU5q8qhmht7uRWezHiTDSWyVT7kMu");
static const string strSecret4     ("6bRCArv9Htu4oLMdTsHhyE4jKHUYo46HKSbHiBRT8itJWQuyN34");
static const string strSecret4C    ("RgunJXKZba4omWS3waxjqAfTmhibLGeK2PxLkkzvM5sSGYZA3piX");

static const CCoinAddr addr3 ("GLduwFUxWvKSotSgqhNwKFcU58wQjPwtfV");
static const CCoinAddr addr4 ("GSFFyXXYHNTtDk8W8M4LcZMcyG4fJuqjoo");
static const CCoinAddr addr3C ("GczsCEv6UXUByQTmsSnFoLWG3KWD7yV9zp");
static const CCoinAddr addr4C ("GJgcXeqegX3BW2AihD6q1gbetgYqpAkrxD");


static const string strAddressBad("1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF");

_TEST(coin_key)
{
  CCoinSecret bsecret3, bsecret4;
  CCoinSecret bsecret3C, bsecret4C;
  CCoinSecret baddress1;

  _TRUE( bsecret3.SetString (strSecret3) );
  _TRUE( bsecret4.SetString (strSecret4) );
  _TRUE( bsecret3C.SetString(strSecret3C));
  _TRUE( bsecret4C.SetString(strSecret4C));
  _TRUE(!baddress1.SetString(strAddressBad));

  bool fCompressed;
  CSecret secret3  = bsecret3.GetSecret (fCompressed);
  _TRUE(fCompressed == false);
  CSecret secret4  = bsecret4.GetSecret (fCompressed);
  _TRUE(fCompressed == false);
  bsecret3C.SetSecret(secret3, true);
//fprintf(stderr, "DEBUG: bsecret3C '%s'\n", bsecret3C.ToString().c_str());
  bsecret4C.SetSecret(secret4, true);
//fprintf(stderr, "DEBUG: bsecret4C '%s'\n", bsecret4C.ToString().c_str());
  CSecret secret3C = bsecret3C.GetSecret(fCompressed);
  _TRUE(fCompressed == true);
  CSecret secret4C = bsecret4C.GetSecret(fCompressed);
  _TRUE(fCompressed == true);
  _TRUE(secret3 == secret3C);
  _TRUE(secret4 == secret4C);
#if 0
  CSecret secret1  = bsecret1.GetSecret (fCompressed);
  _TRUE(fCompressed == false);
  CSecret secret2  = bsecret2.GetSecret (fCompressed);
  _TRUE(fCompressed == false);
  CSecret secret1C = bsecret1C.GetSecret(fCompressed);
  _TRUE(fCompressed == true);
  CSecret secret2C = bsecret2C.GetSecret(fCompressed);
  _TRUE(fCompressed == true);

  _TRUE(secret1 == secret1C);
  _TRUE(secret2 == secret2C);
#endif

#if 0
  CKey key1, key2, key1C, key2C;
  key1.SetSecret(secret1, false);
  key2.SetSecret(secret2, false);
  key1C.SetSecret(secret1, true);
  key2C.SetSecret(secret2, true);
  _TRUE(addr1.Get()  == CTxDestination(key1.GetPubKey().GetID()));
  _TRUE(addr2.Get()  == CTxDestination(key2.GetPubKey().GetID()));
  _TRUE(addr1C.Get() == CTxDestination(key1C.GetPubKey().GetID()));
  _TRUE(addr2C.Get() == CTxDestination(key2C.GetPubKey().GetID()));
#endif
  CKey key3, key4;
  key3.SetSecret(secret3, false);
  key4.SetSecret(secret4, false);
  CKey key3C, key4C;
  key3C.SetSecret(secret3, true);
  key4C.SetSecret(secret4, true);

  _TRUE(addr3.Get()  == CTxDestination(key3.GetPubKey().GetID()));
  _TRUE(addr4.Get()  == CTxDestination(key4.GetPubKey().GetID()));
  _TRUE(addr3C.Get() == CTxDestination(key3C.GetPubKey().GetID()));
  _TRUE(addr4C.Get() == CTxDestination(key4C.GetPubKey().GetID()));


  for (int n=0; n<16; n++)
  {
    string strMsg = strprintf("Very secret message %i: 11", n);
    uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

    // normal signatures


    vector<unsigned char> sign3, sign4;
    _TRUE(key3.Sign (hashMsg, sign3));
    _TRUE(key4.Sign (hashMsg, sign4));
    vector<unsigned char> sign3C, sign4C;
    _TRUE(key3C.Sign(hashMsg, sign3C));
    _TRUE(key4C.Sign(hashMsg, sign4C));
#if 0
    vector<unsigned char> sign1, sign2, sign1C, sign2C;
    _TRUE(key1.Sign (hashMsg, sign1));
    _TRUE(key2.Sign (hashMsg, sign2));
    _TRUE(key1C.Sign(hashMsg, sign1C));
    _TRUE(key2C.Sign(hashMsg, sign2C));
#endif

    _TRUE( key3.Verify(hashMsg, sign3));
    _TRUE(!key3.Verify(hashMsg, sign4));
    _TRUE( key3.Verify(hashMsg, sign3C));
    _TRUE(!key3.Verify(hashMsg, sign4C));
#if 0
    _TRUE( key1.Verify(hashMsg, sign1));
    _TRUE(!key1.Verify(hashMsg, sign2));
    _TRUE( key1.Verify(hashMsg, sign1C));
    _TRUE(!key1.Verify(hashMsg, sign2C));
#endif

    _TRUE(!key4.Verify(hashMsg, sign3));
    _TRUE( key4.Verify(hashMsg, sign4));
    _TRUE(!key4.Verify(hashMsg, sign3C));
    _TRUE( key4.Verify(hashMsg, sign4C));

    _TRUE( key3C.Verify(hashMsg, sign3));
    _TRUE(!key3C.Verify(hashMsg, sign4));
    _TRUE( key3C.Verify(hashMsg, sign3C));
    _TRUE(!key3C.Verify(hashMsg, sign4C));

    _TRUE(!key4C.Verify(hashMsg, sign3));
    _TRUE( key4C.Verify(hashMsg, sign4));
    _TRUE(!key4C.Verify(hashMsg, sign3C));
    _TRUE( key4C.Verify(hashMsg, sign4C));
#if 0
    _TRUE(!key2.Verify(hashMsg, sign1));
    _TRUE( key2.Verify(hashMsg, sign2));
    _TRUE(!key2.Verify(hashMsg, sign1C));
    _TRUE( key2.Verify(hashMsg, sign2C));

    _TRUE( key1C.Verify(hashMsg, sign1));
    _TRUE(!key1C.Verify(hashMsg, sign2));
    _TRUE( key1C.Verify(hashMsg, sign1C));
    _TRUE(!key1C.Verify(hashMsg, sign2C));

    _TRUE(!key2C.Verify(hashMsg, sign1));
    _TRUE( key2C.Verify(hashMsg, sign2));
    _TRUE(!key2C.Verify(hashMsg, sign1C));
    _TRUE( key2C.Verify(hashMsg, sign2C));
#endif

    // compact signatures (with key recovery)

    vector<unsigned char> csign3, csign4;
    _TRUE(key3.SignCompact (hashMsg, csign3));
    _TRUE(key4.SignCompact (hashMsg, csign4));
    vector<unsigned char> csign3C, csign4C;
    _TRUE(key3C.SignCompact(hashMsg, csign3C));
    _TRUE(key4C.SignCompact(hashMsg, csign4C));

#if 0
    vector<unsigned char> csign1, csign2, csign1C, csign2C;

    _TRUE(key1.SignCompact (hashMsg, csign1));
    _TRUE(key2.SignCompact (hashMsg, csign2));
    _TRUE(key1C.SignCompact(hashMsg, csign1C));
    _TRUE(key2C.SignCompact(hashMsg, csign2C));
#endif

    CKey rkey3, rkey4;
    CKey rkey3C, rkey4C;
    _TRUE(rkey3.SetCompactSignature (hashMsg, csign3));
    _TRUE(rkey4.SetCompactSignature (hashMsg, csign4));
    _TRUE(rkey3C.SetCompactSignature(hashMsg, csign3C));
    _TRUE(rkey4C.SetCompactSignature(hashMsg, csign4C));

    _TRUE(rkey3.GetPubKey()  == key3.GetPubKey());
    _TRUE(rkey4.GetPubKey()  == key4.GetPubKey());
    _TRUE(rkey3C.GetPubKey() == key3C.GetPubKey());
    _TRUE(rkey4C.GetPubKey() == key4C.GetPubKey());
#if 0
    CKey rkey1, rkey2, rkey1C, rkey2C;

    _TRUE(rkey1.SetCompactSignature (hashMsg, csign1));
    _TRUE(rkey2.SetCompactSignature (hashMsg, csign2));
    _TRUE(rkey1C.SetCompactSignature(hashMsg, csign1C));
    _TRUE(rkey2C.SetCompactSignature(hashMsg, csign2C));

    _TRUE(rkey1.GetPubKey()  == key1.GetPubKey());
    _TRUE(rkey2.GetPubKey()  == key2.GetPubKey());
    _TRUE(rkey1C.GetPubKey() == key1C.GetPubKey());
    _TRUE(rkey2C.GetPubKey() == key2C.GetPubKey());
#endif
  }

}



_TEST(coin_key_phrase)
{
  bool fCompressed = false;

  /* generate new coin address key */
  CKey key;
  key.MakeNewKey(false);
  CCoinSecret secret(key.GetSecret(fCompressed), false); 
  _TRUE(secret.IsValid() == true);

  /* convert to a 'phrase' */
  string phrase = EncodeMnemonicSecret(secret);

  CCoinSecret cmp_secret;
  bool ret = DecodeMnemonicSecret(phrase, cmp_secret);
  _TRUE(ret == true);
  _TRUE(cmp_secret.IsValid() == true);
  
  _TRUE(cmp_secret.GetSecret(fCompressed) == secret.GetSecret(fCompressed));
}



#ifdef __cplusplus
}
#endif




#if 0

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
fprintf(stderr, "DEBUG: HDPrivKey alloc: vchMasterKey = '%s'\n", HexStr(vchMasterKey).c_str()); 

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
fprintf(stderr, "DEBUG: secret_hex <%d bytes>: '%s'\n", strlen(secret_hex), secret_hex);

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
fprintf(stderr, "DEBUG: DHPrivKey:derive: chain hex '%s'\n", chain_hex);

  strcpy(secret_hex, HexStr(vchKey).c_str());
fprintf(stderr, "DEBUG: DHPrivKey:derive: secret hex '%s'\n", secret_hex);

  strcpy(pubkey_hex, HexStr(pubkey).c_str());
fprintf(stderr, "DEBUG: DHPrivKey:derive: pubkey hex '%s'\n", pubkey_hex);

  strcpy(privkey_hex, shecdsa_hd_privkey(pubkey_hex,
        chain_hex, secret_hex, i));
fprintf(stderr, "DEBUG: DHPrivKey:derive: privkey_hex '%s'\n", privkey_hex);

  cbuff secret = ParseHex(privkey_hex); 
  privkey = HDPrivKey(*this, secret, ParseHex(chain_hex), i);


}

CPubKey HDPrivKey::GetPubKey() const
{
  char m_key[256];
  char m_chain[256];

  strcpy(m_key, HexStr(vchMasterKey).c_str());
  strcpy(m_chain, HexStr(vchMasterChain).c_str());
fprintf(stderr, "DEBUG: GetPubKey: m_key '%s'\n", m_key);
fprintf(stderr, "DEBUG: GetPubKey: m_chain '%s'\n", m_chain);
  string ret_hex = shecdsa_hd_priv2pub(m_key, m_chain, index);
fprintf(stderr, "DEBUG: GetPubKey: ret_hex '%s'\n", ret_hex.c_str());

  cbuff buff = ParseHex(ret_hex);
  CPubKey pubkey(buff);

  return (pubkey);
}



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



#endif





extern CCoinAddr GetAccountAddress(CWallet *wallet, string strAccount, bool bForceNew);
extern CWallet *GetWallet(CIface *iface);

#ifdef __cplusplus
extern "C" {
#endif

  _TEST(coin_hdkey)
  {
    CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
    CWallet *wallet = GetWallet(iface);
    string strAccount("");
    char master_pubkey[256];
    char buf[32];
    int idx;

    cbuff seed;
    {
      bool fCompressed;
      CKey seed_key;
      seed_key.MakeNewKey(false);
      CSecret seed_secret = seed_key.GetSecret(fCompressed);
      seed = cbuff(seed_secret.begin(), seed_secret.end());
    }

    HDPrivKey privkey;
    privkey.SetSeed(seed);
fprintf(stderr, "DEBUG: TEST: master private key '%s'\n", HexStr(privkey.vchKey).c_str()); 

    string master_secret = HexStr(privkey.vchKey);
    strcpy(master_pubkey, shecdsa_hd_point_hex((char *)master_secret.c_str()));
fprintf(stderr, "DEBUG: TEST: master public key '%s'\n", master_pubkey);

    CPubKey m_pubkey(ParseHex(master_pubkey));
    HDPubKey key(ParseHex(master_pubkey),
        privkey.vchChain, privkey.depth, privkey.index);
    fprintf(stderr, "DEBUG: TEST: remastered public key '%s'\n", HexStr(key.Raw()).c_str()); 
    _TRUE(key.IsValid() == true);

    /* extract child pub key */
    idx = 1;
    HDPubKey t_pubkey;
    _TRUE(key.derive(t_pubkey, idx) == true);
    _TRUE(t_pubkey.IsValid() == true);
fprintf(stderr, "DEBUG: TEST: derived public key '%s'\n", HexStr(t_pubkey.Raw()).c_str());

#if 0
  CCoinAddr addr;
  addr.Set(t_pubkey.GetID());
fprintf(stderr, "DEBUG: dervive/1/pubkey pubkey hex '%s' [idx %d]\n", t_pubkey.GetID().ToString().c_str(), idx);
fprintf(stderr, "DEBUG: derive/1/pubkey coin addr '%s'\n", addr.ToString().c_str());
#endif

/* -- */


  /* extract child priv key */
  HDPrivKey t_privkey;
  bool ret = privkey.derive(t_privkey, key.Raw(), idx);
  _TRUE(ret == true);
fprintf(stderr, "DEBUG: TEST: derived private key '%s'\n", HexStr(t_privkey.vchKey).c_str());

/* -- */

  CPubKey t_pubkey2 = t_privkey.GetPubKey();
fprintf(stderr, "DEBUG: TEST: derived public-from-private key '%s'\n", HexStr(t_pubkey2.Raw()).c_str());
//  addr.Set(t_pubkey2.GetID());

  _TRUE(t_pubkey2.Raw() == t_pubkey.Raw());

}



#ifdef __cplusplus
}
#endif



