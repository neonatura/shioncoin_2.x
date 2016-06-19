
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

#ifndef __ALIAS_H__
#define __ALIAS_H__

#include "base58.h"

typedef map<std::string, uint256> alias_list;

extern alias_list mapAliases[MAX_COIN_IFACE];

inline bool arrcasecmp(cbuff v1, cbuff v2)
{
  int idx;

  if (v1.size() != v2.size())
    return (false);

  size_t len = v1.size();
  unsigned char *p1 = &*v1.begin();
  unsigned char *p2 = &*v2.begin();
  for (idx = 0; idx < len; idx++) {
    if (tolower(p1[idx]) != tolower(p2[idx]))
      return (false);
  }

  return (true);
}


class CAliasIndex 
{
  public:
    cbuff label;

    mutable uint256 hashTx;
    mutable bool fActive;

    CAliasIndex() {
        SetNull();
    }

    void SetNull()
    {
      label.clear();
      fActive = false;
    }

    bool isActive()
    {
      return (fActive);
    }
    void setActive(bool active)
    {
      fActive = active;
    }
};


class CAlias : public CAliasIndex
{
  static const int PROTO_ALIAS_VERSION = 1;

  protected:
    uint32_t nVersion;
    SHAlias ref;

    mutable uint160 hash160;

  public:
    static const int ALIAS_NONE = 0;
    static const int ALIAS_COINADDR = TXREF_PUBADDR;

    static const int LEVEL_LABEL = 1;

    CAlias()
    {
      SetNull();
    }

    CAlias(const char *labelIn, uint160 hashIn)
    {
      SetNull();

      label = vchFromString(labelIn); 
      hash160 = hashIn;

      ref.ref_type = ALIAS_COINADDR;
      ref.ref_level = LEVEL_LABEL;
      strncpy(ref.ref_name, labelIn, sizeof(ref.ref_name)-1);
      strncpy(ref.ref_hash, hashIn.ToString().c_str(), sizeof(ref.ref_hash)-1);
      ref.ref_expire = shtime_adj(shtime(), SHARE_DEFAULT_EXPIRE_TIME);
      memcpy(&ref.ref_peer, ashpeer(), sizeof(ref.ref_peer));
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(nVersion);
      READWRITE(FLATDATA(ref));
    )

    friend bool operator==(const CAlias &a, const CAlias &b)
    {
      return (a.ref.ref_type == b.ref.ref_type &&
          arrcasecmp(a.label, b.label));
    }

    CAlias operator=(const CAlias &b)
    {
      nVersion = b.nVersion;
      memcpy(&ref, &b.ref, sizeof(ref));
      label = b.label;
      hash160 = b.hash160;
      fActive = b.fActive;
    }

    void SetNull()
    {
      CAliasIndex::SetNull();
      nVersion = PROTO_ALIAS_VERSION;
      memset(&ref, 0, sizeof(ref));
      hash160.SetHex("0x0");
    }

    time_t GetExpireTime()
    {
      return (shutime(ref.ref_expire));
    }
    bool isExpired()
    {
      return (shtime_after(shtime(), ref.ref_expire));
    }
    uint160 GetHash()
    {
      unsigned char *data = (unsigned char *)&ref;
      cbuff buff(data, data + sizeof(ref));
      return (Hash160(buff));
    }
    uint160 GetAliasHash160()
    {
      return (hash160);
    }

};


alias_list *GetAliasTable(int ifaceIndex);

int init_alias_addr_tx(CIface *iface, const char *title, uint160 ref_hash, CWalletTx& wtx);

#endif /* ndef __ALIAS_H__ */

