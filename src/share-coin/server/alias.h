
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
    uint32_t nType;
    shtime_t expire;
    uint160 hash;

  public:
    static const int ALIAS_NONE = 0;
    static const int ALIAS_COINADDR = 1;
//    static const int ALIAS_CERT = 2;


    CAlias()
    {
      SetNull();
    }

    CAlias(const char *labelIn, uint160 hashIn)
    {
      label = vchFromString(labelIn); 
      hash = hashIn;
      nType = ALIAS_COINADDR;
      expire = shtime_adj(shtime(), SHARE_DEFAULT_EXPIRE_TIME);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(nVersion);
      READWRITE(nType);
      READWRITE(FLATDATA(expire));
      READWRITE(hash);
      READWRITE(label);
    )

    friend bool operator==(const CAlias &a, const CAlias &b)
    {
      return (a.nType == b.nType &&
          arrcasecmp(a.label, b.label));
    }

    CAlias operator=(const CAlias &b)
    {
      nVersion = b.nVersion;
      nType = b.nType;
      expire = b.expire;
      hash = b.hash;
      label = b.label;
    }

    void SetNull()
    {
      CAliasIndex::SetNull();
      nVersion = PROTO_ALIAS_VERSION;
      nType = ALIAS_NONE;
      expire = SHTIME_UNDEFINED;
      hash.SetHex("0x0");
    }
    time_t GetExpireTime()
    {
      return (shutime(expire));
    }
    bool isExpired()
    {
      return (shtime_after(shtime(), expire));
    }
    uint160 GetHash()
    {
      return (Hash160(label));
    }
    uint160 GetAliasHash()
    {
      return (hash);
    }

};



#endif /* ndef __ALIAS_H__ */

