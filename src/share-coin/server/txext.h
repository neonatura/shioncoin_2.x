
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

#ifndef __SERVER__TXEXT_H__
#define __SERVER__TXEXT_H__

#include "base58.h"
#include <vector>

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

inline std::string stringFromVch(const std::vector<unsigned char> &vch) 
{
  std::string res;
  std::vector<unsigned char>::const_iterator vi = vch.begin();
  while (vi != vch.end()) {
    res += (char) (*vi);
    vi++;
  }
  return res;
}


class CExtCore
{
  static const int PROTO_EXT_VERSION = 1;

  public:
    unsigned int nVersion;
    shtime_t tExpire;
    cbuff vchLabel;

    mutable bool fActive;

    CExtCore() {
      SetNull();
    }
    CExtCore(std::string labelIn) {
      SetNull();
      SetLabel(labelIn);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(this->nVersion);
      READWRITE(this->vchLabel);
      READWRITE(this->tExpire);
    )

    void SetNull()
    {
      nVersion = PROTO_EXT_VERSION;
      vchLabel.clear();
      tExpire = shtime_adj(shtime(), SHARE_DEFAULT_EXPIRE_TIME);
      fActive = false;
    }

    bool IsActive()
    {
      if (IsExpired())
        return (false);
      return (fActive);
    }

    void SetActive(bool active)
    {
      fActive = active;
    }

    time_t GetExpireTime()
    {
      return (shutime(tExpire));
    }

    void SetExpireTime(shtime_t tExpireIn)
    {
      tExpire = tExpireIn;
    }

    bool IsExpired()
    {
      if (tExpire == SHTIME_UNDEFINED)
        return (false);
      return (shtime_after(shtime(), tExpire));
    }

    void Init(const CExtCore& b)
    {
      nVersion = b.nVersion;
      vchLabel = b.vchLabel;
      tExpire = b.tExpire;
      fActive = b.fActive;  
    }

    friend bool operator==(const CExtCore &a, const CExtCore &b)
    {
      return (a.nVersion == b.nVersion &&
          a.tExpire == b.tExpire &&
          a.vchLabel == b.vchLabel
          );
    }

    CExtCore operator=(const CExtCore &b)
    {
      Init(b);
      return *this;
    }

    void SetLabel(std::string labelIn)
    {
      vchLabel = vchFromString(labelIn);
    }
    std::string GetLabel()
    {
      return (stringFromVch(vchLabel)); 
    }

    void HandleState(int mode)
    {
      switch (mode) {
        case OP_EXT_ACTIVATE:
          SetActive(true);
          break;
        case OP_EXT_REMOVE:
          SetActive(false);
          break;
      }
    } 
};


#include "alias.h"
#include "offer.h"
#include "certificate.h"
#include "asset.h"


#endif /* ndef __SERVER_TXEXT_H__ */




