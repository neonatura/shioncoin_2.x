


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

#ifndef __SHLIB_H__
#define __SHLIB_H__

#include "share.h"
#include "serialize.h"


typedef shcert_t SHCert;
typedef shent_t SHCertEnt;
typedef shlic_t SHLicense;
typedef shref_t SHAlias;
typedef shasset_t SHAsset;

class SHPeer
{
  public:
    shpeer_t peer;

    SHPeer()
    {
      SetNull();
    }
    SHPeer(shpeer_t *peerIn)
    {
      memcpy(&peer, peerIn, sizeof(peer));
    }
    IMPLEMENT_SERIALIZE (
      READWRITE(FLATDATA(peer));
    )
    void SetNull()
    {
      memset(&peer, 0, sizeof(peer));
    }
};

class SHSig
{
  public:
    shsig_t sig;

    SHSig()
    {
      SetNull();
    }
    SHSig(shsig_t *sigIn)
    {
      memcpy(&sig, sigIn, sizeof(sig));
    }
    IMPLEMENT_SERIALIZE (
      READWRITE(FLATDATA(sig));
    )
    void SetNull()
    {
      memset(&sig, 0, sizeof(sig));
    }
};

inline std::vector<unsigned char> vchFromString(const std::string &str) {
  unsigned char *strbeg = (unsigned char*) str.c_str();
  return std::vector<unsigned char>(strbeg, strbeg + str.size());
}   

#endif /* ndef __SHLIB_H__ */
