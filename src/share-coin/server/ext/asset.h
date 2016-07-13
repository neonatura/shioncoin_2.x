
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

#ifndef __ASSET_H__
#define __ASSET_H__

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
using namespace std;
using namespace json_spirit;


typedef map<uint160, uint256> asset_list;


class CAsset : public CExtCore
{

  protected:
    uint160 hCert;
    CSign sigCert;
    cbuff vHash;

    /* reserved */
    cbuff vUrl;
    cbuff vLocale;

  public:
    CAsset()
    {
      SetNull();
    }

    CAsset(const CAsset& assetIn)
    {
      SetNull();
      Init(assetIn);
    }

    CAsset(string labelIn, string strHashIn)
    {
      SetNull();
      SetLabel(labelIn);
      SetAssetHash(strHashIn);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(*(CExtCore *)this);
      READWRITE(hCert);
      READWRITE(sigCert);
      READWRITE(vHash);

      /* reserved */
      READWRITE(vUrl);
      READWRITE(vLocale);
    )

    void SetNull()
    {
      CExtCore::SetNull();

      hCert = 0;
      sigCert.SetNull();
      vHash.clear();
      vUrl.clear();
      vLocale.clear();
    }

    void Init(const CAsset& assetIn)
    {
      CExtCore::Init(assetIn);
      hCert = assetIn.hCert;
      sigCert = assetIn.sigCert;
      vHash = assetIn.vHash;
    }

    friend bool operator==(const CAsset &a, const CAsset &b)
    {
      return (
        ((CExtCore&) a) == ((CExtCore&) b) &&
        a.hCert == b.hCert &&
        a.sigCert == b.sigCert &&
        a.vHash == b.vHash 
      );
    }

    CAsset operator=(const CAsset &b)
    {
      Init(b);
      return (*this);
    }


    bool Sign(uint160 sigCertIn);

    bool VerifySignature();

    void SetAssetHash(string strHash)
    {
      vHash = vchFromString(strHash); 
    }

    string GetAssetHash()
    {
      return (stringFromVch(vHash));
    }

    const uint160 GetHash()
    {
      uint256 hashOut = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hashOut;
      cbuff rawbuf(raw, raw + sizeof(hashOut));
      return Hash160(rawbuf);
    }

    std::string ToString();

    Object ToValue();

};

bool VerifyAsset(CTransaction& tx);


int init_asset_tx(CIface *iface, string strAccount, string strTitle, string strHash, CWalletTx& wtx);

int update_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, string strTitle, string strHash, CWalletTx& wtx);

int activate_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, const uint160& hashCert, CWalletTx& wtx);

int remove_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, CWalletTx& wtx);




#endif /* ndef __ASSET_H__ */


