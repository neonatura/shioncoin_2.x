
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








class CAlias : public CIdent
{
  public:
    static const int ALIAS_NONE = 0;
    static const int ALIAS_COINADDR = TXREF_PUBADDR;

    CAlias()
    {
      SetNull();
    }

    CAlias(const CAlias& alias)
    {
      SetNull();
      Init(alias);
    }

    CAlias(const CIdent& ident)
    {
      SetNull();
      CIdent::Init(ident);
    }

    CAlias(std::string labelIn, const uint160& hashIn)
    {
      SetNull();

      /* assign title */
      SetLabel(labelIn);

      /* fill content layer */
      char hstr[256];
      memset(hstr, 0, sizeof(hstr));
      strncpy(hstr, hashIn.GetHex().c_str(), sizeof(hstr)-1);
      vAddr = cbuff(hstr, hstr + strlen(hstr));

      /* set attributes */
      SetType(ALIAS_COINADDR);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(*(CIdent *)this);
    )

    void FillReference(SHAlias *ref)
    {
      memset(ref, 0, sizeof(SHAlias));
      std::string strLabel = GetLabel();
      strncpy(ref->ref_name,
          (const char *)strLabel.c_str(), 
          MIN(strLabel.size(), sizeof(ref->ref_name)-1));
      if (vAddr.data()) {
        strncpy(ref->ref_hash,
            (const char *)vAddr.data(),
            MIN(vAddr.size(), sizeof(ref->ref_hash)-1));
      }
      ref->ref_expire = tExpire;
      ref->ref_type = nType;
    }

    friend bool operator==(const CAlias &a, const CAlias &b)
    {
      return (
          ((CIdent&) a) == ((CIdent&) b)
        );
    }
    void Init(const CAlias& alias)
    {
      CIdent::Init(alias);
    }

    CAlias operator=(const CAlias &b)
    {
      Init(b);
      return *this;
    }

    void SetNull()
    {
      CIdent::SetNull();
    }

    void NotifySharenet(int ifaceIndex)
    {
      CIface *iface = GetCoinByIndex(ifaceIndex);
      if (!iface || !iface->enabled) return;

      SHAlias ref;
      FillReference(&ref);
      shnet_inform(iface, TX_REFERENCE, &ref, sizeof(ref));
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

class CWalletTx;


alias_list *GetAliasTable(int ifaceIndex);

alias_list *GetAliasPendingTable(int ifaceIndex);


bool GetTxOfAlias(CIface *iface, const std::string strTitle, CTransaction& tx);

bool IsAliasTx(const CTransaction& tx);

bool IsLocalAlias(CIface *iface, const CTransaction& tx);

int64 GetAliasOpFee(CIface *iface, int nHeight); 

bool VerifyAlias(CTransaction& tx);


int init_alias_addr_tx(CIface *iface, const char *title, CCoinAddr& addr, CWalletTx& wtx);

int update_alias_addr_tx(CIface *iface, const char *title, CCoinAddr& addr, CWalletTx& wtx);


#endif /* ndef __ALIAS_H__ */

