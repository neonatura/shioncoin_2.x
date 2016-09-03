
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

#ifndef __EXEC_H__
#define __EXEC_H__




class CExec : public CCert
{
  public:
    static const double DEFAULT_EXEC_LIFESPAN = MAX_SHARE_SESSION_TIME;

    mutable int indexPool;

    CExec()
    {
      SetNull();
    }

    CExec(const CCert& certIn)
    {
      SetNull();
      CCert::Init(certIn);
    }

    CExec(const CExec& execIn)
    {
      SetNull();
      Init(execIn);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(*(CCert *)this);
    )

    void SetNull()
    {
      CCert::SetNull();
    }

    void Init(const CExec& execIn)
    {
      CCert::Init(execIn);
      indexPool = execIn.indexPool;
    }

    friend bool operator==(const CExec &a, const CExec &b)
    {
      return (
        ((CCert&) a) == ((CCert&) b)
      );
    }

    CExec operator=(const CExec &b)
    {
      Init(b);
      return (*this);
    }

#if 0
    bool Sign(uint160 sigCertIn);
    bool VerifySignature();
#endif

    bool SignContext();
    bool VerifyContext();
    bool SetData(cbuff data);
    bool GetData(cbuff& data);
    bool LoadData(string path);

    const uint160 GetHash()
    {
      uint256 hashOut = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hashOut;
      cbuff rawbuf(raw, raw + sizeof(hashOut));
      return Hash160(rawbuf);
    }

    bool SetStack();

    bool SetStack(cbuff stack)
    {
      vContext = stack;
      return (true);
    }

    cbuff GetStack()
    { 
      return (vContext);
    }

    uint160 GetIdentHash()
    {
      return (CIdent::GetHash());
    }

    CCoinAddr GetExecAddr()
    {
      return (CCoinAddr(stringFromVch(vAddr)));
    }

    void SetExecAddr(const CCoinAddr& addr)
    {
      vAddr = vchFromString(addr.ToString()); 
    }

    CCoinAddr GetCoinAddr()
    {
      return (CCoinAddr(stringFromVch(signature.vAddrKey)));
    }

    void SetCoinAddr(const CCoinAddr& addr)
    {
      signature.vAddrKey = vchFromString(addr.ToString()); 
    }

    std::string ToString();

    Object ToValue();

};

bool VerifyExec(CTransaction& tx, int& mode);


int init_exec_tx(CIface *iface, string strAccount, string strPath, int64 nExecFee, CWalletTx& wtx);

int update_exec_tx(CIface *iface, const uint160& hashExec, string strPath, CWalletTx& wtx);

int activate_exec_tx(CIface *iface, string strAccount, uint160 hExec, string strFunc, CWalletTx& wtx);

int remove_exec_tx(CIface *iface, string strAccount, const uint160& hashExec, CWalletTx& wtx);




#endif /* ndef __EXEC_H__ */


