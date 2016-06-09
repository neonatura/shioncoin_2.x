
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

#ifndef __SERVER__CERTIFICATE_H__
#define __SERVER__CERTIFICATE_H__

using namespace std;

inline std::vector<unsigned char> vchFromString(const std::string &str) {
  unsigned char *strbeg = (unsigned char*) str.c_str();
  return std::vector<unsigned char>(strbeg, strbeg + str.size());
}   

typedef shcert_t SHCert;
typedef shcert_ent_t SHCertEnt;

class SHPeer
{
  public:
    shpeer_t peer;
    mutable unsigned char *raw_data;

    SHPeer()
    {
      SetNull();
    }
    SHPeer(shpeer_t *peerIn)
    {
      memcpy(&peer, peerIn, sizeof(peer));
      raw_data = (unsigned char *)&peer;
    }
    IMPLEMENT_SERIALIZE (
        READWRITE(cbuff(raw_data, raw_data + sizeof(peer)));
    )
    void SetNull()
    {
      memset(&peer, 0, sizeof(peer));
      raw_data = NULL;
    }
};

class SHSig
{
  public:
    shsig_t sig;
    mutable unsigned char *raw_data;

    SHSig()
    {
      SetNull();
    }
    SHSig(shsig_t *sigIn)
    {
      memcpy(&sig, sigIn, sizeof(sig));
      raw_data = (unsigned char *)&sig;
    }
    IMPLEMENT_SERIALIZE (
        READWRITE(cbuff(raw_data, raw_data + sizeof(sig)));
    )
    void SetNull()
    {
      memset(&sig, 0, sizeof(sig));
      raw_data = NULL;
    }
};

class CCertEnt
{
  protected:
    SHCertEnt entity;

  public:
    SHPeer peer;
    SHSig sig;

    CCertEnt()
    {
      SetNull();
    }
    
    CCertEnt(shcert_ent_t *entityIn)
    {
      SetNull();
      memcpy(&entity, entityIn, sizeof(entity));
      peer = SHPeer(&entity.ent_peer);
      sig = SHSig(&entity.ent_sig);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(cbuff(entity.ent_data, entity.ent_data + sizeof(entity.ent_data)));
      READWRITE(cbuff(entity.ent_name, entity.ent_name + sizeof(entity.ent_name)));
      READWRITE(peer);
      READWRITE(sig);
      READWRITE(entity.ent_len);
    )

    void SetNull()
    {
      memset(&entity, 0, sizeof(entity));
    }

    std::string GetName()
    {
      string ent_name(entity.ent_name);
      return (ent_name);
    }

    const char *GetSecret(int& data_len)
    {
      data_len = entity.ent_len; 
      return ((const char *)entity.ent_data);
    }


};

class CCert
{
  protected:
    SHCert cert;
    CCertEnt ent_sub;
    CCertEnt ent_iss;

  public:
    CCert()
    {
      SetNull();
    }

    CCert(shcert_t *certIn)
    {
      SetNull();
      memcpy(&cert, certIn, sizeof(cert));
      ent_sub = CCertEnt(&cert.cert_sub);
      ent_iss = CCertEnt(&cert.cert_iss);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(ent_sub);
      READWRITE(ent_iss);
      READWRITE(cbuff(cert.cert_ser, cert.cert_ser + sizeof(cert.cert_ser)));
      READWRITE(cert.cert_fee);
      READWRITE(cert.cert_flag);
      READWRITE(cert.cert_ver);
    )

    void SetNull()
    {
      memset(&cert, 0, sizeof(cert));
    }

    int GetVersion()
    {
      return ((int)cert.cert_ver);
    }

    int GetFlags()
    {
      return ((int)cert.cert_flag);
    }

    int64 GetFee()
    {
      return ((int64)cert.cert_fee);
    }

    std::string GetSerialNumber()
    {
/* convert from 128bit binary .. */
    }

    CCertEnt *GetIssuerEntity()
    {
      return (&ent_iss);
    }

    CCertEnt *GetSubjectEntity()
    {
      return (&ent_sub);
    }
    
};


/** 
 * a 'discount' applied when certification is infrequent.
 */
uint64 GetCertFeeSubsidy(unsigned int nHeight);

/**
 * The cost of a initiate, active, and transfer certificate operation.
 */
int64 GetCertNetworkFee(int nHeight);



#endif /* ndef __SERVER__CERTIFICATE_H__ */


