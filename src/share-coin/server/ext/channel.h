
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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

#ifndef __CHANNEL_H__
#define __CHANNEL_H__

class CChannel
{
  public:
    uint160 hRedeem;
    uint160 lcl_pubkey;
    uint160 rem_pubkey;
    uint160 lcl_npubkey;
    uint160 rem_npubkey;
    uint160 lcl_addr;
    uint160 rem_addr;
    int64 lcl_value;
    int64 rem_value;
    unsigned int nSeq;

    CChannel()
    {
      SetNull();
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(hRedeem);
      READWRITE(lcl_pubkey);
      READWRITE(rem_pubkey);
      READWRITE(lcl_npubkey);
      READWRITE(rem_npubkey);
      READWRITE(lcl_addr);
      READWRITE(rem_addr);
      READWRITE(lcl_value);
      READWRITE(rem_value);
      READWRITE(nSeq);
    )

    void SetNull()
    {

      hRedeem = 0;
      lcl_pubkey = 0;
      rem_pubkey = 0;
      lcl_npubkey = 0;
      rem_npubkey = 0;
      lcl_addr = 0;
      rem_addr = 0;
      lcl_value = 0;
      rem_value = 0;
      nSeq = 1;
    }

    void Init(const CChannel& channelIn)
    {

      hRedeem = channelIn.hRedeem;
      lcl_pubkey = channelIn.lcl_pubkey;
      rem_pubkey = channelIn.rem_pubkey;
      rem_npubkey = channelIn.rem_npubkey;
      lcl_npubkey = channelIn.lcl_npubkey;
      lcl_addr = channelIn.lcl_addr;
      rem_addr = channelIn.rem_addr;
      lcl_value = channelIn.lcl_value;
      rem_value = channelIn.rem_value;
      nSeq = channelIn.nSeq;
    }

    friend bool operator==(const CChannel &a, const CChannel &b)
    {
      return (
        a.hRedeem == b.hRedeem &&
        a.lcl_pubkey == b.lcl_pubkey &&
        a.rem_pubkey == b.rem_pubkey &&
        a.lcl_npubkey == b.lcl_npubkey &&
        a.rem_npubkey == b.rem_npubkey &&
        a.lcl_addr == b.lcl_addr &&
        a.rem_addr == b.rem_addr &&
        a.lcl_value == b.lcl_value &&
        a.rem_value == b.rem_value &&
        a.nSeq == b.nSeq
      );
    }

    CChannel operator=(const CChannel &b)
    {
      Init(b);
      return (*this);
    }

    const uint160 GetHash()
    {
      return (hRedeem);
    }

    std::string ToString();

    Object ToValue();

    bool SetHash();

    void GetRedeemScript(CScript& script);
 
    bool GetChannelTx(int ifaceIndex, CTransaction& tx);

    const CCoinAddr GetOriginAddr()
    {
      CCoinAddr addr;
      addr.Set(CKeyID(lcl_addr));
      return (addr);
    }

    const CCoinAddr GetPeerAddr()
    {
      CCoinAddr addr;
      addr.Set(CKeyID(rem_addr));
      return (addr);
    }

};


channel_list *GetChannelTable(int ifaceIndex);

channel_list *GetChannelSpentTable(int ifaceIndex);

int64 GetChannelReturnFee(const CTransaction& tx);


bool IsChannelTx(const CTransaction& tx);


bool GetTxOfChannel(CIface *iface, const uint160& hashChannel, CTransaction& tx); 


/** 
 * Initiate a Channel Funding Transaction for a counter-party.
 * @param strAccount the originating account initiating the channel.
 * @param addr counter-party coin address
 * @param nValue amount to allocate to the channel.
 */
int init_channel_tx(CIface *iface, string strAccount, int64 nValue, CCoinAddr& addr, CWalletTx& wtx);

/** 
 * Activate a Channel Funding Transaction from a counter-party.
 */
int activate_channel_tx(CIface *iface, CTransaction *txIn, int64 nValue, CWalletTx& wtx);

/**
 * Perform a pay operation "outside the blockchain".
 */
int pay_channel_tx(CIface *iface, string strAccount, uint160 hChan, int64 nValue, CWalletTx& wtx);

/**
 * Commit to a channel payment amendment.
 */
int validate_channel_tx(CIface *iface, const CTransaction *txIn, CWalletTx& wtx);


/**
 * Commit the current balances of the channel onto the block-chain.
 */
int generate_channel_tx(CIface *iface, uint160 hChan, CWalletTx& wtx);

/**
 * Forcibly reset the channel to the last established balance.
 */
int remove_channel_tx(CIface *iface, const uint160& hashChannel, CWalletTx& wtx);



#endif /* ndef __CHANNEL_H__ */


