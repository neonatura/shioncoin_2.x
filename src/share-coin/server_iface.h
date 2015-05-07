
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

#ifndef __SERVER_IFACE_H__
#define __SERVER_IFACE_H__

#define BLKERR_BAD_SESSION 61
#define BLKERR_INVALID_JOB 62
#define BLKERR_DUPLICATE_BLOCK 63
#define BLKERR_LOW_DIFFICULTY 23
#define BLKERR_UNKNOWN 20
#define BLKERR_INVALID_BLOCK 71
#define BLKERR_INVALID_FORMAT 72
#define BLKERR_CHECKPOINT 73

#define STERR_GENERAL -1 /* a non-descript error occurred */
#define STERR_SAFEMODE -2
#define STERR_INVAL_AMOUNT -3
#define STERR_ACCESS_UNAVAIL -4 /* error accessing private key */
#define STERR_INVAL -5 /* invalid state occurred */
#define STERR_FUND_UNAVAIL -6
#define STERR_INTERNAL_MEM -7
#define STERR_INVAL_PARAM -8 /* invalid param */
#define STERR_AGAIN -10 /* not ready to perform requested operation (downloading blocks) */
#define STERR_INTERNAL_MAP -12 /* keypool dried up */
#define STERR_ACCESS_NOKEY -13 /* a required key was not specified */
#define STERR_ACCESS -14 /* a required key is not valid */
#define STERR_INTERNAL_DB -20 /* database error */
#define STERR_DECODE_TX -22 /* tx decode failed / tx rejected */
#define STERR_INVAL_OBJ -32600 /* invalid request object */

#ifdef __cplusplus
extern "C" {
#endif



/* net.cpp */
void start_node(void);
void start_node_peer(const char *host, int port);

/* init.cpp */
int load_wallet(void);
int load_peers(void);
void flush_addrman_db(void);
void server_shutdown(void);

const char *getblocktemplate(void);


const char *getblocktransactions(void);

const char *getaddressbyaccount(const char *accountName);

double getaccountbalance(const char *accountName);

int block_save(int block_height, const char *json_str);

char *block_load(int block_height);

int setblockreward(const char *accountName, double amount);

int wallet_account_transfer(const char *sourceAccountName, const char *accountName, const char *comment, double amount);


const char *getmininginfo(void);

const char *getblockinfo(const char *hash);
const char *gettransactioninfo(const char *hash);
const char *getlastblockinfo(int height);

const char *getaccounttransactioninfo(const char *account, const char *pkey_str, int duration);

const char *stratum_getaddressinfo(const char *addr_hash);

const char *stratum_getaddresssecret(const char *addr_hash, const char *pkey_str);

const char *submitblock(unsigned int workId, unsigned int nTime, unsigned int nNonce, char *xn_hex);

const char *getminingtransactioninfo(unsigned int workId);

const char *stratum_create_account(const char *acc_name);

const char *stratum_create_transaction(char *account, char *pkey_str, char *dest, double amount);

const char *stratum_getaccountinfo(const char *acc_name, const char *pkey_str);

const char *stratum_error_get(int req_id);

const char *stratum_importaddress(const char *account, const char *privaddr_str);

const char *getnewaddress(const char *account);

const int reloadblockfile(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* ndef __SERVER_IFACE_H__ */

