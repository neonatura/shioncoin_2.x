
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

#include "share.h"
#include "shcoind.h"
#include "util.h"
#include "main.h"
#include "block.h"

#ifndef WIN32
#include "sys/stat.h"
#endif

using namespace std;
using namespace boost;


unsigned int nWalletDBUpdated;



//
// CDB
//

CDBEnv bitdb;

void CDBEnv::EnvShutdown()
{
    if (!fDbEnvInit)
        return;

    fDbEnvInit = false;
    try
    {
        dbenv.close(0);
    }
    catch (const DbException& e)
    {
        printf("EnvShutdown exception: %s (%d)\n", e.what(), e.get_errno());
    }
    DbEnv(0).remove(GetDataDir().string().c_str(), 0);
}

CDBEnv::CDBEnv() : dbenv(0)
{
}

CDBEnv::~CDBEnv()
{
    EnvShutdown();
}

void CDBEnv::Close()
{
    EnvShutdown();
}

bool CDBEnv::Open(boost::filesystem::path pathEnv_)
{
    if (fDbEnvInit)
        return true;

    if (fShutdown)
        return false;

    pathEnv = pathEnv_;
    filesystem::path pathDataDir = pathEnv;
    filesystem::path pathLogDir = pathDataDir / "database";
    filesystem::create_directory(pathLogDir);
    filesystem::path pathErrorFile = pathDataDir / "db.log";
    printf("dbenv.open LogDir=%s ErrorFile=%s\n", pathLogDir.string().c_str(), pathErrorFile.string().c_str());

    unsigned int nEnvFlags = 0;
    if (GetBoolArg("-privdb", true))
        nEnvFlags |= DB_PRIVATE;

    int nDbCache = GetArg("-dbcache", 25);
    dbenv.set_lg_dir(pathLogDir.string().c_str());
    dbenv.set_cachesize(nDbCache / 1024, (nDbCache % 1024)*1048576, 1);
    dbenv.set_lg_bsize(1048576);
    dbenv.set_lg_max(10485760);
    dbenv.set_lk_max_locks(10000);
    dbenv.set_lk_max_objects(10000);
    dbenv.set_errfile(fopen(pathErrorFile.string().c_str(), "a")); /// debug
    dbenv.set_flags(DB_AUTO_COMMIT, 1);
    dbenv.set_flags(DB_TXN_WRITE_NOSYNC, 1);
    dbenv.log_set_config(DB_LOG_AUTO_REMOVE, 1);
    int ret = dbenv.open(pathDataDir.string().c_str(),
                     DB_CREATE     |
                     DB_INIT_LOCK  |
                     DB_INIT_LOG   |
                     DB_INIT_MPOOL |
                     DB_INIT_TXN   |
                     DB_THREAD     |
                     DB_RECOVER    |
                     nEnvFlags,
                     S_IRUSR | S_IWUSR);
    if (ret > 0)
        return error(SHERR_ACCESS, "CDB() : error %d opening database environment", ret);

    fDbEnvInit = true;
    return true;
}

void CDBEnv::CheckpointLSN(std::string strFile)
{
    dbenv.txn_checkpoint(0, 0, 0);
    dbenv.lsn_reset(strFile.c_str(), 0);
}


CDB::CDB(const char *pszFile, const char* pszMode) :
    pdb(NULL), activeTxn(NULL)
{
    int ret;
    if (pszFile == NULL)
        return;

    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    bool fCreate = strchr(pszMode, 'c');
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    {
        LOCK(bitdb.cs_db);
        if (!bitdb.Open(GetDataDir()))
            throw runtime_error("env open failed");

        strFile = pszFile;
        ++bitdb.mapFileUseCount[strFile];
        pdb = bitdb.mapDb[strFile];
        if (pdb == NULL)
        {
            pdb = new Db(&bitdb.dbenv, 0);

            ret = pdb->open(NULL,      // Txn pointer
                            pszFile,   // Filename
                            "main",    // Logical db name
                            DB_BTREE,  // Database type
                            nFlags,    // Flags
                            0);

            if (ret > 0)
            {
                delete pdb;
                pdb = NULL;
                {
                     LOCK(bitdb.cs_db);
                    --bitdb.mapFileUseCount[strFile];
                }
                strFile = "";
                throw runtime_error(strprintf("CDB() : can't open database file %s, error %d", pszFile, ret));
            }

            if (fCreate && !Exists(string("version")))
            {
                bool fTmp = fReadOnly;
                fReadOnly = false;
                WriteVersion(CLIENT_VERSION);
                fReadOnly = fTmp;
            }

            bitdb.mapDb[strFile] = pdb;
        }
    }
}

#if 0
static bool IsChainFile(std::string strFile)
{
    if (strFile == "blkinfo.dat")
        return true;

    return false;
}
#endif

void CDB::Close()
{
    if (!pdb)
        return;
    if (activeTxn)
        activeTxn->abort();
    activeTxn = NULL;
    pdb = NULL;

    // Flush database activity from memory pool to disk log
    unsigned int nMinutes = 0;
    if (fReadOnly)
        nMinutes = 1;
#if 0
    if (IsChainFile(strFile))
        nMinutes = 2;
    if (IsChainFile(strFile) && IsInitialBlockDownload())
        nMinutes = 5;
#endif

    bitdb.dbenv.txn_checkpoint(nMinutes ? GetArg("-dblogsize", 100)*1024 : 0, nMinutes, 0);

    {
        LOCK(bitdb.cs_db);
        --bitdb.mapFileUseCount[strFile];
    }
}

void CDBEnv::CloseDb(const string& strFile)
{
    {
        LOCK(cs_db);
        if (mapDb[strFile] != NULL)
        {
            // Close the database handle
            Db* pdb = mapDb[strFile];
            pdb->close(0);
            delete pdb;
            mapDb[strFile] = NULL;
        }
    }
}

bool CDB::Rewrite(const string& strFile, const char* pszSkip)
{
    while (!fShutdown)
    {
        {
            LOCK(bitdb.cs_db);
            if (!bitdb.mapFileUseCount.count(strFile) || bitdb.mapFileUseCount[strFile] == 0)
            {
                // Flush log data to the dat file
                bitdb.CloseDb(strFile);
                bitdb.CheckpointLSN(strFile);
                bitdb.mapFileUseCount.erase(strFile);

                bool fSuccess = true;
                printf("Rewriting %s...\n", strFile.c_str());
                string strFileRes = strFile + ".rewrite";
                { // surround usage of db with extra {}
                    CDB db(strFile.c_str(), "r");
                    Db* pdbCopy = new Db(&bitdb.dbenv, 0);
    
                    int ret = pdbCopy->open(NULL,                 // Txn pointer
                                            strFileRes.c_str(),   // Filename
                                            "main",    // Logical db name
                                            DB_BTREE,  // Database type
                                            DB_CREATE,    // Flags
                                            0);
                    if (ret > 0)
                    {
                        printf("Cannot create database file %s\n", strFileRes.c_str());
                        fSuccess = false;
                    }
    
                    Dbc* pcursor = db.GetCursor();
                    if (pcursor)
                        while (fSuccess)
                        {
                            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
                            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                            int ret = db.ReadAtCursor(pcursor, ssKey, ssValue, DB_NEXT);
                            if (ret == DB_NOTFOUND)
                            {
                                pcursor->close();
                                break;
                            }
                            else if (ret != 0)
                            {
                                pcursor->close();
                                fSuccess = false;
                                break;
                            }
                            if (pszSkip &&
                                strncmp(&ssKey[0], pszSkip, std::min(ssKey.size(), strlen(pszSkip))) == 0)
                                continue;
                            if (strncmp(&ssKey[0], "\x07version", 8) == 0)
                            {
                                // Update version:
                                ssValue.clear();
                                ssValue << CLIENT_VERSION;
                            }
                            Dbt datKey(&ssKey[0], ssKey.size());
                            Dbt datValue(&ssValue[0], ssValue.size());
                            int ret2 = pdbCopy->put(NULL, &datKey, &datValue, DB_NOOVERWRITE);
                            if (ret2 > 0)
                                fSuccess = false;
                        }
                    if (fSuccess)
                    {
                        db.Close();
                        bitdb.CloseDb(strFile);
                        if (pdbCopy->close(0))
                            fSuccess = false;
                        delete pdbCopy;
                    }
                }
                if (fSuccess)
                {
                    Db dbA(&bitdb.dbenv, 0);
                    if (dbA.remove(strFile.c_str(), NULL, 0))
                        fSuccess = false;
                    Db dbB(&bitdb.dbenv, 0);
                    if (dbB.rename(strFileRes.c_str(), NULL, strFile.c_str(), 0))
                        fSuccess = false;
                }
                if (!fSuccess)
                    printf("Rewriting of %s FAILED!\n", strFileRes.c_str());
                return fSuccess;
            }
        }
        Sleep(100);
    }
    return false;
}


void CDBEnv::Flush(bool fShutdown)
{
    int64 nStart = GetTimeMillis();
    // Flush log data to the actual data file
    //  on all files that are not in use
    printf("Flush(%s)%s\n", fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started");
    if (!fDbEnvInit)
        return;
    {
        LOCK(cs_db);
        map<string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end())
        {
            string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            printf("%s refcount=%d\n", strFile.c_str(), nRefCount);
            if (nRefCount == 0)
            {
                // Move log data to the dat file
                CloseDb(strFile);
                printf("%s checkpoint\n", strFile.c_str());
                dbenv.txn_checkpoint(0, 0, 0);
                //if (!IsChainFile(strFile) || fDetachDB) {
                if (fDetachDB) {
                    printf("%s detach\n", strFile.c_str());
                    dbenv.lsn_reset(strFile.c_str(), 0);
                }
                printf("%s closed\n", strFile.c_str());
                mapFileUseCount.erase(mi++);
            }
            else
                mi++;
        }
        printf("DBFlush(%s)%s ended %15"PRI64d"ms\n", fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started", GetTimeMillis() - nStart);
        if (fShutdown)
        {
            char** listp;
            if (mapFileUseCount.empty())
            {
                dbenv.log_archive(&listp, DB_ARCH_REMOVE);
                Close();
            }
        }
    }
}





//
// CTxDB
//

bool CTxDB::ReadTxIndex(uint256 hash, CTxIndex& txindex)
{
    assert(!fClient);
    txindex.SetNull();
    return Read(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex& txindex)
{
    assert(!fClient);
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight)
{
    assert(!fClient);

    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction& tx)
{
    assert(!fClient);
    uint256 hash = tx.GetHash();

//    Debug("EraseTxIndex: removing tx '%s' from block-chain.", tx.GetHash().GetHex().c_str());

    return Erase(make_pair(string("tx"), hash));
}

bool CTxDB::ContainsTx(uint256 hash)
{
    assert(!fClient);
    return Exists(make_pair(string("tx"), hash));
}


bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
fprintf(stderr, "DEBUG: ReadDiskTx()\n");
  return (tx.ReadTx(ifaceIndex, hash));
}

#if 0
bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
return (GetTransaction(GetCoinByIndex(ifaceIndex), hash, tx, (*blkidx)[
    assert(!fClient);
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex))
        return false;
    return (tx.ReadFromDisk(txindex.pos));
}
#endif

#if 0
bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}
#endif

#if 0
bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
    return ReadDiskTx(outpoint.hash, tx, txindex);
}
#endif

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
  return (ReadDiskTx(outpoint.hash, tx));
#if 0
    CTxIndex txindex;
    return ReadDiskTx(outpoint.hash, tx, txindex);
#endif
}

#if 0
bool CTxDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}
#endif

bool CTxDB::ReadHashBestChain(uint256& hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}

bool CTxDB::ReadBestInvalidWork(CBigNum& bnBestInvalidWork)
{
    return Read(string("bnBestInvalidWork"), bnBestInvalidWork);
}

bool CTxDB::WriteBestInvalidWork(CBigNum bnBestInvalidWork)
{
    return Write(string("bnBestInvalidWork"), bnBestInvalidWork);
}

CBlockIndex *InsertBlockIndex(blkidx_t *blockIndex, uint256 hash)
{
    if (hash == 0)
        return NULL;

    // Return existing
    map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hash);
    if (mi != blockIndex->end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
    mi = blockIndex->insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}


/** FOLLOWING NOT USED YET **/

#ifdef __cplusplus
extern "C" {
#endif

#define TXIDX_TABLE "txidx"

shdb_t *txdb_open(CIface *iface)
{
  shdb_t *db;

  db = shdb_open(iface->name);
  if (!db)
    return (NULL);

  if (0 == shdb_table_new(db, TXIDX_TABLE)) {
    shdb_col_new(db, TXIDX_TABLE, "origin");
    shdb_col_new(db, TXIDX_TABLE, "spent");
  }

  return (db);
}

void txdb_close(shdb_t **db_p)
{
  shdb_t *db;

  if (!db_p)
    return;

  db = *db_p;
  *db_p = NULL;

  shdb_close(db);
}

bool WriteTxIndex(CIface *iface, uint256 txOrigin, uint256 txSpent)
{
  shdb_t *db;
  shdb_idx_t rowid;
  char sql_str[1024];
  char hash[512];
  char *ret_val;
  int err;

  db = txdb_open(iface);
  if (!db)
    return (false);

  ret_val = NULL;
  sprintf(sql_str, "select origin from %s where origin = '%s' and spent = '%s'", TXIDX_TABLE, txOrigin.GetHex().c_str(), txSpent.GetHex().c_str());
  err = shdb_exec_cb(db, sql_str, shdb_col_value_cb, &ret_val);
  if (!err) {
    /* entry already exists */
    free(ret_val);
    return (0);
  }

  err = shdb_row_new(db, TXIDX_TABLE, &rowid);
  if (err) goto error;
  strcpy(hash, txOrigin.GetHex().c_str());
  err = shdb_row_set(db, TXIDX_TABLE, rowid, "origin", hash);
  if (err) goto error;
  strcpy(hash, txSpent.GetHex().c_str()); 
  err = shdb_row_set(db, TXIDX_TABLE, rowid, "spent", hash);
  if (err) goto error;

  err = 0;

error:
  txdb_close(&db);
  return (err);
}

#ifdef __cplusplus
}
#endif


int txdb_hashlist_cb(void *p, int arg_nr, char **args, char **cols)
{
  HashList *list = (HashList *)p;
  uint256 hash;

  if (arg_nr > 0 && *args) {
    hash.SetHex(*args);
    list->push_back(hash);
fprintf(stderr, "DEBUG: txdb_hashlist_cb: inserted hash '%s'\n", hash.GetHex().c_str());
  }

  return (0);
}


bool ReadTxIndexOrigin(CIface *iface, uint256 txSpent, HashList& txOrigin)
{
  vector<uint256> origin; 
  shdb_t *db;
  shdb_idx_t rowid;
  char sql_str[1024];
  char *ret_val;
  int err;

  db = txdb_open(iface);
  if (!db)
    return (false);

  ret_val = NULL;
  sprintf(sql_str, "select origin from %s where spent = '%s'", TXIDX_TABLE, txSpent.GetHex().c_str());
  shdb_exec_cb(db, sql_str, txdb_hashlist_cb, &origin);

  txOrigin = origin;

  txdb_close(&db);
  
  return (true);
}

bool ReadTxIndexSpent(CIface *iface, uint256 txOrigin, HashList& txSpent)
{
  vector<uint256> spent;
  shdb_t *db;
  shdb_idx_t rowid;
  char sql_str[1024];
  char *ret_val;
  int err;

  db = txdb_open(iface);
  if (!db)
    return (false);

  ret_val = NULL;
  sprintf(sql_str, "select spent from %s where origin = '%s'", TXIDX_TABLE, txOrigin.GetHex().c_str());
  shdb_exec_cb(db, sql_str, txdb_hashlist_cb, &spent);

  txSpent = spent;

  txdb_close(&db);
  
  return (true);
}


#if 0
bool CTxDB::ReadHashBestChain(uint256& hashBestChain)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  hashBestChain = ReadBestChain(iface);
  return (true);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  WriteBestChain(iface, hashBestChain);
  return (true);
}
bool CTxDB::ReadBestInvalidWork(CBigNum& bnBestInvalidWork)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bnBestInvalidWork = ReadBestInvalid(iface);
  return (true);
}

bool CTxDB::WriteBestInvalidWork(CBigNum bnBestInvalidWork)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  WriteBestInvalid(iface, bnBestInvalidWork);
  return (true);
}
#endif

