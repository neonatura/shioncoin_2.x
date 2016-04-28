
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

#include "db.h"
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"

#ifdef WIN32
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef fcntl
#undef fcntl
#endif

#include <boost/array.hpp>
#include <share.h>
#include "walletdb.h"

using namespace std;
using namespace boost;

static CWallet *shcWallet;

int shc_UpgradeWallet(void)
{
  int nMaxVersion = 0;//GetArg("-upgradewallet", 0);
  if (nMaxVersion == 0) // the -upgradewallet without argument case
  {
    nMaxVersion = CLIENT_VERSION;
    shcWallet->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
    Debug("using wallet version %d", FEATURE_LATEST);
  }
  else
    printf("Allowing wallet upgrade up to %i\n", nMaxVersion);

  if (nMaxVersion > shcWallet->GetVersion()) {
    shcWallet->SetMaxVersion(nMaxVersion);
  }

}

int shc_LoadWallet(void)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  std::ostringstream strErrors;

  const char* pszP2SH = "/P2SH/";
  COINBASE_FLAGS << std::vector<unsigned char>(pszP2SH, pszP2SH+strlen(pszP2SH));

  if (!bitdb.Open(GetDataDir()))
  {
    fprintf(stderr, "error: unable to open data directory.\n");
    return (-1);
  }

  if (!LoadBlockIndex(iface)) {
    fprintf(stderr, "error: unable to open load block index.\n");
    return (-1);
  }

  bool fFirstRun = true;
  shcWallet = new CWallet("shc_wallet.dat");
  SetWallet(SHC_COIN_IFACE, shcWallet);
  shcWallet->LoadWallet(fFirstRun);

  if (fFirstRun)
  {

    // Create new keyUser and set as default key
    RandAddSeedPerfmon();

    CPubKey newDefaultKey;
    if (!shcWallet->GetKeyFromPool(newDefaultKey, false))
      strErrors << _("Cannot initialize keypool") << "\n";
    shcWallet->SetDefaultKey(newDefaultKey);
    if (!shcWallet->SetAddressBookName(shcWallet->vchDefaultKey.GetID(), ""))
      strErrors << _("Cannot write default address") << "\n";
  }

  printf("%s", strErrors.str().c_str());

  RegisterWallet(shcWallet);

  CBlockIndex *pindexRescan = pindexBest;
  if (GetBoolArg("-rescan"))
    pindexRescan = pindexGenesisBlock;
  else
  {
    CWalletDB walletdb("shc_wallet.dat");
    CBlockLocator locator(GetCoinIndex(iface));
    if (walletdb.ReadBestBlock(locator))
      pindexRescan = locator.GetBlockIndex();
  }
  if (pindexBest != pindexRescan && pindexBest && pindexRescan && pindexBest->nHeight > pindexRescan->nHeight)
  {
    int64 nStart;

    printf("Rescanning last %i blocks (from block %i)...\n", pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
    nStart = GetTimeMillis();
    shcWallet->ScanForWalletTransactions(pindexRescan, true);
    printf(" rescan      %15"PRI64d"ms\n", GetTimeMillis() - nStart);
  }

  shc_UpgradeWallet();

/* DEBUG: */
//pwalletMain = shcWallet;
}


