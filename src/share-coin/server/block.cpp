
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

#include "shcoind.h"
#include "block.h"
#include <vector>

using namespace std;


//vector <bc_t *> vBlockChain;

/**
 * Opens a specific database of block records.
 */
bc_t *GetBlockChain(CIface *iface)
{

  if (!iface->bc_block) {
    char name[4096];

    sprintf(name, "%s_block", iface->name);
    bc_open(name, &iface->bc_block);
  }

  return (iface->bc_block);
}

/**
 * Closes all open block record databases.
 */
void CloseBlockChains(void)
{
  CIface *iface;
  int idx;

  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
    iface = GetCoinByIndex(idx);
    if (!iface)
      continue;

    if (iface->bc_block) {
      bc_close(iface->bc_block);
      iface->bc_block = NULL;
    }
    if (iface->bc_tx) {
      bc_close(iface->bc_tx);
      iface->bc_tx = NULL;
    }
  }

}

#if 0
bc_t *GetBlockChain(char *name)
{
  bc_t *bc;

  for(vector<bc_t *>::iterator it = vBlockChain.begin(); it != vBlockChain.end(); ++it) {
    bc = *it;
    if (0 == strcmp(bc_name(bc), name))
      return (bc);
  }

  bc_open(name, &bc);
  vBlockChain.push_back(bc);

  return (bc);
}

/**
 * Closes all open block record databases.
 */
void CloseBlockChains(void)
{
  bc_t *bc;

  for(vector<bc_t *>::iterator it = vBlockChain.begin(); it != vBlockChain.end(); ++it) {
    bc_t *bc = *it;
    bc_close(bc);
  }
  vBlockChain.clear();

}
#endif


int64 GetInitialBlockValue(int nHeight, int64 nFees)
{
  int64 nSubsidy = 4000 * COIN;

  if ((nHeight % 100) == 1)
  {
    nSubsidy = 100000 * COIN; //100k
  }else if ((nHeight % 50) == 1)
  {
    nSubsidy = 50000 * COIN; //50k
  }else if ((nHeight % 20) == 1)
  {
    nSubsidy = 20000 * COIN; //20k
  }else if ((nHeight % 10) == 1)
  {
    nSubsidy = 10000 * COIN; //10k
  }else if ((nHeight % 5) == 1)
  {
    nSubsidy = 5000 * COIN; //5k
  }

  //limit first blocks to protect against instamine.
  if (nHeight < 2){
    nSubsidy = 24000000 * COIN; // 1.5%
  }else if(nHeight < 500)
  {
    nSubsidy = 100 * COIN;
  }
  else if(nHeight < 1000)
  {
    nSubsidy = 500 * COIN;
  }

  nSubsidy >>= (nHeight / 139604);

  return (nSubsidy + nFees);
}

int64 GetBlockValue(int nHeight, int64 nFees)
{
  int64 nSubsidy = 4000 * COIN;
  int base = nHeight;

  if (nHeight < 107500) {
    return (GetInitialBlockValue(nHeight, nFees));
  }

#if CLIENT_VERSION_REVISION > 4
  if (nHeight >= 1675248) {
    /* transition from 1.6bil cap to 1.6tril cap. */
    base /= 9;
  }
#endif

  nSubsidy >>= (base / 139604);

#if CLIENT_VERSION_REVISION > 4
  if (nHeight >= 1675248) {
    /* balance flux of reward. reduces max coin cap to 320bil */
    nSubsidy /= 5;
  }
#endif

  return nSubsidy + nFees;
}

