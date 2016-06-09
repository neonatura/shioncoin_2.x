
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

using namespace std;


uint64 GetCertFeeSubsidy(unsigned int nHeight) 
{
  unsigned int h6 = 360 * 6;
  unsigned int nTargetTime = 0;
  unsigned int nTarget1hrTime = 0;
  unsigned int blk1hrht = nHeight - 1;
  unsigned int blk6hrht = nHeight - 1;
  bool bFound = false;
  uint64 hr1 = 1, hr6 = 1;

#if 0 /* DEBUG: */
  BOOST_FOREACH(CCertFee &nmFee, lstCertIssuerFees) {
    if(nmFee.nHeight <= nHeight)
      bFound = true;
    if(bFound) {
      if(nTargetTime==0) {
        hr1 = hr6 = 0;
        nTargetTime = nmFee.nTime - h6;
        nTarget1hrTime = nmFee.nTime - (h6/6);
      }
      if(nmFee.nTime > nTargetTime) {
        hr6 += nmFee.nFee;
        blk6hrht = nmFee.nHeight;
        if(nmFee.nTime > nTarget1hrTime) {
          hr1 += nmFee.nFee;
          blk1hrht = nmFee.nHeight;
        }
      }
    }
  }
#endif
  hr6 /= (nHeight - blk6hrht) + 1;
  hr1 /= (nHeight - blk1hrht) + 1;
  uint64 nSubsidyOut = hr1 > hr6 ? hr1 : hr6;
fprintf(stderr, "DEBUG: GEtCertSubsidy: %llu\n", (unsigned long long)nSubsidyOut);
  return nSubsidyOut;
}

int64 GetCertNetworkFee(int nHeight) 
{
  int64 nRes = 48 * COIN;
  int64 nDif = 34 * COIN;
  int nTargetHeight = 2081280;
fprintf(stderr, "DEBUG: GEtCertNetworkFee: %llu\n", (unsigned long long)(nRes - ( (nHeight/nTargetHeight) * nDif )));
  return nRes - ( (nHeight/nTargetHeight) * nDif );
}



