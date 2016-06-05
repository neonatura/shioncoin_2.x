

#ifndef __SERVER__CHAIN_H__
#define __SERVER__CHAIN_H__

#ifdef __cplusplus
extern "C" {
#endif

#define BCOP_NONE 0
#define BCOP_IMPORT 1
#define BCOP_EXPORT 2
#define BCOP_DOWNLOAD 3

#include <stdio.h>

typedef struct ChainOp
{
  char path[PATH_MAX+1];
  int mode;
  int ifaceIndex;
  int pos;
  unsigned int max;
  unsigned int total;
} ChainOp;

int InitChainImport(int ifaceIndex, const char *path, int offset);
int InitChainExport(int ifaceIndex, const char *path, int max);
int InitDownloadBlockchain(int ifaceIndex, int maxHeight);
void event_cycle_chain(int ifaceIndex);

void ScanWalletTxUpdated(CWallet *wallet, const CBlock *pblock);

void InitScanWalletTx(CWallet *wallet, int nHeight);

void UpdateDownloadBlockchain(int ifaceIndex);

#ifdef __cplusplus
}
#endif

#endif /* ndef __SERVER__CHAIN_H__ */
