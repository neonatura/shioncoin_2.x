

#ifndef __SERVER__CHAIN_H__
#define __SERVER__CHAIN_H__

#ifdef __cplusplus
extern "C" {
#endif

#define BCOP_IMPORT 1
#define BCOP_EXPORT 2

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
void event_cycle_chain(int ifaceIndex);

#ifdef __cplusplus
}
#endif

#endif /* ndef __SERVER__CHAIN_H__ */
