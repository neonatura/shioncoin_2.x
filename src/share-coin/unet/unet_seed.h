

#ifndef __UNET_SEED_H__
#define __UNET_SEED_H__


#define USDE_SEED_LIST_SIZE 7
static char *usde_seed_list[USDE_SEED_LIST_SIZE] = {
  "45.79.197.174", /* coin1.sharelib.net */
  "45.79.195.108", /* coin2.sharelib.net */
  "184.166.75.160",
  "193.227.134.111",
  "79.98.149.228",
  "88.208.1.194",
  "146.0.32.101",
/* 68.65.205.226:9014 */
};

#define SHC_SEED_LIST_SIZE 2
static char *shc_seed_list[SHC_SEED_LIST_SIZE] = {
  "45.79.197.174", /* coin1.sharelib.net */
  "45.79.195.108" /* coin2.sharelib.net */
};

#define OMNI_SEED_LIST_SIZE 4
static char *omni_seed_list[OMNI_SEED_LIST_SIZE] = {
  "45.79.197.174", /* coin1.sharelib.net */
  "45.79.195.108", /* coin2.sharelib.net */
  "192.99.42.164",
  "192.99.42.206"
};



#endif /* ndef __UNET_SEED_H__ */
