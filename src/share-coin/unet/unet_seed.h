

#ifndef __UNET_SEED_H__
#define __UNET_SEED_H__


#define USDE_SEED_LIST_SIZE 9
static char *usde_seed_list[USDE_SEED_LIST_SIZE] = {
  "45.79.197.174", /* coin1.sharelib.net */
  "45.79.195.108", /* coin2.sharelib.net */
  "193.227.134.111",
  "79.98.149.228",
  "88.208.1.194",
  "146.0.32.101",
  "42.119.113.9", 
  "158.69.27.82",
  "151.55.14.246"
};

#define SHC_SEED_LIST_SIZE 2
static char *shc_seed_list[SHC_SEED_LIST_SIZE] = {
  "45.79.197.174", /* coin1.sharelib.net */
  "45.79.195.108" /* coin2.sharelib.net */
};

#define EMC2_SEED_LIST_SIZE 3
static char *emc2_seed_list[EMC2_SEED_LIST_SIZE] = {
  "45.79.197.174", /* coin1.sharelib.net */
  "45.79.195.108", /* coin2.sharelib.net */
  "98.115.147.74",
};



#endif /* ndef __UNET_SEED_H__ */
