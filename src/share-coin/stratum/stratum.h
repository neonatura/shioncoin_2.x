
#define USER_SYSTEM (1 << 0)

#define MAX_SPEED_STEP 60
#define MAX_ROUNDS_PER_HOUR 6

typedef struct user_t
{
  scrypt_peer peer;

  /** last aquired usde block */
  char block_hash[256];

  char worker[128];
  char cli_ver[128];
  int work_diff;

  int fd;
  int flags;

  /* request id for 'client.get_version'. */
  int cli_id;

  /* last height notified to user */
  int height;

  /* last submitted block timestamp. */
  double block_tm;

  /* total shares from blocks */ 
  uint64_t block_tot;

  /* cntal accepted blocks submitted. */ 
  size_t block_cnt;

  /* average round share value over last hour */
  double block_avg[MAX_ROUNDS_PER_HOUR];

  /* how many blocks submitted per second (avg) */
  double block_freq;

  /* number of blocks accepted for submission */
  int block_acc;

double speed[MAX_SPEED_STEP];

  /* the timestamp when the current round started. */
  time_t round_stamp;

  struct user_t *next;
} user_t;

typedef struct task_t
{

  /* unique reference number for task */
  unsigned int task_id;

  /* block attributes */
  int version;
  char cb1[256];
  char cb2[256];
  char prev_hash[256];
  char xnonce2[16];
  char nbits[32];
  time_t curtime;
  long height;
  /** whether new cycle of work tasks has occurred. */
  int work_reset;

  /* transactions */
  char **merkle;
  size_t merkle_len;

  /* block template parameters */
  char tmpl_merkle[256];
  char tmpl_xnonce1[16];

  double target;

  shmeta_t *share_list;
  shfs_ino_t *share_file; 

  scrypt_work work;

  struct task_t *next;
} task_t;

#include "stratum_user.h"
#include "stratum_protocol.h"
#include "stratum_message.h"
#include "stratum_task.h"

