



#ifndef __STRATUM__USER_H__
#define __STRATUM__USER_H__

#define USER_SYSTEM (1 << 0)
#define USER_AUTH (1 << 1)
#define USER_SUBSCRIBE (1 << 2)
#define USER_SYNC (1 << 3)
#define USER_CLIENT (1 << 4)
#define USER_REMOTE (1 << 5)



user_t *stratum_user(user_t *user, char *username);

int stratum_user_broadcast_task(task_t *task);

double stratum_user_speed(user_t *user);

user_t *stratum_user_init(int fd);

void stratum_user_block(user_t *user, double share_diff);

user_t *stratum_user_get(int fd);

const char *get_user_flag_label(int flag);

void stratum_user_free(user_t *f_user);



#endif /* __STRATUM__USER_H__ */

