



#ifndef __STRATUM__USER_H__
#define __STRATUM__USER_H__

#define USER_ACTIVE (1 << 0)
#define USER_AUTH (1 << 1)
#define USER_SUBSCRIBE (1 << 2)



user_t *stratum_user(user_t *user, char *username);
void stratum_user_block(user_t *user, task_t *task);
int stratum_user_broadcast_task(task_t *task);
double stratum_user_speed(user_t *user);
user_t *stratum_user_init(int fd);

#endif /* __STRATUM__USER_H__ */

