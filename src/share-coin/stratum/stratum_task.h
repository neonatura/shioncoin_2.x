







#ifndef __STRATUM__TASK_H__
#define __STRATUM__TASK_H__

/**
 * Maximum time-span before a task assigned to a stratum client expires.
 */
#define MAX_TASK_LIFESPAN 100 


/** */
void task_free(task_t **task_p);

/** */
task_t *stratum_task(unsigned int task_id);


task_t *task_init(void);


#endif /* __STRATUM__TASK_H__ */

