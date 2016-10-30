
int bc_idx_set(bc_t *bc, bcsize_t pos, bc_idx_t *idx);

int bc_idx_clear(bc_t *bc, bcsize_t pos);
int bc_idx_find(bc_t *bc, bc_hash_t hash, bc_idx_t *ret_idx, int *ret_pos);
int bc_idx_get(bc_t *bc, bcsize_t pos, bc_idx_t *ret_idx);

bcsize_t bc_idx_next(bc_t *bc);

int bc_idx_reset(bc_t *bc, bcsize_t pos, bc_idx_t *idx);



