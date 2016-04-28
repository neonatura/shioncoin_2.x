
int bc_idx_set(bc_t *bc, size_t pos, bc_idx_t *idx);
int bc_idx_next(bc_t *bc);
int bc_idx_new(bc_t *bc, int pos, bc_hash_t hash, size_t data_len);
int bc_idx_clear(bc_t *bc, size_t pos);
int bc_idx_find(bc_t *bc, bc_hash_t hash, bc_idx_t *ret_idx, int *ret_pos);


