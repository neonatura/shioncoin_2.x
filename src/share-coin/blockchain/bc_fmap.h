
void bc_map_free(bc_map_t *map);

int bc_map_open(bc_t *bc, bc_map_t *map);

int bc_map_alloc(bc_t *bc, bc_map_t *map, size_t len);

int bc_map_append(bc_t *bc, bc_map_t *map, void *raw_data, size_t data_len);
int bc_map_write(bc_t *bc, bc_map_t *map, size_t of, void *raw_data, size_t data_len);
