
#ifndef _ZLIMDB_CLIENT_H
#define _ZLIMDB_CLIENT_H

#include "zlimdbprotocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _zlimdb_ zlimdb;

typedef void (*zlimdb_callback)(void* user_data, const zlimdb_header* message);

typedef enum
{
  zlimdb_local_error_none,
  zlimdb_local_error_system,
  zlimdb_local_error_invalid_parameter,
  zlimdb_local_error_not_initialized,
  zlimdb_local_error_state,
  zlimdb_local_error_resolve,
  zlimdb_local_error_interrupted,
  zlimdb_local_error_timeout,
  zlimdb_local_error_invalid_message_data,
  zlimdb_local_error_invalid_response,
  zlimdb_local_error_buffer_size,
  zlimdb_local_error_connection_closed,
} zlimdb_local_error;

int zlimdb_init();
int zlimdb_cleanup();

zlimdb* zlimdb_create(zlimdb_callback callback, void* user_data);
int zlimdb_free(zlimdb* zdb);

int zlimdb_connect(zlimdb* zdb, const char* server, uint16_t port, const char* user_name, const char* password);
int zlimdb_is_connected(zlimdb* zdb);

int zlimdb_errno();
void zlimdb_seterrno(int errnum);
const char* zlimdb_strerror(int errnum);

int zlimdb_add_table(zlimdb* zdb, const char* name, uint32_t* table_id);
int zlimdb_find_table(zlimdb* zdb, const char* name, uint32_t* table_id);
int zlimdb_copy_table(zlimdb* zdb, uint32_t table_id, const char* new_name, uint32_t* new_table_id);
int zlimdb_remove_table(zlimdb* zdb, uint32_t table_id);
int zlimdb_add_user(zlimdb* zdb, const char* user_name, const char* password);

int zlimdb_add(zlimdb* zdb, uint32_t table_id, const zlimdb_entity* data, uint64_t* id);
int zlimdb_update(zlimdb* zdb, uint32_t table_id, const zlimdb_entity* data);
int zlimdb_remove(zlimdb* zdb, uint32_t table_id, uint64_t entity_id);
int zlimdb_clear(zlimdb* zdb, uint32_t table_id);
int zlimdb_query(zlimdb* zdb, uint32_t table_id, zlimdb_query_type type, uint64_t param);
int zlimdb_query_entity(zlimdb* zdb, uint32_t table_id, uint64_t entity_id, zlimdb_entity* entity, uint32_t min_size, uint32_t max_size);
int zlimdb_subscribe(zlimdb* zdb, uint32_t table_id, zlimdb_query_type type, uint64_t param, uint8_t flags);
int zlimdb_get_response(zlimdb* zdb, zlimdb_header* message, uint32_t max_size);
int zlimdb_unsubscribe(zlimdb* zdb, uint32_t table_id);
int zlimdb_sync(zlimdb* zdb, uint32_t table_id, int64_t* server_time, int64_t* table_time);
int zlimdb_control(zlimdb* zdb, uint32_t table_id, uint64_t entity_id, uint32_t control_code, const void* data, uint32_t size, zlimdb_header* message, uint32_t max_size);
int zlimdb_control_respond(zlimdb* zdb, uint32_t request_id, const void* data, uint32_t size);
int zlimdb_control_respond_error(zlimdb* zdb, uint32_t request_id, uint16_t error);

const zlimdb_entity* zlimdb_get_first_entity(const zlimdb_header* header, uint32_t min_size);
const zlimdb_entity* zlimdb_get_next_entity(const zlimdb_header* header, uint32_t min_size, const zlimdb_entity* entity);
const void* zlimdb_get_response_data(const zlimdb_header* header, uint32_t min_size);

int zlimdb_exec(zlimdb* zdb, uint32_t timeout);
int zlimdb_interrupt(zlimdb* zdb);

#ifdef __cplusplus
}
#endif

#endif /* _ZLIMDB_CLIENT_H */
