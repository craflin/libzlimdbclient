
#ifndef _ZLIMDB_CLIENT_H
#define _ZLIMDB_CLIENT_H

#include "zlimdbprotocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _zlimdb zlimdb;

typedef void (*zlimdb_callback)(void* user_data, void* data, unsigned short size);

typedef enum
{
  zlimdb_local_error_none,
  zlimdb_local_error_invalid_parameter,
  zlimdb_local_error_not_initialized,
  zlimdb_local_error_out_of_memory,
  zlimdb_local_error_state,
  zlimdb_local_error_socket,
  zlimdb_local_error_resolve,
  zlimdb_local_error_interrupted,
  zlimdb_local_error_timeout,
  zlimdb_local_error_invalid_message_size,
  zlimdb_local_error_invalid_message_data,
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
const char* zlimdb_strerror(int errnum);

int zlimdb_add_table(zlimdb* zdb, const char* name, uint32_t* table_id);

int zlimdb_add(zlimdb* zdb, uint32_t table_id, const void* data, uint32_t size);
int zlimdb_query(zlimdb* zdb, uint32_t table_id, zlimdb_query_type type, uint64_t param);
int zlimdb_subscribe(zlimdb* zdb, uint32_t table_id, zlimdb_query_type type, uint64_t param);
int zlimdb_get_response(zlimdb* zdb, void* data, uint32_t maxSize, uint32_t* size);
int zlimdb_sync(zlimdb* zdb, uint32_t table_id, int64_t* server_time, int64_t* table_time);

int zlimdb_exec(zlimdb* zdb, uint32_t timeout);
int zlimdb_interrupt(zlimdb* zdb);

#ifdef __cplusplus
}
#endif

#endif /* _ZLIMDB_CLIENT_H */
