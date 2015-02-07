
#ifndef _ZLIMDB_CLIENT_H
#define _ZLIMDB_CLIENT_H

#include "zlimdbprotocol.h"

typedef struct _zlimdb zlimdb;

typedef void (*zlimdb_callback)(void* user_data, void* data, unsigned short size);

typedef enum
{
  zlimdb_local_error_none,
  zlimdb_local_error_state,
  zlimdb_local_error_socket,
  zlimdb_local_error_resolve,
  zlimdb_local_error_interrupted,
  zlimdb_local_error_timeout,
  zlimdb_local_error_invalid_message_size,
  zlimdb_local_error_buffer_size,
  zlimdb_local_error_connection_closed,
} zlimdb_local_error;

int zlimdb_init();
int zlimdb_cleanup();

zlimdb* zlimdb_create(zlimdb_callback callback, void* user_data);
int zlimdb_free(zlimdb* zdb);

int zlimdb_connect(zlimdb* zdb, const char* server, uint16_t port, const char* user_name, const char* password);
int zlimdb_errno();
const char* zlimdb_strerror(int errnum);

int zlimdb_add(zlimdb* zdb, uint32_t table_id, const void* data, uint16_t size);
int zlimdb_query(zlimdb* zdb, uint32_t table_id, zlimdb_query_type type, uint64_t param);
int zlimdb_query_get_response(zlimdb* zdb, void* data, uint16_t size);

int zlimdb_exec(zlimdb* zdb, uint32_t timeout);
int zlimdb_interrupt(zlimdb* zdb);

#endif /* _ZLIMDB_CLIENT_H */
