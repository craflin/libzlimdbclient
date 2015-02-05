
#ifndef _ZLIMDB_CLIENT_H
#define _ZLIMDB_CLIENT_H

#include "zlimdbprotocol.h"

typedef struct _zlimdb zlimdb;

typedef void (*zlimdb_callback)(void* user_data, void* data, unsigned short size);

typedef enum
{
  zlimdb_error_none,
  zlimdb_error_state,
  zlimdb_error_socket,
  zlimdb_error_resolve,
  zlimdb_error_interrupted,
  zlimdb_error_timeout,
  zlimdb_error_invalid_response,
  zlimdb_error_connection_closed,
} zlimdb_error;

int zlimdb_init();
int zlimdb_cleanup();

zlimdb* zlimdb_create(zlimdb_callback callback, void* user_data);
int zlimdb_free(zlimdb* zdb);

int zlimdb_connect(zlimdb* zdb, const char* server, uint16_t port, const char* user_name, const char* password);
int zlimdb_errno();

int zlimdb_add(zlimdb* zdb, uint32_t table_id, void* data, uint16_t size);

int zlimdb_exec(zlimdb* zdb, uint32_t timeout);
int zlimdb_interrupt(zlimdb* zdb);

#endif /* _ZLIMDB_CLIENT_H */
