
#ifndef _ZLIMDB_CLIENT_H
#define _ZLIMDB_CLIENT_H

#include "zlimdbprotocol.h"

struct zlimdb_t;

typedef struct zlimdb_t zlimdb;

typedef void (*zlimdb_callback)(void* user_data, void* data, unsigned short size);

typedef enum
{
  zlimdb_no_error,
  zlimdb_inval_error,
  zlimdb_state_error,
  zlimdb_socket_error,
  zlimdb_resolve_error,
  zlimdb_interrupted,
  zlimdb_timeout,
} zlimdb_error;

int zlimdb_init();
int zlimdb_cleanup();

zlimdb* zlimdb_create(zlimdb_callback callback, void* user_data);
int zlimdb_free(zlimdb* zdb);

int zlimdb_connect(zlimdb* zdb, const char* server, unsigned short port);
int zlimdb_errno(zlimdb* zdb);

int zlimdb_add(zlimdb* zdb, unsigned int table_id, void* data, unsigned short size);

int zlimdb_exec(zlimdb* zdb, unsigned int timeout);
int zlimdb_interrupt(zlimdb* zdb);

#endif /* _ZLIMDB_CLIENT_H */
