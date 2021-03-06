
#ifndef _ZLIMDB_PROTOCOL_H
#define _ZLIMDB_PROTOCOL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZLIMDB_DEFAULT_PORT 13211
#define ZLIMDB_MAX_ENTITY_SIZE 0xffff
#define ZLIMDB_MAX_MESSAGE_SIZE (128 + ZLIMDB_MAX_ENTITY_SIZE)

typedef enum
{
  zlimdb_message_error_response,
  zlimdb_message_login_request,
  zlimdb_message_login_response,
  zlimdb_message_auth_request,
  zlimdb_message_auth_response,
  zlimdb_message_add_request,
  zlimdb_message_add_response,
  zlimdb_message_update_request,
  zlimdb_message_update_response,
  zlimdb_message_remove_request,
  zlimdb_message_remove_response,
  zlimdb_message_subscribe_request,
  zlimdb_message_subscribe_response,
  zlimdb_message_unsubscribe_request,
  zlimdb_message_unsubscribe_response,
  zlimdb_message_query_request,
  zlimdb_message_query_response,
  zlimdb_message_sync_request,
  zlimdb_message_sync_response,
  zlimdb_message_control_request,
  zlimdb_message_control_response,
  zlimdb_message_clear_request,
  zlimdb_message_clear_response,
  zlimdb_message_copy_request,
  zlimdb_message_copy_response,
  zlimdb_message_find_request,
  zlimdb_message_find_response,
  zlimdb_message_rename_request,
  zlimdb_message_rename_response,
  zlimdb_message_reload_request,
  zlimdb_message_shutdown_request,
} zlimdb_message_type;
  
typedef enum
{
  zlimdb_table_clients = 1,
  zlimdb_table_tables,
} zlimdb_table_id;

typedef enum
{
  zlimdb_error_invalid_message_data = 1000,
  zlimdb_error_invalid_message_type,
  zlimdb_error_entity_not_found,
  zlimdb_error_table_not_found,
  zlimdb_error_not_implemented,
  zlimdb_error_invalid_request,
  zlimdb_error_invalid_login,
  zlimdb_error_open_file,
  zlimdb_error_read_file,
  zlimdb_error_write_file,
  zlimdb_error_subscription_not_found,
  zlimdb_error_entity_id,
  zlimdb_error_table_already_exists,
  zlimdb_error_responder_not_available,
  zlimdb_error_responder_already_present,
} zlimdb_message_error;

typedef enum
{
  zlimdb_header_flag_fragmented = 0x01,
  zlimdb_header_flag_compressed = 0x02,
} zlimdb_header_flag;

typedef enum
{
  zlimdb_query_type_all,
  zlimdb_query_type_by_id,
  zlimdb_query_type_since_id,
  zlimdb_query_type_since_time,
  zlimdb_query_type_since_last,
  zlimdb_query_type_since_next,
} zlimdb_query_type;

#pragma pack(push, 1)
typedef struct
{
  uint32_t flags:8; ///< @see zlimdb_header_flag
  uint32_t size:24; ///< The size of the message including the header.
  uint16_t message_type; ///< @see zlimdb_message_type
  uint32_t request_id; ///< An identifier that can be chosen by the client. The response will carry the same identifier.
} zlimdb_header;

typedef struct
{
  zlimdb_header header;
  uint16_t error; ///< @see zlimdb_message_error
} zlimdb_error_response;

typedef struct
{
  zlimdb_header header;
  uint16_t user_name_size; ///< The length of the user name.
} zlimdb_login_request;

typedef struct
{
  zlimdb_header header;
  uint8_t pw_salt[32];
  uint8_t auth_salt[32];
} zlimdb_login_response;

typedef struct
{
  zlimdb_header header;
  uint8_t signature[32];
} zlimdb_auth_request;

typedef struct
{
  zlimdb_header header;
  uint32_t table_id;
} zlimdb_add_request;

typedef struct
{
  zlimdb_header header;
  uint64_t id;
} zlimdb_add_response;

typedef zlimdb_add_request zlimdb_update_request;
typedef zlimdb_add_request zlimdb_clear_request;
typedef zlimdb_add_request zlimdb_find_request;
typedef zlimdb_add_request zlimdb_reload_request;

typedef struct
{
  zlimdb_header header;
  uint32_t table_id;
  uint32_t destination_table_id;
} zlimdb_copy_request;

typedef zlimdb_copy_request zlimdb_rename_request;

typedef struct
{
  zlimdb_header header;
  uint32_t table_id;
  uint64_t id;
} zlimdb_remove_request;

typedef struct
{
  zlimdb_header header;
  uint32_t table_id;
  uint8_t type; ///< @see zlimdb_query_type
  uint64_t param;
} zlimdb_query_request;

typedef enum
{
  zlimdb_subscribe_flag_none = 0x00,
  zlimdb_subscribe_flag_responder = 0x01,
} zlimdb_subscribe_flag;

typedef struct
{
  zlimdb_query_request query;
  uint8_t flags; ///< @see zlimdb_subscribe_flag
} zlimdb_subscribe_request;

typedef struct
{
  zlimdb_header header;
  uint32_t table_id;
} zlimdb_unsubscribe_request;

typedef struct
{
  zlimdb_header header;
  uint32_t table_id;
} zlimdb_sync_request;

typedef struct
{
  zlimdb_header header;
  int64_t server_time;
  int64_t table_time;
} zlimdb_sync_response;

typedef struct
{
  zlimdb_header header;
  uint32_t table_id;
  uint64_t id;
  uint32_t control_code;
} zlimdb_control_request;

typedef zlimdb_add_response zlimdb_copy_response;
typedef zlimdb_add_response zlimdb_find_response;
typedef zlimdb_add_response zlimdb_rename_response;

typedef struct
{
  uint64_t id;
  uint64_t time;
  uint16_t size;
} zlimdb_entity;

typedef struct
{
  zlimdb_entity entity;
  uint8_t flags; // todo: flags like "private", "public"...
  uint16_t name_size;
} zlimdb_table_entity;

typedef struct
{
  zlimdb_entity entity;
  uint8_t pw_salt[32];
  uint8_t pw_hash[32];
} zlimdb_user_entity;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif // _ZLIMDB_PROTOCOL_H
