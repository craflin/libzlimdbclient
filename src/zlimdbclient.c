
#ifdef _WIN32
#include <winsock2.h>
#else
// todo
#endif
#include <assert.h>
#include <lz4.h>

#include "zlimdbclient.h"
#include "sha256.h"

#define ZLIMDB_DEFAULT_PORT 13211

#ifdef _WIN32
#define ERRNO WSAGetLastError()
#define SET_ERRNO(e) WSASetLastError(e)
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EINPROGRESS WSAEINPROGRESS
#define EINVAL WSAEINVAL
#define CLOSE closesocket
typedef int socklen_t;
#define MSG_NOSIGNAL 0
#else
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define ERRNO errno
#define SET_ERRNO(e) (errno = e)
#define CLOSE close
#define SOCKET_ERROR (-1)
#endif

typedef enum
{
  zlimdb_state_disconnected,
  zlimdb_state_connected,
  zlimdb_state_receiving_response,
  zlimdb_state_received_response,
  zlimdb_state_error,
} zlimdb_state;

struct _zlimdb
{
  zlimdb_state state;
  SOCKET socket;
#ifdef _WIN32
  HANDLE hInterruptEvent;
  HANDLE hReadEvent;
  DWORD selectedEvents;
#else
  // todo int interruptFd;
#endif
  zlimdb_callback callback;
  void* userData;
};

#ifdef _MSC_VER
static int __declspec(thread) zlimdbErrno = zlimdb_local_error_none;
#else
static int __thread zlimdbErrno = zlimdb_error_none;
#endif

static volatile long zlimdbInitCalls = 0;

int zlimdb_sendRequest(zlimdb* zdb, zlimdb_header* header);
int zlimdb_receiveHeader(zlimdb* zdb, zlimdb_header* header);
int zlimdb_receiveData(zlimdb* zdb, void* data, size_t size);
int zlimdb_receiveResponseData(zlimdb* zdb, const zlimdb_header* header, void* data, size_t size);
int zlimdb_receiveResponse(zlimdb* zdb, void* buffer, size_t size);
int zlimdb_receiveResponseOrMessage(zlimdb* zdb, void* buffer, size_t size);

int zlimdb_init()
{
#ifdef _WIN32
  if(InterlockedIncrement(&zlimdbInitCalls) == 1)
  {
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;
    if(WSAStartup(wVersionRequested, &wsaData) != 0)
    {
      InterlockedDecrement(&zlimdbInitCalls);
      return -1;
    }
  }
#endif
  return 0;
}

int zlimdb_cleanup()
{
#ifdef _WIN32
  if(InterlockedDecrement(&zlimdbInitCalls) == 0)
  {
    if(WSACleanup() != 0)
    {
      InterlockedIncrement(&zlimdbInitCalls);
      return -1;
    }
  }
#endif
  return 0;
}

zlimdb* zlimdb_create(zlimdb_callback callback, void* user_data)
{
  if(zlimdbInitCalls == 0)
  {
    zlimdbErrno = zlimdb_local_error_not_initialized;
    return 0;
  }
  zlimdb* zdb = malloc(sizeof(zlimdb));
  if(!zdb)
  {
    zlimdbErrno = zlimdb_local_error_out_of_memory;
    return 0;
  }
  zdb->socket = INVALID_SOCKET;
#ifdef _WIN32
  zdb->hInterruptEvent = WSA_INVALID_EVENT;
  zdb->hReadEvent = WSA_INVALID_EVENT;
  if((zdb->hInterruptEvent = WSACreateEvent()) == WSA_INVALID_EVENT ||
    (zdb->hReadEvent = WSACreateEvent()) == WSA_INVALID_EVENT)
  {
    zlimdb_free(zdb);
    return 0;
  }
  zdb->selectedEvents = 0;
#else
  // todo zdb->eventfd = eventfd();
  if(zdb->eventfd == 0)
  {
    free(zdb);
    return 0;
  }
#endif
  zdb->state = zlimdb_state_disconnected;
  zdb->socket = INVALID_SOCKET;
  zdb->callback = callback;
  zdb->userData = user_data;
  zlimdbErrno = zlimdb_local_error_none;
  return zdb;
}

int zlimdb_free(zlimdb* zdb)
{
  if(!zdb)
  {
    zlimdbErrno = zlimdb_local_error_invalid_parameter;
    return -1;
  }
  if(zdb->socket != INVALID_SOCKET)
    CLOSE(zdb->socket);
#ifdef _WIN32
  if(zdb->hInterruptEvent != WSA_INVALID_EVENT)
    WSACloseEvent(zdb->hInterruptEvent);
  if(zdb->hReadEvent != WSA_INVALID_EVENT)
    WSACloseEvent(zdb->hReadEvent);
#else
  // todo if(zdb->eventfd) close(zdb->eventfd);
#endif
  free(zdb);
  return 0;
}

int zlimdb_connect(zlimdb* zdb, const char* server, uint16_t port, const char* user_name, const char* password)
{
  if(!zdb)
  {
    zlimdbErrno = zlimdb_local_error_invalid_parameter;
    return -1;
  }
  if(zdb->state != zlimdb_state_disconnected)
  {
    zlimdbErrno = zlimdb_local_error_state;
    return -1;
  }
  assert(zdb->socket == INVALID_SOCKET);
#ifdef _WIN32
  zdb->socket = socket(AF_INET, SOCK_STREAM, 0);
#else
  zdb->socket = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
#endif
  if(zdb->socket == INVALID_SOCKET)
  {
    zlimdbErrno = zlimdb_local_error_socket;
    return -1;
  }

  struct sockaddr_in sin;
  memset(&sin,0,sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port ? port : ZLIMDB_DEFAULT_PORT);
  sin.sin_addr.s_addr = server ? inet_addr(server) : INADDR_LOOPBACK;
  if(sin.sin_addr.s_addr ==  INADDR_NONE)
  {
    zlimdbErrno = zlimdb_local_error_resolve;
    int err = ERRNO;
    CLOSE(zdb->socket);
    SET_ERRNO(err);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  if(connect(zdb->socket, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    zlimdbErrno = zlimdb_local_error_socket;
    int err = ERRNO;
    CLOSE(zdb->socket);
    SET_ERRNO(err);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  // send login request
  size_t usernameLen = strlen(user_name);
  zlimdb_login_request* loginRequest = _alloca(sizeof(zlimdb_login_request) + usernameLen);
  loginRequest->header.message_type = zlimdb_message_login_request;
  loginRequest->header.size = sizeof(zlimdb_login_request) + usernameLen;
  loginRequest->user_name_size = usernameLen;
  memcpy(loginRequest + 1, user_name, usernameLen);
  if(zlimdb_sendRequest(zdb, &loginRequest->header) != 0)
  {
    int err = ERRNO;
    CLOSE(zdb->socket);
    SET_ERRNO(err);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  // receive login response
  zlimdb_login_response loginResponse;
  if(zlimdb_receiveResponse(zdb, &loginResponse, sizeof(loginResponse)) != 0)
  {
    int err = ERRNO;
    CLOSE(zdb->socket);
    SET_ERRNO(err);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  // send auth request
  size_t passwordLen = strlen(password);
  zlimdb_auth_request authRequest;
  authRequest.header.message_type = zlimdb_message_auth_request;
  authRequest.header.size = sizeof(authRequest);
  uint8_t pwHash[32];
  sha256_hmac(loginResponse.pw_salt, sizeof(loginResponse.pw_salt), (const uint8_t*)password, passwordLen , pwHash);
  sha256_hmac(loginResponse.auth_salt, sizeof(loginResponse.auth_salt), pwHash, sizeof(pwHash), authRequest.signature);
  if(zlimdb_sendRequest(zdb, &authRequest.header) != 0)
  {
    int err = ERRNO;
    CLOSE(zdb->socket);
    SET_ERRNO(err);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  // receive auth response
  zlimdb_header authReponse;
  if(zlimdb_receiveResponse(zdb, &authReponse, sizeof(authReponse)) != 0)
  {
    int err = ERRNO;
    CLOSE(zdb->socket);
    SET_ERRNO(err);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  zdb->state = zlimdb_state_connected;
  zlimdbErrno = zlimdb_local_error_none;
  return 0;
}

int zlimdb_errno(zlimdb* zdb)
{
  return zlimdbErrno;
}

const char* zlimdb_strerror(int errnum)
{
  switch(errnum)
  {
  // libzlimdbclient errors
  case zlimdb_local_error_none: return "Success";
  case zlimdb_local_error_invalid_parameter: return "Invalid parameter";
  case zlimdb_local_error_not_initialized: return "Not initialized";
  case zlimdb_local_error_out_of_memory: return "Out of memory";
  case zlimdb_local_error_state: return "State error";
  case zlimdb_local_error_socket: return "Socket error";
  case zlimdb_local_error_resolve: return "Hostname could not be resolved";
  case zlimdb_local_error_interrupted: return "Operation was interruped";
  case zlimdb_local_error_timeout: return "Operation has timed out";
  case zlimdb_local_error_invalid_message_size: return "Received invalid message";
  case zlimdb_local_error_buffer_size: return "Buffer was too small";
  case zlimdb_local_error_connection_closed: return "Connection was closed";

  // client protocol errors:
  case zlimdb_error_invalid_message_size: return "Invalid message size";
  case zlimdb_error_invalid_message_type: return "invalid message type";
  case zlimdb_error_entity_not_found: return "Entity not found";
  case zlimdb_error_table_not_found: return "Table not found";
  case zlimdb_error_not_implemented: return "Operation not implemented";
  case zlimdb_error_invalid_request: return "Invalid request";
  case zlimdb_error_invalid_login: return "Invalid login data";
  case zlimdb_error_open_file: return "Could not open file";
  case zlimdb_error_read_file: return "Could not read from file";
  case zlimdb_error_write_file: return "Could not write to file";
  case zlimdb_error_subscription_not_found: "Subscription not found";
  case zlimdb_error_invalid_message_data: return "Invalid message data";

  default: return "Unknown error";
  }
}

int zlimdb_add_table(zlimdb* zdb, const char* name, uint64_t* table_id)
{
  if(!zdb)
  {
    zlimdbErrno = zlimdb_local_error_invalid_parameter;
    return -1;
  }
  if(zdb->state != zlimdb_state_connected)
  {
    zlimdbErrno = zlimdb_local_error_state;
    return -1;
  }

  // create message
  size_t nameLen = strlen(name);
  zlimdb_add_request* addRequest = _alloca(sizeof(zlimdb_add_request) + sizeof(zlimdb_table_entity) + nameLen);
  addRequest->header.message_type = zlimdb_message_add_request;
  addRequest->header.size = sizeof(zlimdb_add_request) + sizeof(zlimdb_table_entity) + nameLen;
  addRequest->table_id = zlimdb_table_tables;
  zlimdb_table_entity* tableEntity = (zlimdb_table_entity*)(addRequest + 1);
  tableEntity->entity.id = 0;
  tableEntity->entity.time = 0;
  tableEntity->entity.size = sizeof(zlimdb_table_entity) + nameLen;
  tableEntity->name_size = nameLen;
  tableEntity->flags = 0;
  memcpy(tableEntity + 1, name, nameLen);

  // send message
  if(zlimdb_sendRequest(zdb, &addRequest->header) != 0)
    return -1;

  // receive response
  zlimdb_add_response addResponse;
  if(zlimdb_receiveResponseOrMessage(zdb, &addResponse, sizeof(addResponse)) != 0)
    return -1;
  if(table_id)
    *table_id = addResponse.id;
  zlimdbErrno = zlimdb_local_error_none;
  return 0;
}

int zlimdb_add(zlimdb* zdb, uint32_t table_id, const void* data, uint32_t size)
{
  if(!zdb)
  {
    zlimdbErrno = zlimdb_local_error_invalid_parameter;
    return -1;
  }
  if(zdb->state != zlimdb_state_connected)
  {
    zlimdbErrno = zlimdb_local_error_state;
    return -1;
  }

  // create message
  zlimdb_add_request* addRequest = _alloca(sizeof(zlimdb_add_request) + size);
  addRequest->header.message_type = zlimdb_message_add_request;
  addRequest->header.size = sizeof(zlimdb_add_request) + size;
  addRequest->table_id = table_id;
  memcpy(addRequest + 1, data, size);

  // send message
  if(zlimdb_sendRequest(zdb, &addRequest->header) != 0)
    return -1;

  // receive response
  zlimdb_add_response addResponse;
  if(zlimdb_receiveResponseOrMessage(zdb, &addResponse, sizeof(addResponse)) != 0)
    return -1;
  zlimdbErrno = zlimdb_local_error_none;
  return 0;
}

int zlimdb_query(zlimdb* zdb, uint32_t table_id, zlimdb_query_type type, uint64_t param)
{
  if(!zdb)
  {
    zlimdbErrno = zlimdb_local_error_invalid_parameter;
    return -1;
  }
  if(zdb->state != zlimdb_state_connected)
  {
    zlimdbErrno = zlimdb_local_error_state;
    return -1;
  }

  // create message
  zlimdb_query_request queryRequest;
  queryRequest.header.message_type = zlimdb_message_query_request;
  queryRequest.header.size = sizeof(queryRequest);
  queryRequest.table_id = table_id;
  queryRequest.type = type;
  queryRequest.param = param;

  // send message
  if(zlimdb_sendRequest(zdb, &queryRequest.header) != 0)
    return -1;

  zdb->state = zlimdb_state_receiving_response;
  zlimdbErrno = zlimdb_local_error_none;
  return 0;
}

int zlimdb_subscribe(zlimdb* zdb, uint32_t table_id, zlimdb_query_type type, uint64_t param)
{
  if(!zdb)
  {
    zlimdbErrno = zlimdb_local_error_invalid_parameter;
    return -1;
  }
  if(zdb->state != zlimdb_state_connected)
  {
    zlimdbErrno = zlimdb_local_error_state;
    return -1;
  }

  // create message
  zlimdb_query_request subscribeRequest;
  subscribeRequest.header.message_type = zlimdb_message_subscribe_request;
  subscribeRequest.header.size = sizeof(subscribeRequest);
  subscribeRequest.table_id = table_id;
  subscribeRequest.type = type;
  subscribeRequest.param = param;

  // send message
  if(zlimdb_sendRequest(zdb, &subscribeRequest.header) != 0)
    return -1;

  zdb->state = zlimdb_state_receiving_response;
  zlimdbErrno = zlimdb_local_error_none;
  return 0;
}


int zlimdb_get_response(zlimdb* zdb, void* data, uint32_t maxSize2, uint32_t* size2)
{
  if(!zdb)
  {
    zlimdbErrno = zlimdb_local_error_invalid_parameter;
    return -1;
  }
  switch(zdb->state)
  {
  case zlimdb_state_receiving_response:
    break;
  case zlimdb_state_received_response:
    zdb->state = zlimdb_state_connected;
    zlimdbErrno = zlimdb_local_error_none;
    return -1;
  default:
    zlimdbErrno = zlimdb_local_error_state;
    return -1;
  }

  // receive response
  zlimdb_header header;
  for(;;)
  {
    if(zlimdb_receiveHeader(zdb, &header) != 0)
      return -1;
    if(header.request_id == 1)
    {
      if(header.flags & zlimdb_header_flag_compressed)
      {
        size_t dataSize = header.size - sizeof(header);
        if(dataSize < sizeof(uint16_t))
        {
          zdb->state = zlimdb_state_error;
          zlimdbErrno = zlimdb_local_error_invalid_message_data;
          return -1;
        }
        void* buffer = _alloca(dataSize);
        if(zlimdb_receiveResponseData(zdb, &header, buffer, dataSize) != 0)
            return -1;
        uint16_t rawDataSize = *(const uint16_t*)buffer;
        if(rawDataSize > 0)
        {
          if(rawDataSize > maxSize2)
          {
            zdb->state = zlimdb_state_error;
            zlimdbErrno = zlimdb_local_error_buffer_size;
            return -1;
          }
          if(LZ4_decompress_safe((char*)buffer + sizeof(uint16_t), (char*)data, dataSize - sizeof(uint16_t), rawDataSize) != rawDataSize)
          {
            zdb->state = zlimdb_state_error;
            zlimdbErrno = zlimdb_local_error_invalid_message_data;
            return -1;
          }
        }
        *size2 = rawDataSize;
      }
      else
      {
        assert(!(header.flags & zlimdb_header_flag_compressed));
        if(zlimdb_receiveResponseData(zdb, &header, data, maxSize2) != 0)
          return -1;
        *size2 = header.size - sizeof(header);
      }
      if(!(header.flags & zlimdb_header_flag_fragmented))
        zdb->state = zlimdb_state_received_response;
      zlimdbErrno = zlimdb_local_error_none;
      return 0;
    }
    else
    {
      size_t bufferSize = header.size;
      void* buffer = _alloca(bufferSize);
      if(zlimdb_receiveData(zdb, (char*)buffer + sizeof(header), bufferSize - sizeof(header)) != 0)
          return -1; 
      if(zdb->callback)
      {
        *(zlimdb_header*)buffer = header;
        zdb->callback(zdb->userData, buffer, bufferSize);
      }
    }
  }
}

int zlimdb_sync(zlimdb* zdb, uint32_t table_id, int64_t* server_time, int64_t* table_time)
{
  if(!zdb)
  {
    zlimdbErrno = zlimdb_local_error_invalid_parameter;
    return -1;
  }
  if(zdb->state != zlimdb_state_connected)
  {
    zlimdbErrno = zlimdb_local_error_state;
    return -1;
  }

  // create message
  zlimdb_sync_request syncRequest;
  syncRequest.header.message_type = zlimdb_message_sync_request;
  syncRequest.header.size = sizeof(syncRequest);
  syncRequest.table_id = table_id;

  // send message
  if(zlimdb_sendRequest(zdb, &syncRequest.header) != 0)
    return -1;

  // receive response
  zlimdb_sync_response syncResponse;
  if(zlimdb_receiveResponseOrMessage(zdb, &syncResponse, sizeof(syncResponse)) != 0)
    return -1;
  if(server_time)
    *server_time = syncResponse.server_time;
  if(table_time)
    *table_time = syncResponse.table_time;
  zlimdbErrno = zlimdb_local_error_none;
  return 0;
}

int zlimdb_exec(zlimdb* zdb, unsigned int timeout)
{
  if(!zdb)
  {
    zlimdbErrno = zlimdb_local_error_invalid_parameter;
    return -1;
  }
  if(zdb->state != zlimdb_state_connected)
  {
    zlimdbErrno = zlimdb_local_error_state;
    return -1;
  }

#ifdef _WIN32
  if(zdb->selectedEvents == 0)
  {
    if(WSAEventSelect(zdb->socket, zdb->hReadEvent, FD_READ| FD_CLOSE) == SOCKET_ERROR)
    {
      zdb->state = zlimdb_state_error;
      zlimdbErrno = zlimdb_local_error_socket;
      int err = ERRNO;
      CLOSE(zdb->socket);
      SET_ERRNO(err);
      zdb->socket = INVALID_SOCKET;
      return -1;
    }
  }

  DWORD currentTick = GetTickCount();
  DWORD startTick = currentTick;
  do
  {
    HANDLE handles[] = {zdb->hReadEvent, zdb->hInterruptEvent};
    DWORD passedTicks = currentTick - startTick;
    switch(passedTicks <= timeout ? WaitForMultipleObjects(2, handles, FALSE, timeout - passedTicks) : WAIT_TIMEOUT)
    {
    case WAIT_OBJECT_0:
      break;
    case WAIT_OBJECT_0 + 1:
      WSAResetEvent(zdb->hInterruptEvent);
      zlimdbErrno = zlimdb_local_error_interrupted;
      return -1;
    case WAIT_TIMEOUT:
      zlimdbErrno = zlimdb_local_error_timeout;
      return -1;
    }
    WSANETWORKEVENTS events;
    if(WSAEnumNetworkEvents(zdb->socket, zdb->hReadEvent, &events) == SOCKET_ERROR)
    {
      zdb->state = zlimdb_state_error;
      zlimdbErrno = zlimdb_local_error_socket;
      return -1;
    }
    zlimdb_header header;
    if(zlimdb_receiveHeader(zdb, &header) != 0)
      return -1;
    assert(!(header.flags & zlimdb_header_flag_compressed));
    size_t bufferSize = header.size;
    void* buffer = _alloca(bufferSize);
    if(zlimdb_receiveData(zdb, (char*)buffer + sizeof(header), bufferSize - sizeof(header)) != 0)
      return -1;
    if(zdb->callback)
    {
      *(zlimdb_header*)buffer = header;
      zdb->callback(zdb->userData, buffer, bufferSize);
    }
    currentTick = GetTickCount();
  } while(zdb->state == zlimdb_state_connected);
#else
  // todo
#endif
  return -1;
}

int zlimdb_interrupt(zlimdb* zdb)
{
  if(!zdb)
  {
    zlimdbErrno = zlimdb_local_error_invalid_parameter;
    return -1;
  }
#ifdef _WIN32
  if(!WSASetEvent(zdb->hInterruptEvent))
  {
    zlimdbErrno = zlimdb_local_error_socket;
    return -1;
  }
#else
  // todo
#endif
  zlimdbErrno = zlimdb_local_error_none;
  return 0;
}

int zlimdb_sendRequest(zlimdb* zdb, zlimdb_header* header)
{
  header->flags = 0;
  header->request_id = 1;
  assert(header->size >= sizeof(*header));
  unsigned int sentSize = 0;
  for(;;)
  {
    int res = send(zdb->socket, (const char*)header + sentSize, header->size - sentSize, 0);
    if(res < 0)
    {
#ifdef _WIN32
      if(ERRNO == WSAEWOULDBLOCK)
      {
        WSAEventSelect(zdb->socket, NULL, 0);
        u_long val = 0;
        if(ioctlsocket(zdb->socket, FIONBIO, &val) != 0)
        {
          zdb->state = zlimdb_state_error;
          zlimdbErrno = zlimdb_local_error_socket;
          return -1;
        }
        zdb->selectedEvents = 0;
        continue;
      }
#endif
      zdb->state = zlimdb_state_error;
      zlimdbErrno = zlimdb_local_error_socket;
      return -1;
    }
    return 0;
  } while(sentSize < header->size);
}

int zlimdb_receiveHeader(zlimdb* zdb, zlimdb_header* header)
{
  if(zlimdb_receiveData(zdb, header, sizeof(*header)) != 0)
    return -1;
  if(header->size < sizeof(zlimdb_header))
  {
    zdb->state = zlimdb_state_error;
    zlimdbErrno = zlimdb_local_error_invalid_message_size;
    return -1;
  }
  return 0;
}

int zlimdb_receiveData(zlimdb* zdb, void* data, size_t size)
{
  unsigned int receivedSize = 0;
  while(receivedSize < size)
  {
    int res = recv(zdb->socket, (char*)data + receivedSize, size - receivedSize, 0);
    if(res == 0)
    {
      zdb->state = zlimdb_state_error;
      zlimdbErrno = zlimdb_local_error_connection_closed;
      return -1;
    }
    else if(res < 0)
    {
#ifdef _WIN32
      if(ERRNO == WSAEWOULDBLOCK)
      {
        WSAEventSelect(zdb->socket, NULL, 0);
        u_long val = 0;
        if(ioctlsocket(zdb->socket, FIONBIO, &val) != 0)
        {
          zdb->state = zlimdb_state_error;
          zlimdbErrno = zlimdb_local_error_socket;
          return -1;
        }
        zdb->selectedEvents = 0;
        continue;
      }
#endif
      zdb->state = zlimdb_state_error;
      zlimdbErrno = zlimdb_local_error_socket;
      return -1;
    }
    receivedSize += res;
  }
  return 0;
}

int zlimdb_receiveResponseData(zlimdb* zdb, const zlimdb_header* header, void* data, size_t size)
{
  if(header->message_type == zlimdb_message_error_response)
  {
    if(header->size != sizeof(zlimdb_error_response))
    {
      zdb->state = zlimdb_state_error;
      zlimdbErrno = zlimdb_local_error_invalid_message_size;
      return -1;
    }
    zlimdb_error_response errorResponse;
    if(zlimdb_receiveData(zdb, (char*)&errorResponse + sizeof(*header), sizeof(errorResponse) - sizeof(*header)) != 0)
      return -1;
    zlimdbErrno = errorResponse.error;
    return -1;
  }
  size_t dataSize = header->size - sizeof(*header);
  if(dataSize > size)
  {
    zdb->state = zlimdb_state_error;
    zlimdbErrno = zlimdb_local_error_buffer_size;
    return -1;
  }
  if(zlimdb_receiveData(zdb, data, dataSize) != 0)
    return -1;
  return 0;

}

int zlimdb_receiveResponse(zlimdb* zdb, void* buffer, size_t size)
{
  assert(size >= sizeof(zlimdb_header));
  zlimdb_header* header = buffer;
  if(zlimdb_receiveHeader(zdb, header) != 0)
    return -1;
  if(header->request_id != 1)
  {
    zdb->state = zlimdb_state_error;
    zlimdbErrno = zlimdb_local_error_invalid_message_size;
    return -1;
  }
  return zlimdb_receiveResponseData(zdb, header, (char*)buffer + sizeof(*header), size - sizeof(*header));
}

int zlimdb_receiveResponseOrMessage(zlimdb* zdb, void* buffer, size_t size)
{
  assert(size >= sizeof(zlimdb_header));
  zlimdb_header* header = buffer;
  for(;;)
  {
    if(zlimdb_receiveHeader(zdb, header) != 0)
      return -1;
    if(header->request_id == 1)
      return zlimdb_receiveResponseData(zdb, header, (char*)buffer + sizeof(*header), size - sizeof(*header));
    else
    {
      size_t bufferSize = header->size;
      void* buffer = _alloca(bufferSize);
      if(zlimdb_receiveData(zdb, (char*)buffer +  sizeof(*header), bufferSize - sizeof(*header)) != 0)
          return -1; 
      if(zdb->callback)
      {
        *(zlimdb_header*)buffer = *header;
        zdb->callback(zdb->userData, buffer, bufferSize);
      }
    }
  }
}
