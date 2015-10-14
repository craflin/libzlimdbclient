
#ifdef _WIN32
#include <winsock2.h>
#else
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/eventfd.h>
#include <poll.h>
#endif
#include <assert.h>
#include <time.h>
#include <lz4.h>

#include "zlimdbclient.h"
#include "sha256.h"

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
  _zlimdb_state_disconnected,
  _zlimdb_state_connected,
  _zlimdb_state_error,
} _zlimdb_state;

typedef struct _zlimdb_responseData_ _zlimdb_responseData;
struct _zlimdb_responseData_
{
  _zlimdb_responseData* next;
  _zlimdb_responseData* last;
};

typedef enum
{
  _zlimdb_requestState_receiving,
  _zlimdb_requestState_finished,
  _zlimdb_requestState_internal,
} _zlimdb_requestState;

typedef struct _zlimdb_requestData_ _zlimdb_requestData;
struct _zlimdb_requestData_
{
  uint32_t requestId;
  _zlimdb_requestState state;
  _zlimdb_responseData* response;
  _zlimdb_requestData* next;
};

struct _zlimdb_
{
  _zlimdb_state state;
  SOCKET socket;
#ifdef _WIN32
  HANDLE hInterruptEvent;
  HANDLE hReadEvent;
  DWORD selectedEvents;
#else
  int interruptEventFd;
#endif
  zlimdb_callback callback;
  void* userData;
  uint32_t lastRequestId;
  _zlimdb_requestData* openRequest;
  _zlimdb_requestData* unusedRequest;
  _zlimdb_requestData requestData;
};

#ifdef _MSC_VER
static int __declspec(thread) zlimdbErrno = zlimdb_local_error_none;
#else
static int __thread zlimdbErrno = zlimdb_local_error_none;
#endif

static volatile long zlimdbInitCalls = 0;

static void _zlimdb_freeReponses(_zlimdb_responseData* response)
{
  for(_zlimdb_responseData* next; response; response = next)
  {
    next = response->next;
    free(response);
  }
}

static int _zlimdb_sendRequest(zlimdb* zdb, zlimdb_header* header)
{
  assert(zdb);
  assert(header->size >= sizeof(zlimdb_header));

  header->flags = 0;

#ifdef _WIN32
  unsigned int sentSize = 0;
  do
  {
    int res = send(zdb->socket, (const char*)header + sentSize, header->size - sentSize, 0);
    if(res < 0)
    {
      if(ERRNO == WSAEWOULDBLOCK)
      {
        if(zdb->selectedEvents)
        {
          WSAEventSelect(zdb->socket, zdb->hReadEvent, 0);
          zdb->selectedEvents = 0;
        }
        u_long val = 0;
        if(ioctlsocket(zdb->socket, FIONBIO, &val) != 0)
        {
          zdb->state = _zlimdb_state_error;
          return zlimdbErrno = zlimdb_local_error_system, -1;
        }
        continue;
      }
      zdb->state = _zlimdb_state_error;
      return zlimdbErrno = zlimdb_local_error_system, -1;
    }
    sentSize += res;
  } while(sentSize < header->size);
#else
  int res = send(zdb->socket, (const char*)header, header->size, 0);
  if(res < 0)
  {
    zdb->state = zlimdb_state_error;
    return zlimdbErrno = zlimdb_local_error_system, -1;
  }
  assert(res == header->size);
#endif
  return 0;
}

static int _zlimdb_receiveData(zlimdb* zdb, void* data, size_t size)
{
  assert(zdb);
  assert(data);

  unsigned int receivedSize = 0;
  while(receivedSize < size)
  {
    int res = recv(zdb->socket, (char*)data + receivedSize, size - receivedSize, 0);
    if(res == 0)
    {
      zdb->state = _zlimdb_state_error;
      return zlimdbErrno = zlimdb_local_error_connection_closed, -1;
    }
    else if(res < 0)
    {
#ifdef _WIN32
      if(ERRNO == WSAEWOULDBLOCK)
      {
        if(zdb->selectedEvents)
        {
          WSAEventSelect(zdb->socket, zdb->hReadEvent, 0);
          zdb->selectedEvents = 0;
        }
        u_long val = 0;
        if(ioctlsocket(zdb->socket, FIONBIO, &val) != 0)
        {
          zdb->state = _zlimdb_state_error;
          return zlimdbErrno = zlimdb_local_error_system, -1;
        }
        continue;
      }
#endif
      zdb->state = _zlimdb_state_error;
      return zlimdbErrno = zlimdb_local_error_system, -1;
    }
    receivedSize += res;
  }
  return 0;
}

static int _zlimdb_receiveHeader(zlimdb* zdb, zlimdb_header* header)
{
  assert(zdb);
  assert(header);

  if(_zlimdb_receiveData(zdb, header, sizeof(zlimdb_header)) != 0)
    return -1;
  if(header->size < sizeof(zlimdb_header))
  {
    zdb->state = _zlimdb_state_error;
    return zlimdbErrno = zlimdb_local_error_invalid_message_data, -1;
  }
  return 0;
}

static int _zlimdb_receiveResponseData(zlimdb* zdb, const zlimdb_header* header, void* data, size_t maxSize)
{
  assert(zdb);
  assert(header);
  assert(data);

  if(header->message_type == zlimdb_message_error_response)
  {
    if(header->size != sizeof(zlimdb_error_response))
    {
      zdb->state = _zlimdb_state_error;
      return zlimdbErrno = zlimdb_local_error_invalid_message_data, -1;
    }
    zlimdb_error_response errorResponse;
    if(_zlimdb_receiveData(zdb, &errorResponse.header + 1, sizeof(errorResponse) - sizeof(zlimdb_header)) != 0)
      return -1;
    return zlimdbErrno = errorResponse.error, -1;
  }
  size_t dataSize = header->size - sizeof(zlimdb_header);
  if(dataSize > 0)
  {
    if(dataSize > maxSize)
    {
      zdb->state = _zlimdb_state_error;
      return zlimdbErrno = zlimdb_local_error_buffer_size, -1;
    }
    if(_zlimdb_receiveData(zdb, data, dataSize) != 0)
      return -1;
  }
  return 0;
}

static int _zlimdb_copyResponseData(zlimdb* zdb, const _zlimdb_responseData* response, void* data, size_t maxSize)
{
  assert(zdb);
  assert(response);
  assert(data);

  const zlimdb_header* header = (const zlimdb_header*)(response + 1);
  if(header->message_type == zlimdb_message_error_response)
  {
    if(header->size != sizeof(zlimdb_error_response))
    {
      zdb->state = _zlimdb_state_error;
      return zlimdbErrno = zlimdb_local_error_invalid_message_data, -1;
    }
    return zlimdbErrno = ((const zlimdb_error_response*)header)->error, -1;
  }
  size_t dataSize = header->size - sizeof(zlimdb_header);
  if(dataSize > 0)
  {
    if(dataSize > maxSize)
    {
      zdb->state = _zlimdb_state_error;
      return zlimdbErrno = zlimdb_local_error_buffer_size, -1;
    }
    memcpy(data, header + 1, dataSize);
  }
  return 0;
}

static int _zlimdb_receiveLoginResponse(zlimdb* zdb, void* message, size_t size)
{
  assert(zdb);
  assert(message);
  assert(size >= sizeof(zlimdb_header));

  zlimdb_header* header = message;
  if(_zlimdb_receiveHeader(zdb, header) != 0)
    return -1;
  if(header->request_id != 1 || header->flags)
  {
    zdb->state = _zlimdb_state_error;
    return zlimdbErrno = zlimdb_local_error_invalid_response, -1;
  }
  if(_zlimdb_receiveResponseData(zdb, header, header + 1, size - sizeof(zlimdb_header)) != 0)
    return -1;
  return 0;
}

static int _zlimdb_receiveResponse(zlimdb* zdb, uint32_t requestId, void* message, size_t maxSize)
{
  assert(zdb);
  assert(requestId);
  assert(message);
  assert(maxSize >= sizeof(zlimdb_header));

  // receive new response
  zlimdb_header* header = message;
  for(;;)
  {
    if(_zlimdb_receiveHeader(zdb, header) != 0)
      return -1;
    if(header->request_id == requestId)
      return _zlimdb_receiveResponseData(zdb, header, header + 1, maxSize - sizeof(zlimdb_header));
    else if(header->request_id)
    {
      _zlimdb_requestData* request;
      for(request = zdb->openRequest; request; request = request->next)
        if(request->requestId == header->request_id)
          goto receiveResponse;
      zdb->state = _zlimdb_state_error;
      return zlimdbErrno = zlimdb_local_error_invalid_response, -1;
    receiveResponse: ;

      _zlimdb_responseData* response = malloc(sizeof(_zlimdb_responseData) + header->size);
      if(!response)
      {
        zdb->state = _zlimdb_state_error;
        return zlimdbErrno = zlimdb_local_error_system, -1;
      }
      void* buffer = response + 1;
      if(_zlimdb_receiveData(zdb, (zlimdb_header*)buffer + 1, header->size - sizeof(zlimdb_header)) != 0)
          return -1;
      *(zlimdb_header*)buffer = *header;
      response->next = 0;
      if(request->response)
      {
        request->response->last->next = response;
        request->response->last = response;
      }
      else
      {
        request->response = response;
        response->last = response;
      }
    }
    else
    {
      char buffer[ZLIMDB_MAX_MESSAGE_SIZE];
      if(_zlimdb_receiveData(zdb, (zlimdb_header*)buffer + 1, header->size - sizeof(zlimdb_header)) != 0)
          return -1; 
      if(zdb->callback)
      {
        *(zlimdb_header*)buffer = *header;

        _zlimdb_requestData request;
        request.requestId = requestId;
        request.response = 0;
        request.next = zdb->openRequest;
        request.state = _zlimdb_requestState_internal;
        zdb->openRequest = &request;
        zdb->callback(zdb->userData, (zlimdb_header*)buffer);
        zdb->openRequest = request.next;

        if(request.response)
        {
          if(_zlimdb_copyResponseData(zdb, request.response, header + 1, maxSize - sizeof(zlimdb_header)) != 0);
          {
            _zlimdb_freeReponses(request.response);
            return -1;
          }
          *header = *(zlimdb_header*)(request.response + 1);
          _zlimdb_freeReponses(request.response);
          return 0;
        }
      }
    }
  }
}


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
      return zlimdbErrno = zlimdb_local_error_system, -1;
    }
  }
#else
  __sync_add_and_fetch(&zlimdbInitCalls, 1);
#endif
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_cleanup()
{
#ifdef _WIN32
  if(InterlockedDecrement(&zlimdbInitCalls) == 0)
  {
    if(WSACleanup() != 0)
    {
      InterlockedIncrement(&zlimdbInitCalls);
      return zlimdbErrno = zlimdb_local_error_system, -1;
    }
  }
#else
  __sync_add_and_fetch(&zlimdbInitCalls, -1);
#endif
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

zlimdb* zlimdb_create(zlimdb_callback callback, void* userData)
{
  if(zlimdbInitCalls == 0)
    return zlimdbErrno = zlimdb_local_error_not_initialized, 0;

  zlimdb* zdb = malloc(sizeof(zlimdb));
  if(!zdb)
    return zlimdbErrno = zlimdb_local_error_system, 0;

  zdb->lastRequestId = 0;
  zdb->openRequest = 0;
  zdb->requestData.next = 0;
  zdb->unusedRequest = &zdb->requestData;
  zdb->socket = INVALID_SOCKET;
#ifdef _WIN32
  zdb->hInterruptEvent = WSA_INVALID_EVENT;
  zdb->hReadEvent = WSA_INVALID_EVENT;
  if((zdb->hInterruptEvent = WSACreateEvent()) == WSA_INVALID_EVENT ||
    (zdb->hReadEvent = WSACreateEvent()) == WSA_INVALID_EVENT)
  {
    zlimdb_free(zdb);
    return zlimdbErrno = zlimdb_local_error_system, 0;
  }
  zdb->selectedEvents = 0;
#else
  zdb->interruptEventFd = eventfd(0, EFD_CLOEXEC);
  if(zdb->interruptEventFd == INVALID_SOCKET)
  {
    zlimdb_free(zdb);
    return zlimdbErrno = zlimdb_local_error_system, 0;
  }
#endif
  zdb->state = _zlimdb_state_disconnected;
  zdb->callback = callback;
  zdb->userData = userData;
  return zlimdbErrno = zlimdb_local_error_none, zdb;
}

int zlimdb_free(zlimdb* zdb)
{
  if(!zdb)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->socket != INVALID_SOCKET)
    CLOSE(zdb->socket);
#ifdef _WIN32
  if(zdb->hInterruptEvent != WSA_INVALID_EVENT)
    WSACloseEvent(zdb->hInterruptEvent);
  if(zdb->hReadEvent != WSA_INVALID_EVENT)
    WSACloseEvent(zdb->hReadEvent);
#else
  if(zdb->interruptEventFd != INVALID_SOCKET)
    CLOSE(zdb->interruptEventFd);
#endif
  {
    for(_zlimdb_requestData* i = zdb->openRequest, * next; i; i = next)
    {
      next = i->next;
      _zlimdb_freeReponses(i->response);
      if(i != &zdb->requestData)
        free(i);
    }
    for(_zlimdb_requestData* i = zdb->unusedRequest, * next; i; i = next)
    {
      next = i->next;
      if(i != &zdb->requestData)
        free(i);
    }
  }
  free(zdb);
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_connect(zlimdb* zdb, const char* server, uint16_t port, const char* userName, const char* password)
{
  if(!zdb || !server || !userName || !password)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;
  size_t userNameLen = strlen(userName);
  if(userNameLen > ZLIMDB_MAX_MESSAGE_SIZE - sizeof(zlimdb_login_request))
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_disconnected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  assert(zdb->socket == INVALID_SOCKET);
#ifdef _WIN32
  zdb->socket = socket(AF_INET, SOCK_STREAM, 0);
#else
  zdb->socket = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
#endif
  if(zdb->socket == INVALID_SOCKET)
    return zlimdbErrno = zlimdb_local_error_system, -1;

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port ? port : ZLIMDB_DEFAULT_PORT);
  sin.sin_addr.s_addr = server ? inet_addr(server) : htonl(INADDR_LOOPBACK);
  if(ntohl(sin.sin_addr.s_addr) ==  INADDR_NONE)
  {
    int err = ERRNO;
    CLOSE(zdb->socket);
    SET_ERRNO(err);
    zdb->socket = INVALID_SOCKET;
    return zlimdbErrno = zlimdb_local_error_resolve, -1;
  }

  if(connect(zdb->socket, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    int err = ERRNO;
    CLOSE(zdb->socket);
    SET_ERRNO(err);
    zdb->socket = INVALID_SOCKET;
    return zlimdbErrno = zlimdb_local_error_system, -1;
  }

  // send login request
  char buffer[ZLIMDB_MAX_MESSAGE_SIZE];
  zlimdb_login_request* loginRequest = (zlimdb_login_request*)buffer;
  loginRequest->header.size = sizeof(zlimdb_login_request) + userNameLen;
  loginRequest->header.message_type = zlimdb_message_login_request;
  loginRequest->header.request_id = 1;
  loginRequest->user_name_size = userNameLen;
  memcpy(loginRequest + 1, userName, userNameLen);
  if(_zlimdb_sendRequest(zdb, &loginRequest->header) != 0)
  {
    int err = ERRNO;
    CLOSE(zdb->socket);
    SET_ERRNO(err);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  // receive login response
  zlimdb_login_response loginResponse;
  if(_zlimdb_receiveLoginResponse(zdb, &loginResponse, sizeof(zlimdb_login_response)) != 0)
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
  authRequest.header.size = sizeof(zlimdb_auth_request);
  authRequest.header.message_type = zlimdb_message_auth_request;
  authRequest.header.request_id = 1;
  uint8_t pwHash[32];
  sha256_hmac(loginResponse.pw_salt, sizeof(loginResponse.pw_salt), (const uint8_t*)password, passwordLen , pwHash);
  sha256_hmac(loginResponse.auth_salt, sizeof(loginResponse.auth_salt), pwHash, sizeof(pwHash), authRequest.signature);
  if(_zlimdb_sendRequest(zdb, &authRequest.header) != 0)
  {
    int err = ERRNO;
    CLOSE(zdb->socket);
    SET_ERRNO(err);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  // receive auth response
  zlimdb_header authReponse;
  if(_zlimdb_receiveLoginResponse(zdb, &authReponse, sizeof(zlimdb_header)) != 0)
  {
    int err = ERRNO;
    CLOSE(zdb->socket);
    SET_ERRNO(err);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  zdb->state = _zlimdb_state_connected;
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_is_connected(zlimdb* zdb)
{
  if(!zdb)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  zlimdbErrno = zlimdb_local_error_none;
  if(zdb->state != _zlimdb_state_connected)
    return -1;
  return 0;
}

int zlimdb_errno()
{
  return zlimdbErrno;
}

void zlimdb_seterrno(int errnum)
{
  zlimdbErrno = errnum;
}

const char* zlimdb_strerror(int errnum)
{
  switch(errnum)
  {
  // libzlimdbclient errors
  case zlimdb_local_error_none: return "Success";
  case zlimdb_local_error_system: return "System error";
  case zlimdb_local_error_invalid_parameter: return "Invalid parameter";
  case zlimdb_local_error_not_initialized: return "Not initialized";
  case zlimdb_local_error_state: return "State error";
  case zlimdb_local_error_resolve: return "Hostname could not be resolved";
  case zlimdb_local_error_interrupted: return "Operation was interruped";
  case zlimdb_local_error_timeout: return "Operation has timed out";
  case zlimdb_local_error_invalid_message_data: return "Received invalid message data";
  case zlimdb_local_error_invalid_response: return "Received invalid response";
  case zlimdb_local_error_buffer_size: return "Buffer was too small";
  case zlimdb_local_error_connection_closed: return "Connection was closed";

  // client protocol errors:
  case zlimdb_error_invalid_message_data: return "Invalid message data";
  case zlimdb_error_invalid_message_type: return "invalid message type";
  case zlimdb_error_entity_not_found: return "Entity not found";
  case zlimdb_error_table_not_found: return "Table not found";
  case zlimdb_error_not_implemented: return "Operation not implemented";
  case zlimdb_error_invalid_request: return "Invalid request";
  case zlimdb_error_invalid_login: return "Invalid login data";
  case zlimdb_error_open_file: return "Could not open file";
  case zlimdb_error_read_file: return "Could not read from file";
  case zlimdb_error_write_file: return "Could not write to file";
  case zlimdb_error_subscription_not_found: return "Subscription not found";
  case zlimdb_error_table_already_exists: return "Table already exists";

  default: return "Unknown error";
  }
}

int zlimdb_add_table(zlimdb* zdb, const char* name, uint32_t* tableId)
{
  if(!zdb || !name)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;
  size_t nameLen = strlen(name);
  if(nameLen > ZLIMDB_MAX_MESSAGE_SIZE - sizeof(zlimdb_add_request) - sizeof(zlimdb_table_entity))
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create message
  char buffer[ZLIMDB_MAX_MESSAGE_SIZE];
  zlimdb_add_request* addRequest = (zlimdb_add_request*)buffer;
  addRequest->header.size = sizeof(zlimdb_add_request) + sizeof(zlimdb_table_entity) + nameLen;
  addRequest->header.message_type = zlimdb_message_add_request;
  addRequest->header.request_id = ++zdb->lastRequestId << 1 | 1;
  addRequest->table_id = zlimdb_table_tables;
  zlimdb_table_entity* tableEntity = (zlimdb_table_entity*)(addRequest + 1);
  tableEntity->entity.id = 0;
  tableEntity->entity.time = 0;
  tableEntity->entity.size = sizeof(zlimdb_table_entity) + nameLen;
  tableEntity->name_size = nameLen;
  tableEntity->flags = 0;
  memcpy(tableEntity + 1, name, nameLen);

  // send message
  if(_zlimdb_sendRequest(zdb, &addRequest->header) != 0)
    return -1;

  // receive response
  zlimdb_add_response addResponse;
  if(_zlimdb_receiveResponse(zdb, addRequest->header.request_id, &addResponse, sizeof(zlimdb_add_response)) != 0)
    return -1;
  if(tableId)
    *tableId = (uint32_t)addResponse.id;
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_find_table(zlimdb* zdb, const char* name, uint32_t* tableId)
{
  if(!zdb || !name)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;
  size_t nameLen = strlen(name);
  if(nameLen > ZLIMDB_MAX_MESSAGE_SIZE - sizeof(zlimdb_find_request) - sizeof(zlimdb_table_entity))
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create message
  char buffer[ZLIMDB_MAX_MESSAGE_SIZE];
  zlimdb_find_request* findRequest = (zlimdb_find_request*)buffer;
  findRequest->header.size = sizeof(zlimdb_find_request) + sizeof(zlimdb_table_entity) + nameLen;
  findRequest->header.message_type = zlimdb_message_find_request;
  findRequest->header.request_id = ++zdb->lastRequestId << 1 | 1;
  findRequest->table_id = zlimdb_table_tables;
  zlimdb_table_entity* tableEntity = (zlimdb_table_entity*)(findRequest + 1);
  tableEntity->entity.id = 0;
  tableEntity->entity.time = 0;
  tableEntity->entity.size = sizeof(zlimdb_table_entity) + nameLen;
  tableEntity->name_size = nameLen;
  tableEntity->flags = 0;
  memcpy(tableEntity + 1, name, nameLen);

  // send message
  if(_zlimdb_sendRequest(zdb, &findRequest->header) != 0)
    return -1;

  // receive response
  zlimdb_find_response findResponse;
  if(_zlimdb_receiveResponse(zdb, findRequest->header.request_id, &findResponse, sizeof(zlimdb_find_response)) != 0)
    return -1;
  if(tableId)
    *tableId = (uint32_t)findResponse.id;
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_copy_table(zlimdb* zdb, uint32_t tableId, const char* newName, uint32_t* newTableId)
{
  if(!zdb || !tableId || !newName)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;
  size_t nameLen = strlen(newName);
  if(nameLen > ZLIMDB_MAX_MESSAGE_SIZE - sizeof(zlimdb_copy_request) - sizeof(zlimdb_table_entity))
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create message
  char buffer[ZLIMDB_MAX_MESSAGE_SIZE];
  zlimdb_copy_request* copyRequest = (zlimdb_copy_request*)buffer;
  copyRequest->header.size = sizeof(zlimdb_copy_request) + sizeof(zlimdb_table_entity) + nameLen;
  copyRequest->header.message_type = zlimdb_message_copy_request;
  copyRequest->header.request_id = ++zdb->lastRequestId << 1 | 1;
  copyRequest->table_id = tableId;
  zlimdb_table_entity* tableEntity = (zlimdb_table_entity*)(copyRequest + 1);
  tableEntity->entity.id = 0;
  tableEntity->entity.time = 0;
  tableEntity->entity.size = sizeof(zlimdb_table_entity) + nameLen;
  tableEntity->name_size = nameLen;
  tableEntity->flags = 0;
  memcpy(tableEntity + 1, newName, nameLen);

  // send message
  if(_zlimdb_sendRequest(zdb, &copyRequest->header) != 0)
    return -1;

  // receive response
  zlimdb_copy_response copyResponse;
  if(_zlimdb_receiveResponse(zdb, copyRequest->header.request_id, &copyResponse, sizeof(zlimdb_copy_response)) != 0)
    return -1;
  if(newTableId)
    *newTableId = (uint32_t)copyResponse.id;
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_remove_table(zlimdb* zdb, uint32_t tableId)
{
  return zlimdb_remove(zdb, zlimdb_table_tables, tableId);
}

int zlimdb_add_user(zlimdb* zdb, const char* userName, const char* password)
{
  if(!zdb || !userName || !password)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;
  size_t userNameLen = strlen(userName);
  if(userNameLen > ZLIMDB_MAX_MESSAGE_SIZE - sizeof(zlimdb_add_request) - sizeof(zlimdb_table_entity) - 13)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  // create user table
  char tableName[ZLIMDB_MAX_MESSAGE_SIZE];
  memcpy(tableName, "users/", 6);
  memcpy(tableName + 6, userName, userNameLen);
  memcpy(tableName + 6 + userNameLen, "/user", 5);
  tableName[11 + userNameLen] = '\0';
  uint32_t tableId;
  if(zlimdb_add_table(zdb, tableName, &tableId) != 0)
    return -1;

  // add user entity
  zlimdb_user_entity userEntity;
  userEntity.entity.size = sizeof(zlimdb_user_entity);
  userEntity.entity.id = 1;
  userEntity.entity.time = 0;
  srand((unsigned int)time(0));
  uint16_t* i = (uint16_t*)userEntity.pw_salt, * end = (uint16_t*)(userEntity.pw_salt + sizeof(userEntity.pw_salt));
  for(; i < end; ++i)
    *i = rand();
  sha256_hmac(userEntity.pw_salt, sizeof(userEntity.pw_salt), (const uint8_t*)password, strlen(password), userEntity.pw_hash);
  if(zlimdb_add(zdb, tableId, &userEntity.entity, 0) != 0)
    return -1;
  return 0;
}

int zlimdb_add(zlimdb* zdb, uint32_t tableId, const zlimdb_entity* data, uint64_t* id)
{
  if(!zdb || !tableId || !data || data->size > ZLIMDB_MAX_MESSAGE_SIZE - sizeof(zlimdb_add_request))
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create message
  char buffer[ZLIMDB_MAX_MESSAGE_SIZE];
  zlimdb_add_request* addRequest = (zlimdb_add_request*)buffer;
  addRequest->header.size = sizeof(zlimdb_add_request) + data->size;
  addRequest->header.message_type = zlimdb_message_add_request;
  addRequest->header.request_id = ++zdb->lastRequestId << 1 | 1;
  addRequest->table_id = tableId;
  memcpy(addRequest + 1, data, data->size);

  // send message
  if(_zlimdb_sendRequest(zdb, &addRequest->header) != 0)
    return -1;

  // receive response
  zlimdb_add_response addResponse;
  if(_zlimdb_receiveResponse(zdb, addRequest->header.request_id, &addResponse, sizeof(zlimdb_add_response)) != 0)
    return -1;
  if(id)
    *id = addResponse.id;
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_update(zlimdb* zdb, uint32_t tableId, const zlimdb_entity* data)
{
  if(!zdb || !tableId || data->size > ZLIMDB_MAX_MESSAGE_SIZE - sizeof(zlimdb_update_request))
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create message
  char buffer[ZLIMDB_MAX_MESSAGE_SIZE];
  zlimdb_update_request* updateRequest = (zlimdb_update_request*)buffer;
  updateRequest->header.size = sizeof(zlimdb_update_request) + data->size;
  updateRequest->header.message_type = zlimdb_message_update_request;
  updateRequest->header.request_id = ++zdb->lastRequestId << 1 | 1;
  updateRequest->table_id = tableId;
  memcpy(updateRequest + 1, data, data->size);

  // send message
  if(_zlimdb_sendRequest(zdb, &updateRequest->header) != 0)
    return -1;

  // receive response
  zlimdb_header updateResponse;
  if(_zlimdb_receiveResponse(zdb, updateRequest->header.request_id, &updateResponse, sizeof(zlimdb_header)) != 0)
    return -1;
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_remove(zlimdb* zdb, uint32_t tableId, uint64_t entityId)
{
  if(!zdb || !tableId || !entityId)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create message
  zlimdb_remove_request removeRequest;
  removeRequest.header.size = sizeof(zlimdb_remove_request);
  removeRequest.header.message_type = zlimdb_message_remove_request;
  removeRequest.header.request_id = ++zdb->lastRequestId << 1 | 1;
  removeRequest.table_id = tableId;
  removeRequest.id = entityId;

  // send message
  if(_zlimdb_sendRequest(zdb, &removeRequest.header) != 0)
    return -1;

  // receive response
  zlimdb_header removeResponse;
  if(_zlimdb_receiveResponse(zdb, removeRequest.header.request_id, &removeResponse, sizeof(zlimdb_header)) != 0)
    return -1;
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_clear(zlimdb* zdb, uint32_t tableId)
{
  if(!zdb || !tableId)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create message
  zlimdb_clear_request clearRequest;
  clearRequest.header.size = sizeof(zlimdb_clear_request);
  clearRequest.header.message_type = zlimdb_message_clear_request;
  clearRequest.header.request_id = ++zdb->lastRequestId << 1 | 1;
  clearRequest.table_id = tableId;

  // send message
  if(_zlimdb_sendRequest(zdb, &clearRequest.header) != 0)
    return -1;

  // receive response
  zlimdb_header clearResponse;
  if(_zlimdb_receiveResponse(zdb, clearRequest.header.request_id, &clearResponse, sizeof(zlimdb_header)) != 0)
    return -1;
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_query(zlimdb* zdb, uint32_t tableId, zlimdb_query_type type, uint64_t param)
{
  if(!zdb || !tableId)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create request data
  _zlimdb_requestData* requestData = zdb->unusedRequest;
  if(requestData)
    zdb->unusedRequest = requestData->next;
  else
  {
    requestData = malloc(sizeof(_zlimdb_requestData)); 
    if(!requestData)
      return zlimdbErrno = zlimdb_local_error_system, -1;
  }
  requestData->next = zdb->openRequest;
  requestData->requestId = ++zdb->lastRequestId << 1 | 1;
  requestData->response = 0;
  requestData->state = _zlimdb_requestState_receiving;
  zdb->openRequest = requestData;

  // create message
  zlimdb_query_request queryRequest;
  queryRequest.header.size = sizeof(zlimdb_query_request);
  queryRequest.header.message_type = zlimdb_message_query_request;
  queryRequest.header.request_id = requestData->requestId;
  queryRequest.table_id = tableId;
  queryRequest.type = type;
  queryRequest.param = param;

  // send message
  if(_zlimdb_sendRequest(zdb, &queryRequest.header) != 0)
  {
    zdb->openRequest = requestData->next;
    requestData->next = zdb->unusedRequest;
    zdb->unusedRequest = requestData;
    return -1;
  }

  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_query_entity(zlimdb* zdb, uint32_t tableId, uint64_t entityId, void* data, uint32_t* size)
{
  if(!zdb || !tableId || !entityId || !data || !size)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zlimdb_query(zdb, tableId, zlimdb_query_type_by_id, entityId) != 0)
    return -1;
  if(zlimdb_get_response(zdb, data, size) != 0)
    return -1;
  if(zdb->openRequest->state != _zlimdb_requestState_finished)
  {
    zdb->state = _zlimdb_state_error;
    return zlimdbErrno = zlimdb_local_error_invalid_response, -1;
  }
  _zlimdb_requestData* request = zdb->openRequest;
  zdb->openRequest = request->next;
  _zlimdb_freeReponses(request->response);
  request->next = zdb->unusedRequest;
  zdb->unusedRequest = request;
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_subscribe(zlimdb* zdb, uint32_t tableId, zlimdb_query_type type, uint64_t param)
{
  if(!zdb || !tableId)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create request data
  _zlimdb_requestData* requestData = zdb->unusedRequest;
  if(requestData)
    zdb->unusedRequest = requestData->next;
  else
  {
    requestData = malloc(sizeof(_zlimdb_requestData)); 
    if(!requestData)
      return zlimdbErrno = zlimdb_local_error_system, -1;
  }
  requestData->next = zdb->openRequest;
  requestData->requestId = ++zdb->lastRequestId << 1 | 1;
  requestData->response = 0;
  requestData->state = _zlimdb_requestState_receiving;
  zdb->openRequest = requestData;

  // create message
  zlimdb_subscribe_request subscribeRequest;
  subscribeRequest.header.size = sizeof(zlimdb_subscribe_request);
  subscribeRequest.header.message_type = zlimdb_message_subscribe_request;
  subscribeRequest.header.request_id = requestData->requestId;
  subscribeRequest.table_id = tableId;
  subscribeRequest.type = type;
  subscribeRequest.param = param;

  // send message
  if(_zlimdb_sendRequest(zdb, &subscribeRequest.header) != 0)
  {
    zdb->openRequest = requestData->next;
    requestData->next = zdb->unusedRequest;
    zdb->unusedRequest = requestData;
    return -1;
  }

  return zlimdbErrno = zlimdb_local_error_none, 0;
}


int zlimdb_get_response(zlimdb* zdb, void* data, uint32_t* size)
{
  if(!zdb || !data || !size)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  _zlimdb_requestData* request = zdb->openRequest;
  if(!request)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  switch(request->state)
  {
  case _zlimdb_requestState_receiving:
    break;
  case _zlimdb_requestState_finished:
    {
      _zlimdb_freeReponses(request->response);
      zdb->openRequest = request->next;
      request->next = zdb->unusedRequest;
      zdb->unusedRequest = request;
    }
    return zlimdbErrno = zlimdb_local_error_none, -1;
  default:
    return zlimdbErrno = zlimdb_local_error_state, -1;
  }

  for(;;)
  {
    // return already received response
    _zlimdb_responseData* response = request->response;
    if(response)
    {
      const zlimdb_header* header = (const zlimdb_header*)(response + 1);
      if(header->message_type == zlimdb_message_error_response)
      {
        zdb->state = _zlimdb_state_connected;
        zlimdbErrno = zlimdb_local_error_none;
        _zlimdb_copyResponseData(zdb, response, data, *size); // get errno
        _zlimdb_freeReponses(response);
        zdb->openRequest = request->next;
        request->next = zdb->unusedRequest;
        zdb->unusedRequest = request;
        return -1;
      }
      if(header->flags & zlimdb_header_flag_compressed)
      {
        const void* buffer = header + 1;
        size_t dataSize = header->size - sizeof(zlimdb_header);
        if(dataSize < sizeof(uint16_t))
        {
          zdb->state = _zlimdb_state_error;
          return zlimdbErrno = zlimdb_local_error_invalid_message_data, -1;
        }
        uint16_t rawDataSize = *(const uint16_t*)buffer;
        if(rawDataSize > 0)
        {
          if(rawDataSize > *size)
          {
            zdb->state = _zlimdb_state_error;
            return zlimdbErrno = zlimdb_local_error_buffer_size, -1;
          }
          if(LZ4_decompress_safe((const char*)buffer + sizeof(uint16_t), (char*)data, dataSize - sizeof(uint16_t), rawDataSize) != rawDataSize)
          {
            zdb->state = _zlimdb_state_error;
            return zlimdbErrno = zlimdb_local_error_invalid_message_data, -1;
          }
        }
        *size = rawDataSize;
      }
      else
      {
        size_t dataSize = header->size - sizeof(zlimdb_header);
        if(dataSize > *size)
        {
          zdb->state = _zlimdb_state_error;
          return zlimdbErrno = zlimdb_local_error_buffer_size, -1;
        }
        memcpy(data, header + 1, dataSize);
        *size = dataSize;
      }
      if(!(header->flags & zlimdb_header_flag_fragmented))
        request->state = _zlimdb_requestState_finished;
      request->response = response->next;
      if(response->next)
        response->next->last = response->last;
      free(response);
      return zlimdbErrno = zlimdb_local_error_none, 0;
    }

    // receive new response
    for(;;)
    {
      zlimdb_header header;
      if(_zlimdb_receiveHeader(zdb, &header) != 0)
        return -1;
      if(header.request_id == zdb->openRequest->requestId)
      {
        if(header.message_type == zlimdb_message_error_response)
        {
          zdb->state = _zlimdb_state_connected;
          zlimdbErrno = zlimdb_local_error_none;
          _zlimdb_receiveResponseData(zdb, &header, data, *size); // get errno
          return -1;
        }
        if(header.flags & zlimdb_header_flag_compressed)
        {
          size_t dataSize = header.size - sizeof(zlimdb_header);
          if(dataSize < sizeof(uint16_t))
          {
            zdb->state = _zlimdb_state_error;
            return zlimdbErrno = zlimdb_local_error_invalid_message_data, -1;
          }
          char compressedData[ZLIMDB_MAX_MESSAGE_SIZE];
          if(_zlimdb_receiveResponseData(zdb, &header, compressedData, dataSize) != 0)
              return -1;
          uint16_t rawDataSize = *(const uint16_t*)compressedData;
          if(rawDataSize > 0)
          {
            if(rawDataSize > *size)
            {
              zdb->state = _zlimdb_state_error;
              return zlimdbErrno = zlimdb_local_error_buffer_size, -1;
            }
            if(LZ4_decompress_safe((char*)compressedData + sizeof(uint16_t), (char*)data, dataSize - sizeof(uint16_t), rawDataSize) != rawDataSize)
            {
              zdb->state = _zlimdb_state_error;
              return zlimdbErrno = zlimdb_local_error_invalid_message_data, -1;
            }
          }
          *size = rawDataSize;
        }
        else
        {
          if(_zlimdb_receiveResponseData(zdb, &header, data, *size) != 0)
            return -1;
          *size = header.size - sizeof(zlimdb_header);
        }
        if(!(header.flags & zlimdb_header_flag_fragmented))
          request->state = _zlimdb_requestState_finished;
        return zlimdbErrno = zlimdb_local_error_none, 0;
      }
      else if(header.request_id)
      {
        _zlimdb_requestData* request;
        for(request = zdb->openRequest->next; request; request = request->next)
          if(request->requestId == header.request_id)
            goto receiveResponse;
        zdb->state = _zlimdb_state_error;
        return zlimdbErrno = zlimdb_local_error_invalid_response, -1;
      receiveResponse: ;

        _zlimdb_responseData* response = malloc(sizeof(_zlimdb_responseData) + header.size);
        if(!response)
        {
          zdb->state = _zlimdb_state_error;
          return zlimdbErrno = zlimdb_local_error_system, -1;
        }
        void* buffer = response + 1;
        if(_zlimdb_receiveData(zdb, (zlimdb_header*)buffer + 1, header.size - sizeof(zlimdb_header)) != 0)
            return -1;
        *(zlimdb_header*)buffer = header;
        response->next = 0;
        if(request->response)
        {
          request->response->last->next = response;
          request->response->last = response;
        }
        else
        {
          request->response = response;
          response->last = response;
        }
      }
      else
      {
        char buffer[ZLIMDB_MAX_MESSAGE_SIZE];
        if(_zlimdb_receiveData(zdb, (zlimdb_header*)buffer + 1, header.size - sizeof(zlimdb_header)) != 0)
            return -1; 
        if(zdb->callback)
        {
          *(zlimdb_header*)buffer = header;
          zdb->callback(zdb->userData, (zlimdb_header*)buffer);
        }
        break;
      }
    }
  }
}

zlimdb_entity* zlimdb_get_entity(uint32_t minSize, void** data, uint32_t* size)
{
  if(*size < minSize)
    return 0;
  uint32_t entitySize = ((zlimdb_entity*)*data)->size;
   if(*size < entitySize)
     return 0;
  zlimdb_entity* result = *data;
  *data = (char*)*data + entitySize;
  *size -= entitySize;
  return result;
}

int zlimdb_unsubscribe(zlimdb* zdb, uint32_t tableId)
{
  if(!zdb || !tableId)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create message
  zlimdb_unsubscribe_request unsubscribeRequest;
  unsubscribeRequest.header.size = sizeof(zlimdb_unsubscribe_request);
  unsubscribeRequest.header.message_type = zlimdb_message_unsubscribe_request;
  unsubscribeRequest.header.request_id = ++zdb->lastRequestId << 1 | 1;
  unsubscribeRequest.table_id = tableId;

  // send message
  if(_zlimdb_sendRequest(zdb, &unsubscribeRequest.header) != 0)
    return -1;

  // receive response
  zlimdb_header unsubscribeResponse;
  if(_zlimdb_receiveResponse(zdb, unsubscribeRequest.header.request_id, &unsubscribeResponse, sizeof(zlimdb_header)) != 0)
    return -1;
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_sync(zlimdb* zdb, uint32_t tableId, int64_t* serverTime, int64_t* tableTime)
{
  if(!zdb || !tableId)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create message
  zlimdb_sync_request syncRequest;
  syncRequest.header.size = sizeof(zlimdb_sync_request);
  syncRequest.header.message_type = zlimdb_message_sync_request;
  syncRequest.header.request_id = ++zdb->lastRequestId << 1 | 1;
  syncRequest.table_id = tableId;

  // send message
  if(_zlimdb_sendRequest(zdb, &syncRequest.header) != 0)
    return -1;

  // receive response
  zlimdb_sync_response syncResponse;
  if(_zlimdb_receiveResponse(zdb, syncRequest.header.request_id, &syncResponse, sizeof(zlimdb_sync_request)) != 0)
    return -1;
  if(serverTime)
    *serverTime = syncResponse.server_time;
  if(tableTime)
    *tableTime = syncResponse.table_time;
  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_control(zlimdb* zdb, uint32_t tableId, uint64_t entityId, uint32_t controlCode, const void* data, uint32_t size)
{
  if(!zdb || !tableId || (size && !data) || size > ZLIMDB_MAX_MESSAGE_SIZE - sizeof(zlimdb_control_request))
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

  // create message
  char buffer[ZLIMDB_MAX_MESSAGE_SIZE];
  zlimdb_control_request* controlRequest = (zlimdb_control_request*)buffer;
  controlRequest->header.size = sizeof(zlimdb_control_request) + size;
  controlRequest->header.message_type = zlimdb_message_control_request;
  controlRequest->header.request_id = ++zdb->lastRequestId << 1 | 1;
  controlRequest->table_id = tableId;
  controlRequest->id = entityId;
  controlRequest->control_code = controlCode;
  memcpy(controlRequest + 1, data, size);

  // send message
  if(_zlimdb_sendRequest(zdb, &controlRequest->header) != 0)
    return -1;

  return zlimdbErrno = zlimdb_local_error_none, 0;
}

int zlimdb_exec(zlimdb* zdb, unsigned int timeout)
{
  if(!zdb)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;

  if(zdb->state != _zlimdb_state_connected)
    return zlimdbErrno = zlimdb_local_error_state, -1;

#ifdef _WIN32
  DWORD currentTick = GetTickCount();
  DWORD startTick = currentTick;
  do
  {
    if(zdb->selectedEvents == 0)
    {
      if(WSAEventSelect(zdb->socket, zdb->hReadEvent, FD_READ | FD_CLOSE) == SOCKET_ERROR)
      {
        zdb->state = _zlimdb_state_error;
        return zlimdbErrno = zlimdb_local_error_system, -1;
      }
      zdb->selectedEvents = FD_READ | FD_CLOSE;
    }

    HANDLE handles[] = {zdb->hReadEvent, zdb->hInterruptEvent};
    DWORD passedTicks = currentTick - startTick;
    switch(passedTicks <= timeout ? WaitForMultipleObjects(2, handles, FALSE, timeout - passedTicks) : WAIT_TIMEOUT)
    {
    case WAIT_OBJECT_0:
      break;
    case WAIT_OBJECT_0 + 1:
      WSAResetEvent(zdb->hInterruptEvent);
      return zlimdbErrno = zlimdb_local_error_interrupted, -1;
    case WAIT_TIMEOUT:
      return zlimdbErrno = zlimdb_local_error_timeout, -1;
    }
    WSANETWORKEVENTS events;
    if(WSAEnumNetworkEvents(zdb->socket, zdb->hReadEvent, &events) == SOCKET_ERROR)
    {
      zdb->state = _zlimdb_state_error;
      return zlimdbErrno = zlimdb_local_error_system, -1;
    }
    if(events.lNetworkEvents)
    {
      zlimdb_header header;
      if(_zlimdb_receiveHeader(zdb, &header) != 0)
        return -1;
      assert(!(header.flags & zlimdb_header_flag_compressed));
      size_t bufferSize = header.size;
      char buffer[ZLIMDB_MAX_MESSAGE_SIZE];
      if(_zlimdb_receiveData(zdb, (zlimdb_header*)buffer + 1, bufferSize - sizeof(zlimdb_header)) != 0)
        return -1;
      if(zdb->callback)
      {
        *(zlimdb_header*)buffer = header;
        zdb->callback(zdb->userData, (zlimdb_header*)buffer);
      }
    }
    currentTick = GetTickCount();
  } while(zdb->state == _zlimdb_state_connected);
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int64_t currentTick = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  int64_t startTick = currentTick;
  do
  {
    int64_t passedTicks = currentTick - startTick;
    struct pollfd fds[] = {
      { zdb->socket, POLLIN /*| POLLRDHUP*/ | POLLHUP, 0},
      { zdb->interruptEventFd, POLLIN /*| POLLRDHUP*/ | POLLHUP, 0}
    };
    int ret = passedTicks <= timeout ? poll(fds, 2, timeout - passedTicks) : 0;
    if(ret < 0)
    {
      zdb->state = zlimdb_state_error;
      return zlimdbErrno = zlimdb_local_error_system, -1;
    }
    if(fds[0].revents)
    {
      zlimdb_header header;
      if(zlimdb_receiveHeader(zdb, &header) != 0)
        return -1;
      assert(!(header.flags & zlimdb_header_flag_compressed));
      size_t bufferSize = header.size;
      char buffer[ZLIMDB_MAX_MESSAGE_SIZE];
      if(zlimdb_receiveData(zdb, (zlimdb_header*)buffer + 1, bufferSize - sizeof(zlimdb_header)) != 0)
        return -1;
      if(zdb->callback)
      {
        *(zlimdb_header*)buffer = header;
        zdb->callback(zdb->userData, (zlimdb_header*)buffer);
      }
    }
    if(fds[1].revents)
    {
      uint64_t val;
      if(read(zdb->interruptEventFd, &val, sizeof(val)) == -1)
      {
        zdb->state = _zlimdb_state_error;
        return zlimdbErrno = zlimdb_local_error_system, -1;
      }
      return zlimdbErrno = zlimdb_local_error_interrupted, -1;
    }
    if(ret == 0)
      return zlimdbErrno = zlimdb_local_error_timeout, -1;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    currentTick = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  } while(zdb->state == zlimdb_state_connected);
#endif
  return -1;
}

int zlimdb_interrupt(zlimdb* zdb)
{
  if(!zdb)
    return zlimdbErrno = zlimdb_local_error_invalid_parameter, -1;
#ifdef _WIN32
  if(!WSASetEvent(zdb->hInterruptEvent))
    return zlimdbErrno = zlimdb_local_error_system, -1;
#else
  uint64_t val = 1;
  if(write(zdb->interruptEventFd, &val, sizeof(val)) == -1)
    return zlimdbErrno = zlimdb_local_error_system, -1;
#endif
  return zlimdbErrno = zlimdb_local_error_none, 0;
}
