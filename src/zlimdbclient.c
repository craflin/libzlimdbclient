
#include "zlimdbclient.h"
#include "sha256.h"

#ifdef _WIN32
#include <winsock2.h>
#else
// todo
#endif
#include <assert.h>

#define ZLIMDB_DEFAULT_PORT 13211

#ifdef _WIN32
#define ERRNO WSAGetLastError()
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
#define CLOSE close
#define SOCKET_ERROR (-1)
#endif

struct _zlimdb
{
  SOCKET socket;
#ifdef _WIN32
  HANDLE hInterruptEvent;
  HANDLE hReadEvent;
#else
  // todo int interruptFd;
#endif
  zlimdb_callback callback;
  void* userData;
};

#ifdef _MSC_VER
static int __declspec(thread) zlimdbErrno = zlimdb_error_none;
#else
static int __thread zlimdbErrno = zlimdb_error_none;
#endif

static volatile long zlimdbInitCalls = 0;

int zlimdb_sendRequest(zlimdb* zdb, zlimdb_header* header);
int zlimdb_receiveData(zlimdb* zdb, void* buffer, size_t size);
int zlimdb_receiveResponse(zlimdb* zdb, uint32_t request_id, void* buffer, size_t size);
int zlimdb_receiveResponseCallback(zlimdb* zdb, uint32_t request_id, void* buffer, size_t size);

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
    return 0;
  zlimdb* zdb = malloc(sizeof(zlimdb));
  if(!zdb)
    return 0;
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
#else
  // todo zdb->eventfd = eventfd();
  if(zdb->eventfd == 0)
  {
    free(zdb);
    return 0;
  }
#endif
  zdb->socket = INVALID_SOCKET;
  zlimdbErrno = zlimdb_error_none;
  zdb->callback = callback;
  zdb->userData = user_data;
  return zdb;
}

int zlimdb_free(zlimdb* zdb)
{
  if(!zdb)
    return -1;
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
    return -1;
  if(zdb->socket != INVALID_SOCKET)
  {
    zlimdbErrno = zlimdb_error_state;
    return -1;
  }
#ifdef _WIN32
  zdb->socket = socket(AF_INET, SOCK_STREAM, 0);
#else
  zdb->socket = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
#endif
  if(zdb->socket == INVALID_SOCKET)
  {
    zlimdbErrno = zlimdb_error_socket;
    return -1;
  }

  struct sockaddr_in sin;
  memset(&sin,0,sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port ? port : ZLIMDB_DEFAULT_PORT);
  sin.sin_addr.s_addr = server ? inet_addr(server) : INADDR_LOOPBACK;
  if(sin.sin_addr.s_addr ==  INADDR_NONE)
  {
    zlimdbErrno = zlimdb_error_resolve;
    CLOSE(zdb->socket);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  if(connect(zdb->socket, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    zlimdbErrno = zlimdb_error_socket;
    CLOSE(zdb->socket);
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
    CLOSE(zdb->socket);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  // receive login response
  zlimdb_login_response loginResponse;
  if(zlimdb_receiveResponse(zdb, loginRequest->header.request_id, &loginResponse, sizeof(loginResponse)) != 0)
  {
    CLOSE(zdb->socket);
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
    CLOSE(zdb->socket);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  // receive auth response
  zlimdb_header authReponse;
  if(zlimdb_receiveResponse(zdb, authRequest.header.request_id, &authReponse, sizeof(authReponse)) != 0)
  {
    CLOSE(zdb->socket);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  //
#ifdef _WIN32
  if(WSAEventSelect(zdb->socket, zdb->hReadEvent, FD_READ| FD_CLOSE) == SOCKET_ERROR)
  {
    zlimdbErrno = zlimdb_error_socket;
    CLOSE(zdb->socket);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }
#endif

  zlimdbErrno = zlimdb_error_none;
  return 0;
}

int zlimdb_errno(zlimdb* zdb)
{
  return zlimdbErrno;
}

int zlimdb_add(zlimdb* zdb, uint32_t table_id, const void* data, uint16_t size)
{
  if(!zdb)
    return -1;
  if(zdb->socket == INVALID_SOCKET)
  {
    zlimdbErrno = zlimdb_error_state;
    return -1;
  }

  // create message
  zlimdb_add_request* addRequest = _alloca(sizeof(zlimdb_add_request) + size);
  addRequest->header.message_type = zlimdb_message_add_request;
  addRequest->header.size = sizeof(zlimdb_add_request) + size;
  addRequest->table_id = table_id;
  memcpy(addRequest + 1, data, size);

  // send message
  if(!zlimdb_sendRequest(zdb, &addRequest->header))
    return -1;

  // receive response
  zlimdb_header addResponse;
  if(!zlimdb_receiveResponseCallback(zdb, addRequest->header.request_id, &addResponse, sizeof(addResponse)))
    return -1;
  zlimdbErrno = zlimdb_error_none;
  return 0;
}

int zlimdb_query(zlimdb* zdb, uint32_t table_id, zlimdb_query_type type, uint64_t param)
{
  if(!zdb)
    return -1;
  if(zdb->socket == INVALID_SOCKET)
  {
    zlimdbErrno = zlimdb_error_state;
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
  if(!zlimdb_sendRequest(zdb, &queryRequest.header))
    return -1;

  // receive response
  zlimdb_header queryResponse;
  if(!zlimdb_receiveResponseCallback(zdb, queryRequest.header.request_id, &queryResponse, sizeof(queryResponse)))
    return -1;
  zlimdbErrno = zlimdb_error_none;
  //zdb->state = zlimdb_expecting_response;
  return 0;
}

int zlimdb_query_get_response(zlimdb* zdb, void* data, uint16_t size)
{
  if(!zdb)
    return -1;
  if(zdb->socket == INVALID_SOCKET)
  {
    zlimdbErrno = zlimdb_error_state;
    return -1;
  }
  // ??
  zlimdbErrno = zlimdb_error_none;
  return 0;
}

int zlimdb_exec(zlimdb* zdb, unsigned int timeout)
{
  if(!zdb)
    return -1;
  if(zdb->socket == INVALID_SOCKET)
  {
    zlimdbErrno = zlimdb_error_state;
    return -1;
  }

#ifdef _WIN32
  DWORD currentTick = GetTickCount();
  DWORD startTick = currentTick;
  for(;;)
  {
    HANDLE handles[] = {zdb->hReadEvent, zdb->hInterruptEvent};
    DWORD passedTicks = currentTick - startTick;
    switch(passedTicks <= timeout ? WaitForMultipleObjects(2, handles, FALSE, timeout - passedTicks) : WAIT_TIMEOUT)
    {
    case WAIT_OBJECT_0:
      break;
    case WAIT_OBJECT_0 + 1:
      WSAResetEvent(zdb->hInterruptEvent);
      zlimdbErrno = zlimdb_error_interrupted;
      return -1;
    case WAIT_TIMEOUT:
      zlimdbErrno = zlimdb_error_timeout;
      return -1;
    }
    WSANETWORKEVENTS events;
    if(WSAEnumNetworkEvents(zdb->socket, zdb->hReadEvent, &events) == SOCKET_ERROR)
    {
      zlimdbErrno = zlimdb_error_socket;
      return -1;
    }
    uint8_t buffer[0xffff];
    if(zlimdb_receiveData(zdb, buffer, sizeof(buffer)) != 0)
      return -1;
    if(zdb->callback)
      zdb->callback(zdb->userData, buffer, ((zlimdb_header*)buffer)->size);
    currentTick = GetTickCount();
  }
#else
  // todo
#endif
}

int zlimdb_interrupt(zlimdb* zdb)
{
  if(!zdb)
    return -1;
#ifdef _WIN32
  if(!WSASetEvent(zdb->hInterruptEvent))
  {
    zlimdbErrno = zlimdb_error_socket;
    return -1;
  }
#else
  // todo
#endif
  zlimdbErrno = zlimdb_error_none;
  return 0;
}

int zlimdb_sendRequest(zlimdb* zdb, zlimdb_header* header)
{
  header->flags = 0;
  header->request_id = 1;
  if(send(zdb->socket, (const char*)header, header->size, 0) != header->size)
  {
    zlimdbErrno = zlimdb_error_socket;
    return -1;
  }
  return 0;
}

int zlimdb_receiveData(zlimdb* zdb, void* buffer, size_t size)
{
  assert(size >= sizeof(zlimdb_error_response));
  unsigned int receivedSize = 0;
  do
  {
    int res = recv(zdb->socket, (char*)buffer + receivedSize, sizeof(zlimdb_header) - receivedSize, 0);
    if(res == 0)
    {
      zlimdbErrno = zlimdb_error_connection_closed;
      return -1;
    }
    else if(res < 0)
    {
      zlimdbErrno = zlimdb_error_socket;
      return -1;
    }
    receivedSize += res;
  } while(receivedSize < sizeof(zlimdb_header));
  const zlimdb_header* header = buffer;
  if(header->size < sizeof(zlimdb_header))
  {
    zlimdbErrno = zlimdb_error_invalid_response;
    return -1;
  }
  size_t dataSize = header->size - sizeof(zlimdb_header);
  if(dataSize > 0)
  {
    if(header->size > size)
    {
      zlimdbErrno = zlimdb_error_invalid_response;
      return -1;
    }
    do
    {
      int res = recv(zdb->socket, (char*)buffer + receivedSize, header->size - receivedSize, 0);
      if(res == 0)
      {
        zlimdbErrno = zlimdb_error_connection_closed;
        return -1;
      }
      else if(res < 0)
      {
        zlimdbErrno = zlimdb_error_socket;
        return -1;
      }
      receivedSize += res;
    } while(receivedSize < header->size);
  }
  return 0;
}

int zlimdb_receiveResponse(zlimdb* zdb, uint32_t request_id, void* buffer, size_t size)
{
  if(zlimdb_receiveData(zdb, buffer, size) != 0)
    return -1;
  const zlimdb_header* header = buffer;
  if(header->request_id != request_id)
  {
    zlimdbErrno = zlimdb_error_invalid_response;
    return -1;
  }
  if(header->message_type == zlimdb_message_error_response)
  {
    zlimdbErrno = ((const zlimdb_error_response*)header)->error;
    return -1;
  }
  return 0;
}

int zlimdb_receiveResponseCallback(zlimdb* zdb, uint32_t request_id, void* buffer, size_t size)
{
  for(;;)
  {
    if(zlimdb_receiveData(zdb, buffer, size) != 0)
      return -1;
    const zlimdb_header* header = buffer;
    if(header->request_id == request_id)
    {
      if(header->message_type == zlimdb_message_error_response)
      {
        zlimdbErrno = ((const zlimdb_error_response*)header)->error;
        return -1;
      }
      return 0;
    }
    if(zdb->callback)
      zdb->callback(zdb->userData, buffer, size);
  }
}
