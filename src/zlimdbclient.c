
#include "zlimdbclient.h"

#ifdef _WIN32
#include <winsock2.h>
#else
// todo
#endif

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
  int error;
  zlimdb_callback callback;
  void* userData;
};

static volatile long zlimdbInitCalls = 0;

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
  zdb->error = zlimdb_error_none;
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

int zlimdb_connect(zlimdb* zdb, const char* server, unsigned short port)
{
  if(!zdb)
    return -1;
  if(zdb->socket != INVALID_SOCKET)
  {
    zdb->error = zlimdb_error_state;
    return -1;
  }
#ifdef _WIN32
  zdb->socket = socket(AF_INET, SOCK_STREAM, 0);
#else
  zdb->socket = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
#endif
  if(zdb->socket == INVALID_SOCKET)
  {
    zdb->error = zlimdb_error_socket;
    return -1;
  }

  struct sockaddr_in sin;
  memset(&sin,0,sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port ? port : ZLIMDB_DEFAULT_PORT);
  sin.sin_addr.s_addr = server ? inet_addr(server) : INADDR_LOOPBACK;
  if(sin.sin_addr.s_addr ==  INADDR_NONE)
  {
    zdb->error = zlimdb_error_resolve;
    CLOSE(zdb->socket);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

  if(connect(zdb->socket, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    zdb->error = zlimdb_error_socket;
    CLOSE(zdb->socket);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }

#ifdef _WIN32
  if(WSAEventSelect(zdb->socket, zdb->hReadEvent, FD_READ| FD_CLOSE) == SOCKET_ERROR)
  {
    zdb->error = zlimdb_error_socket;
    CLOSE(zdb->socket);
    zdb->socket = INVALID_SOCKET;
    return -1;
  }
#endif


  zdb->error = zlimdb_error_none;
  return 0;
}

int zlimdb_errno(zlimdb* zdb)
{
  if(!zdb)
    return zlimdb_error_inval;
  return zdb->error;
}

int zlimdbReceiveData(zlimdb* zdb)
{

   //recv(zdb->socket, zdb->receiveBuffer, 
  // todo
}

int zlimdb_add(zlimdb* zdb, unsigned int tableId, void* data, unsigned short size)
{
  if(!zdb)
    return -1;
  if(zdb->socket == INVALID_SOCKET)
  {
    zdb->error = zlimdb_error_state;
    return -1;
  }

  // create message

  // send message

  // receive response
}

int zlimdb_exec(zlimdb* zdb, unsigned int timeout)
{
  if(!zdb)
    return -1;
  if(zdb->socket == INVALID_SOCKET)
  {
    zdb->error = zlimdb_error_state;
    return -1;
  }

#ifdef _WIN32
  for(;;)
  {
    HANDLE handles[] = {zdb->hReadEvent, zdb->hInterruptEvent};
    switch(WaitForMultipleObjects(2, handles, FALSE, timeout))
    {
    case WAIT_OBJECT_0:
      break;
    case WAIT_OBJECT_0 + 1:
      WSAResetEvent(zdb->hInterruptEvent);
      zdb->error = zlimdb_error_interrupted;
      return -1;
    case WAIT_TIMEOUT:
      zdb->error = zlimdb_error_timeout;
      return -1;
    }
    WSANETWORKEVENTS events;
    if(WSAEnumNetworkEvents(zdb->socket, zdb->hReadEvent, &events) == SOCKET_ERROR)
    {
      zdb->error = zlimdb_error_socket;
      return -1;
    }
    //recv(zdb->socket, zdb->receiveBuffer, )
    // todo: read
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
    zdb->error = zlimdb_error_socket;
    return -1;
  }
#else
  // todo
#endif
  return 0;
}

