
#ifndef __WINDIVERT__KERNEL_H__
#define __WINDIVERT__KERNEL_H__

#define WINDIVERT_KERNEL
#include "windivert.h"

typedef struct  PENDED_CONNECT_PACKET_
{
    LIST_ENTRY entry;                       // Entry for queue.
    UINT64 MsgId;                        /*消息ID*/
    UINT32 authConnectDecision;         /* 用户决策 FWP_ACTION_BLOCK  FWP_ACTION_PERMIT*/
    UINT32 Sync;                        /* 是否是同步决策请求*/
    BOOL Outbound;                     /*是否是出方向的*/
    UINT32 ProcessId;                   /* Process ID. */
    UINT32 LocalAddr[4];                /* Local address. */
    UINT32 RemoteAddr[4];               /* Remote address. */
    UINT16 LocalPort;                   /* Local port. */
    UINT16 RemotePort;                  /* Remote port. */
    BOOL ipv4;                       /*是否是IPv4*/
    UINT8  Protocol;                    /* Protocol. */
    ULONG compartmentId;            /* Completion handle (required in order to be able to pend at this layer). */
    HANDLE CompletionContext;           /* Completion result context. */
    NET_BUFFER_LIST* NetBufferList;               /* raw_data*/
    UINT64			endpointHandle;
    SCOPE_ID		remoteScopeId;
    WSACMSGHDR* controlData;
    ULONG			controlDataLength;
    BOOLEAN			ipSecProtected;
    ULONG			nblOffset;
    UINT32			ipHeaderSize;
    UINT32			transportHeaderSize;
    IF_INDEX		interfaceIndex;
    IF_INDEX		subInterfaceIndex;
}PENDED_CONNECT_PACKET;

#endif
