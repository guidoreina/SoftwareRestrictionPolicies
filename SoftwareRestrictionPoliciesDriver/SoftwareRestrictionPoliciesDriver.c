#include <fltkernel.h>
#include <ntddk.h>
#include "communication_port.h"


/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** Constants.                                                               **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
#define TIMEOUT (250 * 10000) /* 250 milliseconds. */


/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** Type definitions.                                                        **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
typedef struct {
  PFLT_FILTER filter;
  PFLT_PORT server_port;
  PFLT_PORT client_port;
} filter_t;


/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** Function prototypes.                                                     **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath);

NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS ConnectCallback(PFLT_PORT ClientPort,
                         PVOID ServerPortCookie,
                         PVOID ConnectionContext,
                         ULONG SizeOfContext,
                         PVOID* ConnectionPortCookie);

void DisconnectCallback(PVOID ConnectionCookie);

NTSTATUS MessageCallback(PVOID PortCookie,
                         PVOID InputBuffer,
                         ULONG InputBufferLength,
                         PVOID OutputBuffer,
                         ULONG OutputBufferLength,
                         PULONG ReturnOutputBufferLength);

void NotifyRoutine(_In_ HANDLE ParentId,
                   _In_ HANDLE ProcessId,
                   _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);


/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** Local variables.                                                         **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
static const FLT_REGISTRATION filter_registration = {
  sizeof(FLT_REGISTRATION),             /* Size. */
  FLT_REGISTRATION_VERSION,             /* Version. */
  0,                                    /* Flags. */
  NULL,                                 /* ContextRegistration. */
  NULL,                                 /* OperationRegistration. */
  FilterUnload,                         /* FilterUnloadCallback. */
  NULL,                                 /* InstanceSetupCallback. */
  NULL,                                 /* InstanceQueryTeardownCallback. */
  NULL,                                 /* InstanceTeardownStartCallback. */
  NULL,                                 /* InstanceTeardownCompleteCallback. */
  NULL,                                 /* GenerateFileNameCallback. */
  NULL,                                 /* NormalizeNameComponentCallback. */
  NULL                                  /* NormalizeContextCleanupCallback. */

#if FLT_MGR_LONGHORN
  , NULL                                /* TransactionNotificationCallback. */
  , NULL                                /* NormalizeNameComponentExCallback. */
#endif /* FLT_MGR_LONGHORN */
#if FLT_MFG_WIN8
  , NULL                                /* SectionNotificationCallback. */
#endif
};

static filter_t filter;


#ifdef ALLOC_PRAGMA
  #pragma alloc_text(INIT, DriverEntry)
  #pragma alloc_text(PAGE, FilterUnload)
  #pragma alloc_text(PAGE, ConnectCallback)
  #pragma alloc_text(PAGE, DisconnectCallback)
  #pragma alloc_text(PAGE, MessageCallback)
  #pragma alloc_text(PAGE, NotifyRoutine)
#endif /* ALLOC_PRAGMA */


/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** Function: DriverEntry                                                    **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
  PSECURITY_DESCRIPTOR sd;
  OBJECT_ATTRIBUTES oa;
  UNICODE_STRING port;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(RegistryPath);

  /* Register with the filter manager. */
  status = FltRegisterFilter(DriverObject,
                             &filter_registration,
                             &filter.filter);

  if (NT_SUCCESS(status)) {
    /* Build default security descriptor. */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

    if (NT_SUCCESS(status)) {
      RtlInitUnicodeString(&port, COMMUNICATION_PORT);

      /* Initialize object attributes. */
      InitializeObjectAttributes(&oa,
                                 &port,
                                 OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                 NULL,
                                 sd);

      /* Create communication server port. */
      status = FltCreateCommunicationPort(filter.filter,
                                          &filter.server_port,
                                          &oa,
                                          NULL,
                                          ConnectCallback,
                                          DisconnectCallback,
                                          MessageCallback,
                                          1);

      FltFreeSecurityDescriptor(sd);

      if (NT_SUCCESS(status)) {
        /* Register callback routine to be notified when a process is
         * created.
         */
        status = PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, FALSE);

        if (NT_SUCCESS(status)) {
          filter.client_port = NULL;

          return status;
        }

        FltCloseCommunicationPort(filter.server_port);
      }
    }

    FltUnregisterFilter(filter.filter);
  }

  return status;
}


/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** Function: FilterUnload                                                   **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
  UNREFERENCED_PARAMETER(Flags);

  PAGED_CODE();

  PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, TRUE);
  FltCloseCommunicationPort(filter.server_port);
  FltUnregisterFilter(filter.filter);

  return STATUS_SUCCESS;
}


/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** Function: ConnectCallback                                                **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
NTSTATUS ConnectCallback(PFLT_PORT ClientPort,
                         PVOID ServerPortCookie,
                         PVOID ConnectionContext,
                         ULONG SizeOfContext,
                         PVOID* ConnectionPortCookie)
{
  UNREFERENCED_PARAMETER(ServerPortCookie);
  UNREFERENCED_PARAMETER(ConnectionContext);
  UNREFERENCED_PARAMETER(SizeOfContext);
  UNREFERENCED_PARAMETER(ConnectionPortCookie);

  PAGED_CODE();

  if (ClientPort) {
    filter.client_port = ClientPort;
    return STATUS_SUCCESS;
  }

  return STATUS_INVALID_HANDLE;
}


/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** Function: DisconnectCallback                                             **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
void DisconnectCallback(PVOID ConnectionCookie)
{
  UNREFERENCED_PARAMETER(ConnectionCookie);

  PAGED_CODE();

  FltCloseClientPort(filter.filter, &filter.client_port);
}


/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** Function: MessageCallback                                                **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
NTSTATUS MessageCallback(PVOID PortCookie,
                         PVOID InputBuffer,
                         ULONG InputBufferLength,
                         PVOID OutputBuffer,
                         ULONG OutputBufferLength,
                         PULONG ReturnOutputBufferLength)
{
  UNREFERENCED_PARAMETER(PortCookie);
  UNREFERENCED_PARAMETER(InputBuffer);
  UNREFERENCED_PARAMETER(InputBufferLength);
  UNREFERENCED_PARAMETER(OutputBuffer);
  UNREFERENCED_PARAMETER(OutputBufferLength);
  UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

  PAGED_CODE();

  return STATUS_SUCCESS;
}


/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** Function: NotifyRoutine                                                  **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
void NotifyRoutine(_In_ HANDLE ParentId,
                   _In_ HANDLE ProcessId,
                   _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
  int reply;
  ULONG replylen;
  LARGE_INTEGER timeout;

  UNREFERENCED_PARAMETER(ParentId);

  PAGED_CODE();

  if ((CreateInfo) && (CreateInfo->ImageFileName)) {
    if (filter.client_port) {
      replylen = sizeof(int);
      timeout.QuadPart = -TIMEOUT;

      /* Send message to client program. */
      if (NT_SUCCESS(FltSendMessage(filter.filter,
                                    &filter.client_port,
                                    CreateInfo->ImageFileName->Buffer,
                                    CreateInfo->ImageFileName->Length,
                                    &reply,
                                    &replylen,
                                    &timeout))) {
        DbgPrint("PID: %d, EXE: '%wZ' => %s.",
                 ProcessId,
                 CreateInfo->ImageFileName,
                 reply ? "allowed" : "not allowed");

        if (!reply) {
          CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }
      }
    } else {
        DbgPrint("[Client not running] PID: %d, EXE: '%wZ' => allowed.",
                 ProcessId,
                 CreateInfo->ImageFileName);
    }
  }
}
