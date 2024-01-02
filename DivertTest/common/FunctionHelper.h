#pragma once
#include "common_struct_define.h"

#pragma warning(push)
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(pop)
NTSTATUS
NTAPI
fnNtQuerySection(
    IN HANDLE               SectionHandle,
    IN SECTION_INFORMATION_CLASS InformationClass,
    OUT PVOID               InformationBuffer,
    IN ULONG                InformationBufferSize,
    OUT PULONG              ResultLength OPTIONAL);

NTSTATUS
NTAPI
fnNtQueryObject(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTSTATUS
NTAPI
pfnNtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);
NTSTATUS fnNtWow64QueryInformationProcess64(
    IN  HANDLE ProcessHandle,
    IN  ULONG  ProcessInformationClass,
    OUT PVOID  ProcessInformation64,
    IN  ULONG  Length,
    OUT PULONG ReturnLength = NULL OPTIONAL
);
NTSTATUS fnNtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength
);
NTSTATUS fnNtWow64ReadVirtualMemory64(
    IN  HANDLE   ProcessHandle,
    IN  ULONG64  BaseAddress,
    OUT PVOID    Buffer,
    IN  ULONG64  BufferLength,
    OUT PULONG64 ReturnLength
);