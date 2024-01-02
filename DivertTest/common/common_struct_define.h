#pragma once
#include <Windows.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L) 
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)
template <int n>
using const_int = std::integral_constant<int, n>;

template<typename T>
constexpr bool is32bit = std::is_same_v<T, uint32_t>;

template<typename T, typename T32, typename T64>
using type_32_64 = std::conditional_t<is32bit<T>, T32, T64>;

template<typename T, int v32, int v64>
constexpr int int_32_64 = std::conditional_t<is32bit<T>, const_int<v32>, const_int<v64>>::value;

template <typename T>
struct _LIST_ENTRY_T
{
    T Flink;
    T Blink;
};
template <typename T>
struct _UNICODE_STRING_T
{
    using type = T;

    uint16_t Length;
    uint16_t MaximumLength;
    T Buffer;
};
template<typename T>
struct _PEB_LDR_DATA2_T
{
    uint32_t Length;
    uint8_t Initialized;
    T SsHandle;
    _LIST_ENTRY_T<T> InLoadOrderModuleList;
    _LIST_ENTRY_T<T> InMemoryOrderModuleList;
    _LIST_ENTRY_T<T> InInitializationOrderModuleList;
    T EntryInProgress;
    uint8_t ShutdownInProgress;
    T ShutdownThreadId;
};

template<typename T>
struct _PEB_T
{
    static_assert(std::is_same_v<T, uint32_t> || std::is_same_v<T, uint64_t>, "T must be uint32_t or uint64_t");

    uint8_t InheritedAddressSpace;
    uint8_t ReadImageFileExecOptions;
    uint8_t BeingDebugged;
    union
    {
        uint8_t BitField;
        struct
        {
            uint8_t ImageUsesLargePages : 1;
            uint8_t IsProtectedProcess : 1;
            uint8_t IsImageDynamicallyRelocated : 1;
            uint8_t SkipPatchingUser32Forwarders : 1;
            uint8_t IsPackagedProcess : 1;
            uint8_t IsAppContainer : 1;
            uint8_t IsProtectedProcessLight : 1;
            uint8_t SpareBits : 1;
        };
    };
    T Mutant;
    T ImageBaseAddress;
    T Ldr;
    T ProcessParameters;
    T SubSystemData;
    T ProcessHeap;
    T FastPebLock;
    T AtlThunkSListPtr;
    T IFEOKey;
    union
    {
        T CrossProcessFlags;
        struct
        {
            uint32_t ProcessInJob : 1;
            uint32_t ProcessInitializing : 1;
            uint32_t ProcessUsingVEH : 1;
            uint32_t ProcessUsingVCH : 1;
            uint32_t ProcessUsingFTH : 1;
            uint32_t ReservedBits0 : 27;
        };
    };
    union
    {
        T KernelCallbackTable;
        T UserSharedInfoPtr;
    };
    uint32_t SystemReserved;
    uint32_t AtlThunkSListPtr32;
    T ApiSetMap;
    union
    {
        uint32_t TlsExpansionCounter;
        T Padding2;
    };
    T TlsBitmap;
    uint32_t TlsBitmapBits[2];
    T ReadOnlySharedMemoryBase;
    T SparePvoid0;
    T ReadOnlyStaticServerData;
    T AnsiCodePageData;
    T OemCodePageData;
    T UnicodeCaseTableData;
    uint32_t NumberOfProcessors;
    uint32_t NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    T HeapSegmentReserve;
    T HeapSegmentCommit;
    T HeapDeCommitTotalFreeThreshold;
    T HeapDeCommitFreeBlockThreshold;
    uint32_t NumberOfHeaps;
    uint32_t MaximumNumberOfHeaps;
    T ProcessHeaps;
    T GdiSharedHandleTable;
    T ProcessStarterHelper;
    union
    {
        uint32_t GdiDCAttributeList;
        T Padding3;
    };
    T LoaderLock;
    uint32_t OSMajorVersion;
    uint32_t OSMinorVersion;
    uint16_t OSBuildNumber;
    uint16_t OSCSDVersion;
    uint32_t OSPlatformId;
    uint32_t ImageSubsystem;
    uint32_t ImageSubsystemMajorVersion;
    union
    {
        uint32_t ImageSubsystemMinorVersion;
        T Padding4;
    };
    T ActiveProcessAffinityMask;
    uint32_t GdiHandleBuffer[int_32_64<T, 34, 60>];
    T PostProcessInitRoutine;
    T TlsExpansionBitmap;
    uint32_t TlsExpansionBitmapBits[32];
    union
    {
        uint32_t SessionId;
        T Padding5;
    };
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    T pShimData;
    T AppCompatInfo;
    _UNICODE_STRING_T<T> CSDVersion;
    T ActivationContextData;
    T ProcessAssemblyStorageMap;
    T SystemDefaultActivationContextData;
    T SystemAssemblyStorageMap;
    T MinimumStackCommit;
    T FlsCallback;
    _LIST_ENTRY_T<T> FlsListHead;
    T FlsBitmap;
    uint32_t FlsBitmapBits[4];
    uint32_t FlsHighIndex;
    T WerRegistrationData;
    T WerShipAssertPtr;
    T pUnused;
    T pImageHeaderHash;
    union
    {
        uint64_t TracingFlags;
        struct
        {
            uint32_t HeapTracingEnabled : 1;
            uint32_t CritSecTracingEnabled : 1;
            uint32_t LibLoaderTracingEnabled : 1;
            uint32_t SpareTracingBits : 29;
        };
    };
    T CsrServerReadOnlySharedMemoryBase;
};

template<typename T>
struct _LDR_DATA_TABLE_ENTRY_BASE_T
{
    _LIST_ENTRY_T<T> InLoadOrderLinks;
    _LIST_ENTRY_T<T> InMemoryOrderLinks;
    _LIST_ENTRY_T<T> InInitializationOrderLinks;
    T DllBase;
    T EntryPoint;
    uint32_t SizeOfImage;
    _UNICODE_STRING_T<T> FullDllName;
    _UNICODE_STRING_T<T> BaseDllName;
    uint32_t Flags;
    uint16_t LoadCount;
    uint16_t TlsIndex;
    _LIST_ENTRY_T<T> HashLinks;
    uint32_t TimeDateStamp;
    T EntryPointActivationContext;
    T PatchInformation;
};
typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: HANDLE
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // 10, qs: PROCESS_LDT_INFORMATION
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only)
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information,
    ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
    ProcessAffinityMask, // s: KAFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // 30, q: HANDLE
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    ProcessIoPriority, // qs: ULONG
    ProcessExecuteFlags, // qs: ULONG
    ProcessResourceManagement,
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // q: ULONG
    ProcessInstrumentationCallback, // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // q: ULONG_PTR
    ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode,
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable, // since WINBLUE
    ProcessCheckStackExtentsMode,
    ProcessCommandLineInformation, // 60, q: UNICODE_STRING
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation,
    ProcessAllowedCpuSetsInformation,
    ProcessReserved1Information,
    ProcessReserved2Information,
    ProcessSubsystemProcess, // 70
    ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
    MaxProcessInfoClass
} PROCESSINFOCLASS;
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemHandleInformation = 16,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemHandleInformationEx = 64,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;
typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation
}MEMORY_INFORMATION_CLASS;
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;
typedef enum _SECTION_INFORMATION_CLASS {
    SectionBasicInformation = 0,
} SECTION_INFORMATION_CLASS;
typedef struct _PROCESS_BASIC_INFORMATION32 {
    NTSTATUS ExitStatus;
    uint32_t PebBaseAddress;
    uint32_t AffinityMask;
    uint32_t BasePriority;
    uint32_t UniqueProcessId;
    uint32_t InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32;
struct _PROCESS_BASIC_INFORMATION_64
{
    NTSTATUS    ExitStatus;
    uint32_t    Reserved0;
    DWORD64	    PebBaseAddress;
    DWORD64	    AffinityMask;
    LONG	    BasePriority;
    ULONG	    Reserved1;
    DWORD64	    uUniqueProcessId;
    DWORD64	    uInheritedFromUniqueProcessId;
};
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;
typedef struct _SYSTEM_HANDLE {
    HANDLE ProcessId;
    BYTE ObjectType;
    BYTE Flags;
    WORD Handle;
    PVOID Address;
    DWORD GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    DWORD HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_EX {
    PVOID Object;
    HANDLE ProcessId;
    HANDLE Handle;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_EX, * PSYSTEM_HANDLE_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR HandleCount;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;
typedef struct _OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;
typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG          Reserved[22];
} PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef struct _SECTION_BASIC_INFORMATION {
    ULONG			SectionBaseAddress;
    ULONG			SectionAttributes;
    LARGE_INTEGER	SectionSize;
} SECTION_BASIC_INFORMATION;








// Type of barrier
enum eBarrier
{
    wow_32_32 = 0,  // Both processes are WoW64 
    wow_32_64,      // Managing x64 process from WoW64 process
};

struct Wow64Barrier
{
    eBarrier type = wow_32_32;
    bool sourceWow64 = false;
    bool targetWow64 = false;
    bool x86OS = false;
};