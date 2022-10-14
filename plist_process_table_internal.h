
#ifndef _PLIST_PROCESS_TABLE_INTERNAL_
#define _PLIST_PROCESS_TABLE_INTERNAL_

#include <PshPack1.h>

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,             // obsolete...delete
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass,  // MaxSystemInfoClass should always be the last enum

    SystemPageMemoryInformation = 123
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG Unknown; //Always contains zero
    ULONG MaximumIncrement; //һ��ʱ�ӵļ�����λ
    ULONG PhysicalPageSize; //һ���ڴ�ҳ�Ĵ�С
    ULONG NumberOfPhysicalPages; //ϵͳ�����Ŷ��ٸ�ҳ
    ULONG LowestPhysicalPage; //�Ͷ��ڴ�ҳ
    ULONG HighestPhysicalPage; //�߶��ڴ�ҳ
    ULONG AllocationGranularity;
    ULONG LowestUserAddress; //�ض��û���ַ
    ULONG HighestUserAddress; //�߶��û���ַ
    ULONG ActiveProcessors; //����Ĵ�����
    UCHAR NumberProcessors; //�ж��ٸ�������
}SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaxLength;
	PWSTR Buffer;

}UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
	ULONG NumberOfThread;
	LARGE_INTEGER WorkingSetPrivateSize;
    BYTE Reserved1[40];
	UNICODE_STRING ImageName;
	ULONG BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved3;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _PRELATIVE_NAME{
    UNICODE_STRING Name;
    HANDLE CurrentDir;
} PRELATIVE_NAME, *PPRELATIVE_NAME;


#include <PopPack.h>

typedef NTSTATUS (WINAPI *LPFN_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

struct plist_pid2hwnd_node 
{
	unsigned long	pid;
	HWND			hwnd;

	UT_hash_handle	hh;
};
#endif
