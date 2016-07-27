// jz.pe.kr

//#include <Ntsecapi.h>
#define _WIN32_WINNT 0x0501

#define PEB_LDR_DATA PEB_LDR_DATAxxx
#define _PEB_LDR_DATA _PEB_LDR_DATAxxx
#define PPEB_LDR_DATA PPEB_LDR_DATAxxx
#define RTL_USER_PROCESS_PARAMETERS RTL_USER_PROCESS_PARAMETERSxxx
#define _RTL_USER_PROCESS_PARAMETERS _RTL_USER_PROCESS_PARAMETERSxxx
#define PRTL_USER_PROCESS_PARAMETERS PRTL_USER_PROCESS_PARAMETERSxxx
#include <WInternl.h>
#undef RTL_USER_PROCESS_PARAMETERS
#undef _RTL_USER_PROCESS_PARAMETERS
#undef PRTL_USER_PROCESS_PARAMETERS
#undef PEB_LDR_DATA
#undef _PEB_LDR_DATA
#undef PPEB_LDR_DATA


typedef void* PPEBLOCKROUTINE;
typedef void** PPVOID;




typedef struct dll_list_entry
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	DWORD imagebase;
	DWORD entrypoint;
	DWORD sizeofimage;
	UNICODE_STRING uniFullPath;
	UNICODE_STRING uniModuleName;
}dll_list_entry;



typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;


typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT                  Flags;
	USHORT                  Length;
	ULONG                   TimeStamp;
	UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;



typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG                   MaximumLength;
	ULONG                   Length;
	ULONG                   Flags;
	ULONG                   DebugFlags;
	PVOID                   ConsoleHandle;
	ULONG                   ConsoleFlags;
	HANDLE                  StdInputHandle;
	HANDLE                  StdOutputHandle;
	HANDLE                  StdErrorHandle;
	UNICODE_STRING          CurrentDirectoryPath;
	HANDLE                  CurrentDirectoryHandle;
	UNICODE_STRING          DllPath;
	UNICODE_STRING          ImagePathName;
	UNICODE_STRING          CommandLine;
	PVOID                   Environment;
	ULONG                   StartingPositionLeft;
	ULONG                   StartingPositionTop;
	ULONG                   Width;
	ULONG                   Height;
	ULONG                   CharWidth;
	ULONG                   CharHeight;
	ULONG                   ConsoleTextAttributes;
	ULONG                   WindowFlags;
	ULONG                   ShowWindowFlags;
	UNICODE_STRING          WindowTitle;
	UNICODE_STRING          DesktopName;
	UNICODE_STRING          ShellInfo;
	UNICODE_STRING          RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;



typedef struct PEB_FREE_BLOCK {
	PEB_FREE_BLOCK          *Next;
	ULONG                   Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;


typedef struct _PEB2 {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PPEBLOCKROUTINE         FastPebLockRoutine;
	PPEBLOCKROUTINE         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PPVOID                  KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PPEB_FREE_BLOCK         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PPVOID                  ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PPVOID                  *ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
	
} PEB2, *PPEB2, REALPEB;





typedef struct _CLIENT_ID
{
     PVOID UniqueProcess;
     PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;


typedef struct _TEB2 {
	NT_TIB                  Tib;
	PVOID                   EnvironmentPointer;
	CLIENT_ID               Cid;
	PVOID                   ActiveRpcInfo;
	PVOID                   ThreadLocalStoragePointer;
	PPEB2                   Peb;
	ULONG                   LastErrorValue;
	ULONG                   CountOfOwnedCriticalSections;
	PVOID                   CsrClientThread;
	PVOID                   Win32ThreadInfo;
	ULONG                   Win32ClientInfo[0x1F];
	PVOID                   WOW32Reserved;
	ULONG                   CurrentLocale;
	ULONG                   FpSoftwareStatusRegister;
	PVOID                   SystemReserved1[0x36];
	PVOID                   Spare1;
	ULONG                   ExceptionCode;
	ULONG                   SpareBytes1[0x28];
	PVOID                   SystemReserved2[0xA];
	ULONG                   GdiRgn;
	ULONG                   GdiPen;
	ULONG                   GdiBrush;
	CLIENT_ID               RealClientId;
	PVOID                   GdiCachedProcessHandle;
	ULONG                   GdiClientPID;
	ULONG                   GdiClientTID;
	PVOID                   GdiThreadLocaleInfo;
	PVOID                   UserReserved[5];
	PVOID                   GlDispatchTable[0x118];
	ULONG                   GlReserved1[0x1A];
	PVOID                   GlReserved2;
	PVOID                   GlSectionInfo;
	PVOID                   GlSection;
	PVOID                   GlTable;
	PVOID                   GlCurrentRC;
	PVOID                   GlContext;
	NTSTATUS                LastStatusValue;
	UNICODE_STRING          StaticUnicodeString;
	WCHAR                   StaticUnicodeBuffer[0x105];
	PVOID                   DeallocationStack;
	PVOID                   TlsSlots[0x40];
	LIST_ENTRY              TlsLinks;
	PVOID                   Vdm;
	PVOID                   ReservedForNtRpc;
	PVOID                   DbgSsReserved[0x2];
	ULONG                   HardErrorDisabled;
	PVOID                   Instrumentation[0x10];
	PVOID                   WinSockData;
	ULONG                   GdiBatchCount;
	ULONG                   Spare2;
	ULONG                   Spare3;
	ULONG                   Spare4;
	PVOID                   ReservedForOle;
	ULONG                   WaitingOnLoaderLock;
	PVOID                   StackCommit;
	PVOID                   StackCommitMax;
	PVOID                   StackReserved;
} TEB2, *PTEB2;

