// http://jz.pe.kr

#ifndef _WINDOWS_
#include <windows.h>
#endif


#define vmalloc( size )		VirtualAlloc( NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE )
#define valloc( size )		VirtualAlloc( NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE )
#define vfree( addr )		VirtualFree( addr, 0, MEM_RELEASE )
#define bitchk( var, bit )	( ( ( var & bit ) == bit ) ? 1 : 0 )
#define chkbit				bitchk
#define toggle( a )			do { if( a == TRUE ){  a = FALSE; } else { a = TRUE; } }while(0);


// Çò°¥¸®´Ï±î..
#define ImpNameTable		OriginalFirstThunk
#define ImpAddrTable		FirstThunk

#define EG( var, label )	do{ if( var == FALSE ) goto label; }while(0)

#ifdef __cplusplus
extern "C"{
#endif

BOOL GetThreadStartRoutine( DWORD *pdwAddress );
//DWORD __declspec(naked) GetThreadId();
//DWORD __declspec(naked) GetProcessId();
BOOL DoesFileExist( char *path );
void* GetTebAddr( DWORD threadId, OPTIONAL DWORD fs );
BOOL MoveTotalDir( char *src, char *dst, OPTIONAL OUT int *pnTotalMoved=NULL );
BOOL RenameMoveFile( char *src, char *dst, OPTIONAL OUT char *renamed_dst=NULL );
BOOL RenameCopyFile( char *src, char *dst, OPTIONAL OUT char *renamed_dst=NULL );
BOOL CopyToDir( char *src, char *dstpath, BOOL bFailIfExists=FALSE );
BOOL MoveToDir( char *src, char *dstpath, BOOL bFailIfExists=FALSE );
BOOL RenameCopyToDir( char *src, char *dstpath, OPTIONAL OUT char *renamed_dst=NULL );

BOOL IsThereFileInDir( char *dirpath );
int GetSimilarityPE( DWORD type_1_ep__2_firstsection, int size, char *path1, char *path2 );
int GetSimilarity( DWORD offset, int size, char *path1, char *path2 );
int GetSimilarityBuf( BYTE *buf1, BYTE *buf2, int size );
int GetSimilarityInstruction( DWORD offset, int size, char *path1, char *path2 );
DWORD GetEPOffset( HANDLE hFile );
BOOL ReadFirstSection( char *filepath, 
					   void *buf, 
					   int bufsize, 
					   OPTIONAL OUT int *npReadResult,
					   OPTIONAL OUT int *npFirstSectionSize );

char *DivideCmdLine( char *cmdline, int index );
BOOL ReadFileAt( char *path, int offset, OUT void *buf, int bufsize, OPTIONAL OUT int *pnReadResult=NULL, OPTIONAL OUT int *LastError=NULL );
BOOL WriteFileAt( char *path, int offset, void *buf, int bufsize, OPTIONAL BOOL convLineFeed=FALSE, OPTIONAL OUT int *pwritten=NULL );


int atoh( char *hexstring );
BOOL strtobytearray( char *inputstr, BYTE *outputbuffer, OPTIONAL int outputbufferlen = 0 );
char *htoa( DWORD input, OUT char *hexstring, OPTIONAL BOOL uppercase=FALSE, OPTIONAL IN int fillzerosize=0 );

void mylog( char *filename, char *format, ... );
DWORD GetPebAddrByPid( DWORD pid );
DWORD GetPebAddrByHandle( HANDLE hProcess );

DWORD MyGetFileSize( char *path );


DWORD GetCrc32( DWORD dwCrc, const void* pBuf, int nLen );
DWORD GetCrcOfByte( DWORD dwCrc, BYTE bytedata );



BOOL SearchLoadedDllNameWithAddr( DWORD addr, OUT char *dllname, int bufsize );
BOOL SearchLoadedDllNameWithAddrW( DWORD addr, OUT WCHAR *wchDllname, int bufsize );


BOOL mread( DWORD addr, OUT void *buf, int size );
BOOL mwrite( DWORD addr, void *buf, int size );

// remote read/write
BOOL rread( HANDLE hproc, DWORD addr, OUT void *buf, int size );
BOOL rwrite( HANDLE hproc, DWORD addr, void *buf, int size );

BOOL rread2( DWORD pid, DWORD addr, OUT void *buf, int size );
BOOL rwrite2( DWORD pid, DWORD addr, void *buf, int size );



BOOL IsSameFile( char *path1, char *path2 );


DWORD GetCeiling( DWORD ulValue, DWORD ulAlign );
DWORD GetFloor( DWORD ulValue, DWORD ulAlign );

#define WILDCARD
int mycmp( void *buf1, WILDCARD void *buf2, int size );

BOOL Tail( char *filepath, char *buf, int bufsize );


BOOL FindProcessWithName( char *exename, OPTIONAL OUT DWORD *pdwProcessId );


void hexdump( BYTE *buf, DWORD from, DWORD size );


void RisePriv();

#ifdef __cplusplus
}
#endif

