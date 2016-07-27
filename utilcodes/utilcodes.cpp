

#ifdef UNICODE
#	undef UNICODE
#endif
#ifdef _UNICODE
#	undef _UNICODE
#endif


#include <windows.h>
#include "utilcodes.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
//#include <disasm/anotherdisasm/disasm.h>
#include <tchar.h>
#include <undocumented.h>
#include <TLHELP32.H>



#pragma warning( disable : 4127 )



BOOL GetThreadStartRoutine( DWORD *pdwAddress )
{
	STARTUPINFO suInfo = {0,};
	PROCESS_INFORMATION procInfo = {0,};
	DWORD dwThreadId;
	DEBUG_EVENT dbgEvent;
	HANDLE hThread;
	CONTEXT ct = {0,};


	suInfo.cb = sizeof(suInfo);

	if( CreateProcess(  NULL,
						"notepad.exe",
						NULL,
						NULL,
						FALSE,
						DEBUG_ONLY_THIS_PROCESS,
						NULL,
						NULL,
						&suInfo,
						&procInfo ) == FALSE )
	{
		return FALSE;
	}

	// process는 현재 suspended
	hThread = CreateRemoteThread(	procInfo.hProcess, 
									NULL,
									0,
									NULL, 
									NULL, 
									CREATE_SUSPENDED, 
									&dwThreadId );

	ct.ContextFlags = CONTEXT_FULL;
	if( GetThreadContext( hThread, &ct ) == FALSE )
		return FALSE;

	*pdwAddress = ct.Eip;


	TerminateThread( hThread, 0 );
	CloseHandle( hThread );
	TerminateProcess( procInfo.hProcess, 0 );
	CloseHandle( procInfo.hProcess );

	return TRUE;


	ResumeThread( hThread );

	while( 1 )
	{
		if( WaitForDebugEvent( &dbgEvent, 100 ) == FALSE )
		{
			return FALSE;
		}

		if( dbgEvent.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT )
		{
			*pdwAddress = (DWORD)dbgEvent.u.CreateThread.lpStartAddress;


			// terminate process
			if( TerminateProcess( procInfo.hProcess, 0 ) == FALSE )
			{
				// one more time;
				if( TerminateProcess( procInfo.hProcess, 0 ) == FALSE )
				{
					return FALSE;
				}
			}
			
			return TRUE;
		}

		ContinueDebugEvent( procInfo.dwProcessId, procInfo.dwThreadId, DBG_CONTINUE );
	}

}




DWORD __declspec(naked) GetThreadId()
{
	_asm{
		mov eax, fs:[0x24]
		ret
	}
}


DWORD __declspec(naked) GetProcessId()
{
	_asm{
		mov eax, fs:[0x20]
		ret
	}
}



BOOL DoesFileExist( char *path )
{
	HANDLE hFile = NULL;
	BOOL result;

	hFile = CreateFile( path, 
						GENERIC_READ, 
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						NULL, 
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL, 
						NULL );
	if( hFile == INVALID_HANDLE_VALUE )
	{
		if( GetLastError() == ERROR_FILE_NOT_FOUND || 
			GetLastError() == ERROR_PATH_NOT_FOUND )
		{
			result = FALSE;
			goto _END;
		}
	}

	result = TRUE;

_END:

	if( hFile != NULL && hFile != INVALID_HANDLE_VALUE )
	{
		CloseHandle( hFile );
	}

	return result;

}




void* GetTebAddr( DWORD threadId, OPTIONAL DWORD fs )
{
	LDT_ENTRY le;
	HANDLE hThread;
	DWORD teb;

	typedef HANDLE (*OPENTHREAD)( DWORD, BOOL, DWORD );
	OPENTHREAD OpenThread = (OPENTHREAD)GetProcAddress( GetModuleHandle( "kernel32.dll" ), "OpenThread" );

	hThread = OpenThread( THREAD_ALL_ACCESS, FALSE, threadId );
	if( hThread == NULL )
		return NULL;

	if( fs == 0 )
	{
		CONTEXT ct;
		memset( &ct, 0, sizeof(ct) );
		ct.ContextFlags = CONTEXT_FULL;
		GetThreadContext( hThread, &ct );
		fs = ct.SegFs;
	}

	GetThreadSelectorEntry( hThread, fs, &le );

	CloseHandle( hThread );

	teb = le.BaseLow | ( le.HighWord.Bytes.BaseHi << 24 ) | ( le.HighWord.Bytes.BaseMid << 16 ) ;

	return (void*)teb;

}



BOOL RenameMoveFile( char *src, char *dst, OPTIONAL OUT char *renamed_dst )
{
	char renamed[MAX_PATH];
	int index = 0;

	if( MoveFile( src, dst ) == FALSE )
	{
		if( GetLastError() == ERROR_FILE_EXISTS || 
			GetLastError() == ERROR_ALREADY_EXISTS )
		{
			while( 1 )
			{
				sprintf( renamed, "%s_%08x", dst, index ++ );

				if( DoesFileExist( renamed ) == FALSE )
				{
					if( MoveFile( src, renamed ) == FALSE )
					{
						return FALSE;
					}
					if( renamed_dst != NULL )
					{
						strcpy( renamed_dst, renamed );
					}
					return TRUE;
				}
			}

		}
		else
		{
			// unknown reason
			return FALSE;
		}

		if( renamed_dst != NULL )
		{
			strcpy( renamed_dst, renamed );
		}

	}
	else
	{
		// CopyFile() success
		strcpy( renamed_dst, src );
	}
	

	return TRUE;
}	




BOOL MoveTotalDir( char *src, char *dst, OPTIONAL OUT int *pnTotalMoved )
{
	BOOL result = TRUE;
	HANDLE hFind = NULL;
	WIN32_FIND_DATA fd;
	char tmp[MAX_PATH];
	char tmp2[MAX_PATH];
	int totalMoved = 0;

	strcpy( tmp, src );
	strcat( tmp, "\\*" );
	hFind = FindFirstFile( tmp, &fd );
	if( hFind == INVALID_HANDLE_VALUE )
	{
		result = FALSE;
		goto _END;
	}

	do
	{
		if( strcmp( fd.cFileName, "." ) == 0 || strcmp( fd.cFileName, ".." ) == 0 )
			continue;
		totalMoved ++;
		strcpy( tmp, src );
		strcat( tmp, "\\" );
		strcat( tmp, fd.cFileName );
		strcpy( tmp2, dst );
		strcat( tmp2, "\\" );
		strcat( tmp2, fd.cFileName );

		if( RenameMoveFile( tmp, tmp2 ) == FALSE )
		{
			result = FALSE;
			goto _END;
		}

	}while( FindNextFile( hFind, &fd ) );


	if( pnTotalMoved != NULL )
	{
		*pnTotalMoved = totalMoved;
	}


_END:

	if( hFind != NULL )
		FindClose( hFind );

	return result;

}


BOOL IsThereFileInDir( char *dirpath )
{
	BOOL result = TRUE;
	HANDLE hFind = NULL;
	WIN32_FIND_DATA fd;
	char tmp[MAX_PATH];

	strcpy( tmp, dirpath );
	strcat( tmp, "\\*" );

	hFind = FindFirstFile( tmp, &fd );
	if( hFind == INVALID_HANDLE_VALUE )
	{
		result = FALSE;
		goto _END;
	}

	do
	{
		if( strcmp( fd.cFileName, "." ) == 0 || strcmp( fd.cFileName, ".." ) == 0 )
			continue;
		result = TRUE;
		goto _END;

	}while( FindNextFile( hFind, &fd ) );


	result = FALSE;


_END:

	if( hFind != NULL )
		FindClose( hFind );

	return result;

}


BOOL RenameCopyFile( char *src, char *dst, OPTIONAL OUT char *renamed_dst )
{
	char renamed[MAX_PATH];
	int index = 0;

	if( CopyFile( src, dst, TRUE ) == FALSE )
	{
		if( GetLastError() == ERROR_FILE_EXISTS || 
			GetLastError() == ERROR_ALREADY_EXISTS )
		{
			while( 1 )
			{
				sprintf( renamed, "%s_%08x", dst, index ++ );

				if( DoesFileExist( renamed ) == FALSE )
				{
					if( CopyFile( src, renamed, FALSE ) == FALSE )
					{
						return FALSE;
					}
					if( renamed_dst != NULL )
					{
						strcpy( renamed_dst, renamed );
					}
					return TRUE;
				}
			}

		}
		else
		{
			// unknown reason
			return FALSE;
		}

		if( renamed_dst != NULL )
		{
			strcpy( renamed_dst, renamed );
		}

	}
	else
	{
		// CopyFile() success
		if( renamed_dst != NULL )
		{
			strcpy( renamed_dst, renamed );
		}
	}
	

	return TRUE;
}	




int GetSimilarityPE( DWORD type_1_ep__2_firstsection, int size, char *path1, char *path2 )
{
	HANDLE hFile1 = INVALID_HANDLE_VALUE, hFile2 = INVALID_HANDLE_VALUE;
	int result = 0;
	int i;
	int same = 0, different = 0;
	BYTE *buf1 = NULL, *buf2 = NULL;
	int ReadResult1 = 0, ReadResult2 = 0;
	DWORD start1, start2;
	int compSize;

	buf1 = (BYTE*)malloc( size );
	if( buf1 == NULL )
	{
		result = 0;
		goto _END;
	}
	buf2 = (BYTE*)malloc( size );
	if( buf2 == NULL )
	{
		result = 0;
		goto _END;
	}



	if( type_1_ep__2_firstsection == 1 )
	{
		hFile1 = CreateFile( path1, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
		hFile2 = CreateFile( path2, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
		if( hFile1 == INVALID_HANDLE_VALUE || hFile2 == INVALID_HANDLE_VALUE )
		{
			result = -1;
			goto _END;
		}

		start1 = GetEPOffset( hFile1 );
		start2 = GetEPOffset( hFile2 );
		if( start1 == -1 || start2 == -1 )
		{
			result = -1;
			goto _END;
		}

		SetFilePointer( hFile1, start1, NULL, FILE_BEGIN );
		SetFilePointer( hFile2, start2, NULL, FILE_BEGIN );

		ReadFile( hFile1, buf1, size, (DWORD*)&ReadResult1, NULL );
		ReadFile( hFile2, buf2, size, (DWORD*)&ReadResult2, NULL );
	}


	else if( type_1_ep__2_firstsection == 2 )
	{
		ReadFirstSection( path1, buf1, size, &ReadResult1, NULL );
		ReadFirstSection( path2, buf2, size, &ReadResult2, NULL );
	}

	compSize = min( ReadResult1, ReadResult2 );

	for( i = 0; i < size; i ++ )
	{
		if( buf1[i] == buf2[i] )
		{
			same ++;
		}
		else
		{
			different ++;
		}
	}

	result = (int)( ( (float)same / (same + different) ) * 100 );


_END:

	if( hFile1 != INVALID_HANDLE_VALUE )
	{
		CloseHandle( hFile1 );
	}
	if( hFile2 != INVALID_HANDLE_VALUE )
	{
		CloseHandle( hFile2 );
	}

	if( buf1 != NULL )
	{
		free( buf1 );
	}
	if( buf2 != NULL )
	{
		free( buf2 );
	}

	return result;
}



int GetSimilarity( DWORD offset, int size, char *path1, char *path2 )
{
	HANDLE hFile1 = INVALID_HANDLE_VALUE, hFile2 = INVALID_HANDLE_VALUE;
	int result = 0;
	int i;
	int same = 0, different = 0;
	BYTE *buf1 = NULL, *buf2 = NULL;
	int ReadResult1 = 0, ReadResult2 = 0;

	int compSize;

	buf1 = (BYTE*)malloc( size );
	if( buf1 == NULL )
	{
		result = 0;
		goto _END;
	}
	buf2 = (BYTE*)malloc( size );
	if( buf2 == NULL )
	{
		result = 0;
		goto _END;
	}


	if( ReadFileAt( path1, offset, buf1, size, &ReadResult1, NULL ) == FALSE ||
		ReadFileAt( path2, offset, buf2, size, &ReadResult2, NULL ) == FALSE )
	{
		result = 0; 
		goto _END;
	}


	compSize = min( ReadResult1, ReadResult2 );

	for( i = 0; i < size; i ++ )
	{
		if( buf1[i] == buf2[i] )
		{
			same ++;
		}
		else
		{
			different ++;
		}
	}

	result = (int)( ( (float)same / (same + different) ) * 100 );


_END:

	if( hFile1 != INVALID_HANDLE_VALUE )
	{
		CloseHandle( hFile1 );
	}
	if( hFile2 != INVALID_HANDLE_VALUE )
	{
		CloseHandle( hFile2 );
	}

	if( buf1 != NULL )
	{
		free( buf1 );
	}
	if( buf2 != NULL )
	{
		free( buf2 );
	}

	return result;
}






int GetSimilarityBuf( BYTE *buf1, BYTE *buf2, int size )
{
	int i;
	int same = 0, different = 0;
	for( i = 0; i < size; i ++ )
	{
		if( buf1[i] == buf2[i] )
		{
			same ++;
		}
		else
		{
			different ++;
		}
	}

	// prevent div by zero
	if( same + different == 0 )
	{
		return 0;
	}

	return (int)( ( (float)same / (same + different) ) * 100 );

}

/*
int GetSimilarityInstruction( DWORD offset, int size, char *path1, char *path2 )
{
	HANDLE hFile1 = INVALID_HANDLE_VALUE, hFile2 = INVALID_HANDLE_VALUE;
	int result = 0;
	int i, j;
	int same = 0, different = 0;
	BYTE *buf1 = NULL, *buf2 = NULL;
	int ReadResult1 = 0, ReadResult2 = 0;
	_dis_data data;
	int len1, len2;

	int compSize;

	buf1 = (BYTE*)malloc( size );
	if( buf1 == NULL )
	{
		result = 0;
		goto _END;
	}
	buf2 = (BYTE*)malloc( size );
	if( buf2 == NULL )
	{
		result = 0;
		goto _END;
	}


	if( ReadFileAt( path1, offset, buf1, size, &ReadResult1, NULL ) == FALSE ||
		ReadFileAt( path2, offset, buf2, size, &ReadResult2, NULL ) == FALSE )
	{
		result = 0; 
		goto _END;
	}


	compSize = min( ReadResult1, ReadResult2 );

	for( i = 0, j = 0; ( i < size ) && ( j < size ); )
	{
		if( buf1[i] == buf2[j] )
		{
			same ++;
		}
		else
		{
			different ++;
		}

		// disassembly len
		len1 = _disasm( buf1+i, &data );
		if( len1 == 0 )
			len1 = 1;
		i += len1;

		len2 = _disasm( buf2+j, &data );
		if( len2 == 0 )
			len2 = 1;
		j += len2;
	}

	result = (int)( ( (float)same / (same + different) ) * 100 );


_END:

	if( hFile1 != INVALID_HANDLE_VALUE )
	{
		CloseHandle( hFile1 );
	}
	if( hFile2 != INVALID_HANDLE_VALUE )
	{
		CloseHandle( hFile2 );
	}

	if( buf1 != NULL )
	{
		free( buf1 );
	}
	if( buf2 != NULL )
	{
		free( buf2 );
	}

	return result;
}


*/

DWORD GetEPOffset( HANDLE hFile )
{
	IMAGE_DOS_HEADER dh;
	IMAGE_NT_HEADERS nh;
	DWORD dwRW;
	BYTE buf[0x1000];
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );

	if( ReadFile( hFile,
				  buf,
				  0x1000,
				  &dwRW,
				  NULL ) == FALSE )
	{
		return (DWORD)-1;
	}

	if( buf[0] != 'M' || buf[1] != 'Z' )
	{
		return (DWORD)-1;
	}

	memcpy( &dh, buf, sizeof(dh) );

	memcpy( &nh, (void*)(buf + dh.e_lfanew), sizeof(nh) );

	if( nh.Signature != 0x4550 )
	{
		return (DWORD)-1;
	}

	return nh.OptionalHeader.AddressOfEntryPoint;

}


BOOL ReadFirstSection( char *filepath, 
							  void *buf, 
							  int bufsize, 
							  OPTIONAL OUT int *npReadResult,
							  OPTIONAL OUT int *npFirstSectionSize )
{
	BOOL result = TRUE;
	int read;
	FILE *fp = NULL;
	IMAGE_DOS_HEADER *dh;
	IMAGE_NT_HEADERS *nh;
	IMAGE_SECTION_HEADER *sh;
	BYTE tmpbuf[0x1000] = {0,};
	int sectionsize;
	int tmp;

	fp = fopen( filepath, "rb" );
	if( fp == NULL )
	{
		result = FALSE;
		goto _END;
	}



	fread( tmpbuf, 1, 0x1000, fp );

	dh = (IMAGE_DOS_HEADER*)tmpbuf;
	nh = (IMAGE_NT_HEADERS*)( tmpbuf + dh->e_lfanew );

	tmp = nh->FileHeader.SizeOfOptionalHeader;
	if( tmp > 0xe0 )
		tmp = 0xe0;

	sh = (IMAGE_SECTION_HEADER*)( (BYTE*)&nh->OptionalHeader + tmp );

	fseek( fp, sh->PointerToRawData, SEEK_SET );

	sectionsize = sh->SizeOfRawData;


	read = fread( buf, 1, bufsize, fp );

	if( npReadResult != NULL )
	{
		*npReadResult = read;
	}

	if( npFirstSectionSize != NULL )
	{
		*npFirstSectionSize = sectionsize;
	}

_END:

	if( fp != NULL )
	{
		fclose( fp );
	}

	return result;

}





char *DivideCmdLine( char *cmdline, int index )
{
//	char *ptr;
	int i;
	BOOL qtfound = FALSE;


	for( i = strlen( cmdline ); i > 0; i -- )
	{
		if( cmdline[i] == '"' )
		{
			toggle( qtfound );
		}

		if( qtfound == FALSE )
		{
			if( cmdline[i] == ' ' )
			{
				index --;
				if( index == 0 )
				{
					return cmdline + i + 1;
				}
			}
		}
	}

	// not divided
	return NULL;
}


BOOL ReadFileAt( char *path, int offset, void *buf, int bufsize, OPTIONAL int *pnReadResult, OPTIONAL int *LastError )
{
	BOOL result = TRUE;
	HANDLE hf = INVALID_HANDLE_VALUE;
	int readresult;

	if( LastError != NULL )
	{
		*LastError = 0;
	}

	hf = CreateFile( path, 
					 GENERIC_READ, 
					 FILE_SHARE_READ|FILE_SHARE_DELETE|FILE_SHARE_WRITE,
					 NULL,
					 OPEN_EXISTING,
					 0, 
					 NULL );
	if( hf == INVALID_HANDLE_VALUE )
	{
		result = FALSE;
		if( LastError != NULL )
			*LastError = GetLastError();

		goto _END;
	}

	SetFilePointer( hf, offset, NULL, FILE_BEGIN );

	if( ReadFile( hf, buf, bufsize, (LPDWORD)&readresult, NULL ) == FALSE || readresult == 0 )
	{
		result = FALSE;
		if( LastError != NULL )
			*LastError = GetLastError();

		goto _END;
	}

	if( pnReadResult != NULL )
		*pnReadResult = readresult;

_END:

	if( hf != INVALID_HANDLE_VALUE )
		CloseHandle( hf );

	return result;

}



BOOL WriteFileAt( char *path, int offset, void *buf, int bufsize, OPTIONAL BOOL convLineFeed, OPTIONAL OUT int *pwritten )
{
	BOOL result =TRUE;
	FILE *fp = NULL;
	int written;

	if( convLineFeed == TRUE )
	{
		fp = fopen( path, "r+t" );
	}
	else
	{
		fp = fopen( path, "r+b" );
	}
	if( fp == NULL )
	{
		result = FALSE;
		goto _end;
	}

	if( offset != 0 )
		fseek( fp, offset, SEEK_SET );

	written = fwrite( buf, sizeof(BYTE), bufsize, fp );

	if( pwritten != NULL )
		*pwritten = written;


_end:

	if( fp != NULL )
		fclose( fp );

	return result;

}





int atoh( char *hexstring )
{
	char input[11];
	char *ptr = hexstring;
	int i;
	int result = 0;

	// remove 0x if there is one
	if( strnicmp( ptr, "0x", 2 ) == 0 )
		ptr += 2;

	strncpy( input, ptr, 11 );
	strlwr( input );

	// ignore hex strings longer than 8 chars
	for( i = strlen(input)-1; i >= 0; i -- )
	{
		if( input[i] == 0 )
			break;

		if( input[i] >= '0' && input[i] <= '9' )
			result += (int)( input[i] - 0x30 ) * (int)( _Pow_int( 0x10, (strlen(input)-1) - i ) );
		else if( input[i] >= 'a' && input[i] <= 'f' )
			result += (int)( input[i] - 0x57 ) * (int)( _Pow_int( 0x10, (strlen(input)-1) - i ) );
		else
			return 0;
	}

	return result;

}


BOOL strtobytearray( char *inputstr, BYTE *outputbuffer, OPTIONAL int outputbufferlen )
{
	BOOL result = FALSE;
	char *ptr;
	int i = 0;
	char tmparr[3];
	int tmpint;

	__try{
		ptr = inputstr;
		if( strnicmp( inputstr, "0x", 2 ) == 0 )
			ptr += 2;

		if( outputbufferlen == 0 )
		{
			outputbufferlen = strlen( ptr ) / 2 + 1;
		}

		while( *ptr )
		{
			strncpy( tmparr, ptr, 2 );
			tmparr[2] = 0;

			tmpint = atoh( tmparr );

			outputbuffer[i] = (BYTE)tmpint;
			i ++;
			ptr += 2;
		}
		return TRUE;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		return FALSE;
	}
}



char *htoa( DWORD input, OUT char *hexstring, OPTIONAL BOOL uppercase, OPTIONAL IN int fillzerosize )
{
	BYTE digit;
	int index;

	BOOL firstDigit = TRUE;

	if( hexstring == NULL )
		return NULL;

	index = 0;
	for( int i = 7; i >= 0; i -- )
	{
		digit = (BYTE)( ( input >> ( i * 4 ) ) & 0xf );

		if( digit == 0 && firstDigit == TRUE )
		{
			if( fillzerosize < i )
			{
				continue;
			}
		}

		if( digit >= 0 && digit <= 9 )
			hexstring[index++] = (char)( digit + '0' );
		else
		{
			if( uppercase )
				hexstring[index++] = (char)( digit + 'A' - 0xa );
			else
				hexstring[index++] = (char)( digit + 'a' - 0xa );
		}

		firstDigit = FALSE;
	}

	hexstring[index] = 0;

	return hexstring;

}







void mylog( char *filename, char *format, ... )
{
	FILE *fp = NULL;
	va_list a;
	char tmp[1024];

	fp = fopen( filename, "at" );
	if( fp == NULL )
		goto _END;

	va_start( a, format );

	vsprintf( tmp, format, a );
	fprintf( fp, "%s\n", tmp );


_END:

	if( fp != NULL )
		fclose( fp );

	return;
}




typedef LONG (WINAPI NTQIP)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
NTQIP *lpfnNtQueryInformationProcess;

DWORD GetPebAddrByPid( DWORD pid )
{
	DWORD pebaddr = 0;
	PROCESS_BASIC_INFORMATION pbi;
	DWORD dwSize;
	HMODULE hLibrary;
	HANDLE hProcess = INVALID_HANDLE_VALUE;

	hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
	if( hProcess == INVALID_HANDLE_VALUE )
	{
		goto _END;
	}

//	pbi.PebBaseAddress = (_PEB *) 0x7ffdf000;

	hLibrary = GetModuleHandle(_T("ntdll.dll"));
	if( hLibrary == NULL )
	{
		goto _END;
	}
	lpfnNtQueryInformationProcess = (NTQIP *) GetProcAddress(hLibrary, "NtQueryInformationProcess");
	if( lpfnNtQueryInformationProcess == NULL )
		goto _END;

	(*lpfnNtQueryInformationProcess)(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &dwSize);

	pebaddr = (DWORD)pbi.PebBaseAddress;


_END:
	if( hProcess != INVALID_HANDLE_VALUE )
		CloseHandle( hProcess );

	return pebaddr;
}


DWORD GetPebAddrByHandle( HANDLE hProcess )
{
	DWORD pebaddr = 0;
	PROCESS_BASIC_INFORMATION pbi;
	DWORD dwSize;
	HMODULE hLibrary; 

//	pbi.PebBaseAddress = (_PEB *) 0x7ffdf000;

	hLibrary = GetModuleHandle(_T("ntdll.dll"));
	if( hLibrary == NULL )
	{
		goto _END;
	}
	lpfnNtQueryInformationProcess = (NTQIP *) GetProcAddress(hLibrary, "NtQueryInformationProcess");
	if( lpfnNtQueryInformationProcess == NULL )
		goto _END;

	(*lpfnNtQueryInformationProcess)(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &dwSize);

	pebaddr = (DWORD)pbi.PebBaseAddress;

_END:

	return pebaddr;
}





DWORD MyGetFileSize( char *path )
{
	DWORD size;
	HANDLE hFile = CreateFile( path, GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL );
	if( hFile == INVALID_HANDLE_VALUE )
	{
		return 0;
	}

	size = GetFileSize( hFile, NULL );
	CloseHandle( hFile );

	return size;
}




static const DWORD s_adwCrcTable[256] = {
  0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
  0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
  0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
  0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
  0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
  0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
  0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
  0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
  0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
  0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
  0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
  0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
  0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
  0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
  0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
  0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
  0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
  0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
  0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
  0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
  0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
  0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
  0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
  0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
  0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
  0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
  0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
  0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
  0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
  0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
  0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
  0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
  0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
  0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
  0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
  0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
  0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
  0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
  0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
  0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
  0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
  0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
  0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
  0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
  0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
  0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
  0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
  0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
  0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
  0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
  0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
  0x2d02ef8dL
};

const DWORD* GetCrcTable()
{
	return (const DWORD*)s_adwCrcTable;
}

/* ========================================================================= */
/*#define DO1(buf) dwCrc = s_adwCrcTable[((int)dwCrc ^ ((*(BYTE*)pBuf)++)) & 0xff] ^ (dwCrc >> 8);*/
#define DO1(buf)  dwCrc = s_adwCrcTable[((int)dwCrc ^ (*buf++)) & 0xff] ^ (dwCrc >> 8); 
#define DO2(buf)  DO1(buf); DO1(buf);
#define DO4(buf)  DO2(buf); DO2(buf);
#define DO8(buf)  DO4(buf); DO4(buf);
/* ========================================================================= */

DWORD GetCrc32( DWORD dwCrc, const void* pBuf, int nLen )
{
	BYTE *pBuff = (BYTE *)pBuf;

	if ( pBuf == NULL )
		return 0L;

	dwCrc = dwCrc ^ 0xffffffffL;
	while( nLen >= 8 )
	{
		DO8( pBuff );
		nLen -= 8;
	}
	if ( nLen )
	{
		do {
			DO1( pBuff );
		} while( --nLen );
	}
	return dwCrc ^ 0xffffffffL;
}


DWORD GetCrcOfByte( DWORD dwCrc, BYTE bytedata )
{
	BYTE *ptr = &bytedata;
	DO1( ptr );
	return dwCrc ^ 0xffffffffL;
}



#define MAX_SEARCH_MODULE	100

BOOL SearchLoadedDllNameWithAddrW( DWORD addr, OUT WCHAR *wchDllname, int bufsize )
{
	dll_list_entry *dllentry;
	LIST_ENTRY *curentry;
	PEB_LDR_DATA *ldr_data;
	int i;

	// get ldr_data
	_asm{
		push ebx
		mov ebx, dword ptr fs:[0x30]
		mov ebx, dword ptr [ebx+0xc]
		mov dword ptr[ldr_data], ebx
		pop ebx
	}

	curentry = ldr_data->InMemoryOrderModuleList.Flink;
	dllentry = (dll_list_entry*)curentry;

	// loop

	for( i = 0; i < MAX_SEARCH_MODULE; i ++ )
	{
		if( ( addr >= dllentry->imagebase ) && ( addr <= dllentry->imagebase + dllentry->sizeofimage ) )
		{
			// found
			break;
		}

		curentry = curentry->Flink;
		dllentry = (dll_list_entry*)curentry;
	}
	if( i == MAX_SEARCH_MODULE )
		// not found
		return FALSE;

	wcsncpy( wchDllname, dllentry->uniModuleName.Buffer, min( dllentry->uniModuleName.Length, bufsize ) );


	return TRUE;
	
}


BOOL SearchLoadedDllNameWithAddr( DWORD addr, OUT char *dllname, int bufsize )
{
	WCHAR wchDllName[MAX_PATH];

	if( SearchLoadedDllNameWithAddrW( addr, wchDllName, MAX_PATH ) == FALSE )
		return FALSE;

	GetLastError();
	if( WideCharToMultiByte( CP_ACP, 0, wchDllName, -1, dllname, bufsize, NULL, NULL ) == NULL )
	{
		GetLastError();
		return FALSE;
	}

	return TRUE;

}




BOOL mread( DWORD addr, OUT void *buf, int size )
{
	DWORD tmp;
	__try{
		if( VirtualProtect( (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &tmp ) == FALSE )
			return FALSE;
		memcpy( (void*)buf, (const void*)addr, size );
		VirtualProtect( (LPVOID)addr, size, tmp, &tmp );
		
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		return FALSE;
	}

	return TRUE;
}


BOOL mwrite( DWORD addr, OUT void *buf, int size )
{
	DWORD tmp;
	__try{
		if( VirtualProtect( (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &tmp ) == FALSE )
			return FALSE;
		memcpy( (void*)addr, (const void*)buf, size );
		VirtualProtect( (LPVOID)addr, size, tmp, &tmp );
		
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		return FALSE;
	}

	return TRUE;

}



BOOL rread( HANDLE hproc, DWORD addr, OUT void *buf, int size )
{
	DWORD tmp;
	DWORD rw;
	MEMORY_BASIC_INFORMATION mbi = {0,};

	if( VirtualQueryEx( hproc, (LPVOID)addr, &mbi, sizeof(mbi) ) == 0 )
	{
		if( GetLastError() == 5 )
		{
			VirtualProtectEx( hproc, (LPVOID)addr, size, PROCESS_VM_READ, &tmp );
			if( ReadProcessMemory( hproc, (LPVOID)addr, buf, size, &rw ) == FALSE )
				return FALSE;
			VirtualProtectEx( hproc, (LPVOID)addr, size, tmp, &tmp );
			return TRUE;
		}
		return FALSE;
	}

	if( VirtualProtectEx( hproc, (LPVOID)addr, size, PAGE_READWRITE, &tmp ) == FALSE )
		return FALSE;
	if( ReadProcessMemory( hproc, (LPVOID)addr, buf, size, &rw ) == FALSE )
		return FALSE;
	VirtualProtectEx( hproc, (LPVOID)addr, size, tmp, &tmp );


	return TRUE;
}


BOOL rwrite( HANDLE hproc, DWORD addr, OUT void *buf, int size )
{
	DWORD tmp;
	DWORD rw;
	if( VirtualProtectEx( hproc, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &tmp ) == FALSE )
		return FALSE;
	if( WriteProcessMemory( hproc, (LPVOID)addr, buf, size, &rw ) == FALSE )
		return FALSE;
	VirtualProtectEx( hproc, (LPVOID)addr, size, tmp, &tmp );


	return TRUE;
}


BOOL rread2( DWORD pid, DWORD addr, OUT void *buf, int size )
{
	HANDLE hproc = NULL;
	BOOL result = TRUE;

	hproc = OpenProcess( PROCESS_VM_READ|PROCESS_VM_OPERATION, FALSE, pid );
	if( hproc == NULL )
	{
		if( GetLastError() == 5 )
		{
			// access denied
			hproc = OpenProcess( PROCESS_VM_READ, FALSE, pid );
			if( hproc == NULL )
			{
				result = FALSE;
				goto _END;
			}
		}
	}

	result = rread( hproc, addr, buf, size );


_END:

	if( hproc != NULL )
		CloseHandle( hproc );

	return result;

}



BOOL rwrite2( DWORD pid, DWORD addr, OUT void *buf, int size )
{
	HANDLE hproc = NULL;
	DWORD tmp;
	DWORD rw;
	BOOL result = TRUE;

	hproc = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
	if( hproc == NULL )
	{
		result = FALSE;
		goto _END;
	}

	if( VirtualProtectEx( hproc, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &tmp ) == FALSE )
	{
		result = FALSE;
		goto _END;
	}
	if( WriteProcessMemory( hproc, (LPVOID)addr, buf, size, &rw ) == FALSE )
	{
		result = FALSE;
		goto _END;
	}

	VirtualProtectEx( hproc, (LPVOID)addr, size, tmp, &tmp );


_END:

	if( hproc != NULL )
		CloseHandle( hproc );

	return result;

}






BOOL IsSameFile( char *path1, char *path2 )
{
	BYTE *buf = NULL;
	DWORD filesize1, filesize2;
	BOOL result;
	DWORD crc1, crc2;
#define INITCRC 0xBAADF00D

	// filesize가 다르면 기냥 다름.

	filesize1 = MyGetFileSize( path1 );
	if( filesize1 == 0 )
	{
		// ㅅㅂ 이럴 땐 그냥 복사 안하게 TRUE 리턴
		result = TRUE;
		goto _END;
	}

	filesize2 = MyGetFileSize( path2 );
	if( filesize2 == 0 )
	{
		// ㅅㅂ 이럴 땐 그냥 복사 안하게 TRUE 리턴
		result = TRUE;
		goto _END;
	}

	if( filesize1 != filesize2 )
	{
		result = FALSE;
		goto _END;
	}

	// 내용 비교
	buf = (BYTE*)valloc( filesize1 );
	if( buf == NULL )
	{
		result = TRUE;
		goto _END;
	}


	if( ReadFileAt( path1, 0, buf, filesize1 ) == FALSE )
	{
		result = TRUE;
		goto _END;
	}

	crc1 = GetCrc32( INITCRC, buf, filesize1 );


// 같을 수밖에 없다.
//	if( filesize1 != filesize2 )
//	{
//		vfree( buf );
//		buf = (BYTE*)valloc( filesize2 );
//		if( buf == NULL )
//		{
//			result = TRUE;
//			goto _END;
//		}
//	}

	if( ReadFileAt( path2, 0, buf, filesize2 ) == FALSE )
	{
		result = TRUE;
		goto _END;
	}

	crc2 = GetCrc32( INITCRC, buf, filesize2 );

	if( crc1 == crc2 )
		result = TRUE;
	else
		result = FALSE;

_END:

	if( buf != NULL )
		vfree( buf );

	return result;

}





DWORD GetCeiling( DWORD ulValue, DWORD ulAlign )
{
	DWORD ulLeft;

	if ( ulAlign == 0 )
		ulAlign = 1;

	ulLeft = ulValue % ulAlign;

	if ( ulLeft != 0 )
	{
		return ulValue + ulAlign - ulLeft;
	}
	else
	{
		return ulValue;
	}
}

DWORD GetFloor( DWORD ulValue, DWORD ulAlign )
{
	DWORD ulLeft;

	if ( ulAlign == 0 )
		ulAlign = 1;

	ulLeft = ulValue % ulAlign;

	return ulValue - ulLeft;
}




int mycmp( void *buf1, WILDCARD void *buf2, int size )
{
	int i;
	BYTE *_buf1 = (BYTE*)buf1;
	BYTE *_buf2 = (BYTE*)buf2;
	for( i = 0; i < size; i ++ )
	{
		if( _buf2[i] == '?' )
			continue;

		if( _buf1[i] > _buf2[i] )
			return 1;
		else if( _buf1[i] < _buf2[i] )
			return -1;
	}

	return 0;

}




#define LINE_END		0x0a

BOOL Tail( char *filepath, char *buf, int bufsize )
{
	BOOL result = FALSE;
	FILE *fp = NULL;
	char *tmp = NULL;
	char *ptr;

	fp = fopen( filepath, "rt" );
	if( fp == NULL )
	{
		result = FALSE;
		goto _END;
	}

	tmp = (char*)malloc( bufsize );
	if( tmp == NULL )
	{
		result = FALSE;
		goto _END;
	}

	fseek( fp, bufsize * -1, SEEK_END );

	fread( tmp, 1, bufsize, fp );
	ptr = strrchr( tmp, LINE_END );
	if( ptr == NULL )
	{
		result = FALSE;
		goto _END;
	}

	// 로그의 형태가
	// xxxx┘
	// <eof> 의 형태로 남기 때문에 맨 마지막 줄은 제외하고 끝에서 두번째의 LINE_END 를 찾는다.
	*ptr = 0;
	ptr = strrchr( tmp, LINE_END );
	if( ptr == NULL )
	{
		result = FALSE;
		goto _END;
	}

	strncpy( buf, ptr + 1, bufsize );

	result = TRUE;


_END:

	if( fp != NULL )
	{
		fclose( fp );
	}
	if( tmp != NULL )
	{
		free( tmp );
	}

	return result;

}



BOOL FindProcessWithName( char *exename, OPTIONAL OUT DWORD *pdwProcessId )
{
	BOOL			result = FALSE;
	HANDLE			hProcessSnap = NULL;
	PROCESSENTRY32	pe = {0,};


	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap == INVALID_HANDLE_VALUE )
	{
		result = FALSE;
		goto _END;
	}

	pe.dwSize = sizeof( pe );
	if( Process32First( hProcessSnap, &pe ) == FALSE )
	{
		result = FALSE;
		goto _END;
	}

	do 
	{
		if( stricmp( exename, pe.szExeFile ) == 0 )
		{
			result = TRUE;
			if( pdwProcessId != NULL )
			{
				*pdwProcessId = pe.th32ProcessID;
			}
			break;
		}
	} while( Process32Next( hProcessSnap, &pe ) == TRUE );


_END:

	if( hProcessSnap != NULL )
	{
		CloseHandle( hProcessSnap );
	}

	return result;
}





BOOL CopyToDir( char *src, char *dstpath, BOOL bFailIfExists )
{
	char dst[MAX_PATH];
	char *filename;

	filename = strrchr( src, '\\' );
	if( filename == NULL )
		return FALSE;


	strcpy( dst, dstpath );
	strcat( dst, filename );

	return CopyFile( src, dst, bFailIfExists );
}



BOOL MoveToDir( char *src, char *dstpath, BOOL bFailIfExists )
{
	char dst[MAX_PATH];
	char *filename;

	filename = strrchr( src, '\\' );
	if( filename == NULL )
		return FALSE;


	strcpy( dst, dstpath );
	strcat( dst, filename );

	if( MoveFile( src, dst ) == FALSE )
	{
		if( GetLastError() == ERROR_FILE_EXISTS )
		{
			if( bFailIfExists == TRUE )
				return FALSE;

			// 삭제후 처리
			DeleteFile( dst );
			return MoveFile( src, dst );
		}
	}

	return TRUE;
}





BOOL RenameCopyToDir( char *src, char *dstpath, OPTIONAL OUT char *renamed_dst )
{
	char dst[MAX_PATH];
	char *filename;

	filename = strrchr( src, '\\' );
	if( filename == NULL )
		return FALSE;


	strcpy( dst, dstpath );
	strcat( dst, filename );

	return RenameCopyFile( src, dst, renamed_dst );
}



void hexdump( BYTE *buf, DWORD from, DWORD size )
{
	// byte dump
	char tmp[30];
	DWORD to = from + size;
	int i, j;

	for( i = 0; i < size; i += 0x10 )
	{
		// addr 
		printf( "%08x  ", from + i );

		// dump
		for( j = 0; j < 0x10; j ++ )
		{
			if( i + j > to )
				break;

			printf( "%02x ", buf[i + j] );
		}

		printf( "   " );

		// char
		for( j = 0; j < 0x10; j ++ )
		{
			if( i + j > to )
				break;

			if( buf[i + j] > 0x20 && buf[i + j] < 0x80 )
				printf( "%c", buf[i + j] );
			else
				printf( "." );
		}

		printf( "\n" );
	}

}




BOOL SetPrivilege(
				  HANDLE hToken,          // access token handle
				  LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
				  BOOL bEnablePrivilege   // to enable or disable privilege
				  ) 
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	
	if ( !LookupPrivilegeValue( 
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid ) )        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
		return FALSE; 
	}
	
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	
	// Enable the privilege or disable all privileges.
	
	if ( !AdjustTokenPrivileges(
		hToken, 
		FALSE, 
		&tp, 
		sizeof(TOKEN_PRIVILEGES), 
		(PTOKEN_PRIVILEGES) NULL, 
		(PDWORD) NULL) )
	{ 
		printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
		return FALSE; 
	} 
	
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	} 
	
	return TRUE;
}

void RisePriv()
{
	HANDLE hToken;
	if( !OpenThreadToken( GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken ) )
	{
		if( GetLastError() == ERROR_NO_TOKEN )
		{
			if( !ImpersonateSelf( SecurityImpersonation) )
			{
				puts( "ImpersonateSelf failure" );
				return;
			}
			if( !OpenThreadToken( GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken ) )
			{
				puts( "OpenThreadToken failure" );
				return;
			}
		}
		else
		{
			puts( "OpenThreadToken failure" );
			return;
		}
	}

	SetPrivilege( hToken, "SeDebugPrivilege", TRUE );

}



