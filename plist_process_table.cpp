
#include <Windows.h>
#include "uthash.h"
#include "plist_process_table_internal.h"
#include "plist_process_table.h"


LPFN_NtQuerySystemInformation NtQuerySystemInformation = NULL;


int pslist_adjust_privilege(const wchar_t *privilege_name)
{
	int ret = -1;
	HANDLE process_handle = NULL;
	HANDLE process_token_handle = NULL;
	TOKEN_PRIVILEGES tp = {0};
	LUID luid;

	if ( privilege_name == NULL )
	{
		return -1;
	}

	do 
	{
		process_handle = GetCurrentProcess();
		if ( process_handle == NULL )
		{
			break;
		}

		if( !OpenProcessToken(process_handle, 0x28, &process_token_handle) )
		{
			break;
		}

		if ( !LookupPrivilegeValueW(NULL, privilege_name, (PLUID)&luid) )
		{
			break;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if( !AdjustTokenPrivileges(process_token_handle, FALSE, &tp, sizeof(tp), NULL, NULL) )
		{
			break;
		}

		ret = 0;

	} while (0);

	if ( process_token_handle )
	{
		CloseHandle(process_token_handle);
	}

	if ( process_handle )
	{
		CloseHandle(process_handle);
	}

	return ret;
}

int plist_ntdll_functions()
{
	HMODULE ntdll_module = NULL;

	ntdll_module = LoadLibraryW(L"ntdll.dll");
	if ( !ntdll_module )
	{
		return -1;
	}

	NtQuerySystemInformation = (LPFN_NtQuerySystemInformation)GetProcAddress(ntdll_module, "NtQuerySystemInformation");
	if ( NtQuerySystemInformation == NULL )
	{
		return -1;
	}

	return 0;
}


BOOL CALLBACK plist_enum_window_proc(HWND hwnd, LPARAM param)
{
	BOOL ret = FALSE;
	DWORD pid = 0;

	struct plist_pid2hwnd_node **pid2hwnd_header = NULL;
	struct plist_pid2hwnd_node *pid2hwnd_node = NULL;

	do 
	{
		pid2hwnd_header = (struct plist_pid2hwnd_node **)param;

		if( GetWindowThreadProcessId(hwnd, &pid) )
		{
			pid2hwnd_node = (struct plist_pid2hwnd_node *)calloc(1, sizeof(struct plist_pid2hwnd_node));
			if (pid2hwnd_node != NULL)
			{
				pid2hwnd_node->pid = pid;
				pid2hwnd_node->hwnd = hwnd;

				HASH_ADD_PTR(*pid2hwnd_header, pid, pid2hwnd_node);
			}
		}

		ret = TRUE;

	} while (0);

	return ret;
}

int plist_pid2hwnd_build(struct plist_pid2hwnd_node **pid2hwnd_header)
{
	// TODO: others

	if( !EnumWindows(plist_enum_window_proc, (LPARAM)pid2hwnd_header) )
	{
		return -1;
	}
	
	if ( *pid2hwnd_header == NULL )
	{
		return -1;
	}

	return 0;
}

int plist_pid2hwnd_destroy(struct plist_pid2hwnd_node *pid2hwnd_header)
{
	struct plist_pid2hwnd_node *tmp = NULL;
	struct plist_pid2hwnd_node *node = NULL;

	if ( pid2hwnd_header == NULL )
	{
		return -1;
	}

	HASH_ITER(hh, pid2hwnd_header, node, tmp)
	{
		if ( node != NULL )
		{
			free(node);
		}
	}

	return 0;
}

int plist_pid2hwnd_get_hwnd(struct plist_pid2hwnd_node *pid2hwnd_header, unsigned long pid, HWND *hwnd)
{
	struct plist_pid2hwnd_node *pid2hwnd_node = NULL;

	if ( pid2hwnd_header == NULL )
	{
		return -1;
	}
	if ( hwnd == NULL )
	{
		return -1;
	}

	HASH_FIND_PTR(pid2hwnd_header, &pid, pid2hwnd_node);
	
	if ( pid2hwnd_node == NULL )
	{
		return -1;
	}

	*hwnd = pid2hwnd_node->hwnd;

	return 0;
}

int plist_get_process_owner(unsigned long pid, wchar_t *owner_name, int name_length, wchar_t *owner_domain, int domain_length)
{
	int ret = -1;

	HANDLE proc_handle = NULL;
	HANDLE proc_token = NULL;
	PTOKEN_USER token_user = NULL;
	SID_NAME_USE snu;
	DWORD token_user_size = 0;
	DWORD error_code = 0;
	DWORD return_bytes = 0;

	if ( owner_name == NULL )
	{
		return -1;
	}

	do 
	{
		proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if ( proc_handle == NULL )
		{
			//
			// NOTE:
			// 这里OpenProcess打开audiodg.exe进程失败，错误码5
			// 此时通过设置OpenProcess第一个参数为PROCESS_QUERY_LIMITED_INFORMATION成功打开audiodg.exe进程
			//

			proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
			if ( proc_handle == NULL )
			{
				error_code = GetLastError();
				break;
			}
		}

		if ( !OpenProcessToken(proc_handle, TOKEN_QUERY, &proc_token) )
		{
			break;
		}

		if ( !GetTokenInformation(proc_token, TokenUser, token_user, token_user_size, &token_user_size) )
		{
			if ( GetLastError() != ERROR_INSUFFICIENT_BUFFER )
			{
				break;
			}
		}

		token_user = (PTOKEN_USER)calloc(token_user_size, 1);
		if ( token_user == NULL )
		{
			break;
		}

		if ( !GetTokenInformation(proc_token, TokenUser, token_user, token_user_size, &token_user_size) )
		{
			break;
		}

		if ( !LookupAccountSidW(NULL, token_user->User.Sid, owner_name, (PDWORD)&name_length, owner_domain, (PDWORD)&domain_length, &snu) )
		{
			error_code = GetLastError();
			break;
		}

		ret = 0;

	} while (0);

	if ( token_user )
	{
		free(token_user);
	}

	if ( proc_token )
	{
		CloseHandle(proc_token);
	}

	if (proc_handle)
	{
		CloseHandle(proc_handle);
	}

	return ret;
}

int plist_enum_process(LPCB_ENUM_PROCESS cb_enum_process, void *ctx)
{
	int ret = -1;
	unsigned char *buffer = NULL;
	unsigned long buffer_size = 0;
	unsigned long ret_size = 0;
	unsigned long proc_index = 0;

	struct plist_pid2hwnd_node *pid2hwnd_header = NULL;

	NTSTATUS ret_result = 0;
	PSYSTEM_PROCESS_INFORMATION system_process_info = NULL;

	do 
	{
		pslist_adjust_privilege(SE_DEBUG_NAME);

		// 构建pid到hwnd的对应表
		plist_pid2hwnd_build(&pid2hwnd_header); 

		// 初始化WinNT未公开的接口
		if( plist_ntdll_functions() != 0 )
		{
			break;
		}

		if ( NtQuerySystemInformation == NULL )
		{
			break;
		}

		// 获取进程信息
		ret_result = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ret_size);
		if ( ret_result != 0xC0000004 )	
		{
			// ret_result is not STATUS_INFO_LENGTH_MISMATCH
			break;
		}
		if (ret_size == 0)
		{
			break;
		}

		buffer_size = ret_size;

		buffer = (unsigned char *)calloc(buffer_size, 1);
		if ( buffer == NULL )
		{
			break;
		}

		ret_result = NtQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, &ret_size);
		if ( ret_result != 0 )
		{
			break;
		}

		system_process_info = (PSYSTEM_PROCESS_INFORMATION)buffer;

		for (;;)
		{
			HWND hwnd = NULL;
			struct plist_process_info plist_info = {0};

			plist_info.pid = (unsigned long)system_process_info->UniqueProcessId;
			plist_info.private_workingset = system_process_info->WorkingSetPrivateSize.QuadPart;
			plist_info.commited = system_process_info->PrivatePageCount;

			if (system_process_info->ImageName.Buffer)
			{
				wcsncpy_s(plist_info.name, system_process_info->ImageName.Buffer, _TRUNCATE);
			}

			if ( plist_info.pid == 0 )
			{
				wcsncpy_s(plist_info.name, L"System Idle Process", _TRUNCATE);
			}

			if ( plist_info.pid <= 8 )
			{
				wcsncpy_s(plist_info.domain, L"NT AUTHORITY", _TRUNCATE);
				wcsncpy_s(plist_info.owner, L"SYSTEM", _TRUNCATE);
			}

			plist_get_process_owner(plist_info.pid, plist_info.owner, _countof(plist_info.owner), plist_info.domain, _countof(plist_info.domain));

			plist_pid2hwnd_get_hwnd(pid2hwnd_header, plist_info.pid, &hwnd);
			if ( hwnd )
			{
				GetWindowTextW(hwnd, plist_info.title, _countof(plist_info.title));
			}

			if ( cb_enum_process != NULL )
			{
				if( cb_enum_process(&plist_info, ctx) != 0 )
				{
					break;
				}
			}

			if ( system_process_info->NextEntryOffset == 0 )
			{
				break;
			}

			system_process_info = (PSYSTEM_PROCESS_INFORMATION)((char *)system_process_info + system_process_info->NextEntryOffset);
		}
		
		ret = 0;
		
	} while (0);

	if (buffer)
	{
		free(buffer);
	}

	plist_pid2hwnd_destroy(pid2hwnd_header);

	return ret;
}