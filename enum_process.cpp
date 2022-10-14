// enum_process.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>

#include "plist_process_table.h"


int cb_enum_process(struct plist_process_info *plist_info, void *ctx)
{
	static int g_proc_index = 0;

	if ( plist_info == NULL )
	{
		return -1;
	}

	wprintf(L"[%d] %ws/%ws \t%d \t%ws \t%ws \t%dKB \t%dKB \n", 
		++g_proc_index, 
		plist_info->domain, plist_info->owner,
		plist_info->pid, 
		plist_info->name,
		plist_info->title,
		(unsigned long)(plist_info->private_workingset >> 10),
		plist_info->commited >> 10
		);

	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	plist_enum_process(cb_enum_process, NULL);

	return 0;
}

