
#ifndef _PLIST_PROCESS_TABLE_
#define _PLIST_PROCESS_TABLE_

struct plist_process_info
{
	unsigned long		pid;
	unsigned long long	private_workingset;
	unsigned long long	commited;

	wchar_t				name[MAX_PATH];
	wchar_t				domain[MAX_PATH];
	wchar_t				owner[MAX_PATH];
	wchar_t				title[MAX_PATH];

};

typedef int (*LPCB_ENUM_PROCESS)(struct plist_process_info *plist_info, void *ctx);

int plist_enum_process(LPCB_ENUM_PROCESS cb_enum_process, void *ctx);


#endif