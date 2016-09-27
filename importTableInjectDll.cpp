///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2016 - <company name here>
///
/// Original filename: importTableInjectDll.cpp
/// Project          : importTableInjectDll
/// Date of creation : 2016-09-20
/// Author(s)        : <author name(s)>
///
/// Purpose          : <description>
///
/// Revisions:
///  0000 [2016-09-20] Initial revision.
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntimage.h>


//#include <string.h>




#ifdef __cplusplus
}; // extern "C"
#endif

#include "importTableInjectDll.h"

//#include "peheader.h"

#include "functions.h"

#include "nativeApi.h"
#ifdef __cplusplus
namespace { // anonymous namespace to limit the scope of this global variable!
#endif
PDRIVER_OBJECT pdoGlobalDrvObj = 0;
#ifdef __cplusplus
}; // anonymous namespace
#endif
extern "C"
extern  PSERVICEDESCRIPTORTABLE KeServiceDescriptorTable;

MyZwProtectVirtualMemory  g_NtProtectVirtualMemory;
PIMAGE_IMPORT_DESCRIPTOR g_OldImportDesc;
KIRQL Irql;
PEPROCESS g_TargetProcess;
HANDLE    g_TargetProcessId;

extern "C"
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegisterPath)
{

	ULONG addr = 0x89*4 + (ULONG)(KeServiceDescriptorTable->ServiceTable);
	g_NtProtectVirtualMemory = (MyZwProtectVirtualMemory)*(PULONG)addr; 

	DbgPrint("驱动加载\r\n");
	DriverObject->DriverUnload = UnloadDriver;
	PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)Start);
	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)Start);
	DbgPrint("驱动卸载\r\n"); 
}

void setKernelMode()
{
	ULONG offset = 0;
	#if defined(AMD64) || defined(IA64)
	offset = 0x1f6;
#else
	offset = 0x140;
#endif
	void *pEthread = PsGetCurrentThread();

	*((char *)pEthread+offset) = 0;
/*
	__asm{
		push eax;
		mov eax,fs:0x124;//获取_KTHREAD 结构体地址

		add eax,0x140;//获取previousmode位置

		mov byte ptr [eax],0;

		pop eax;
	}*/
}


HANDLE OpenProcess(HANDLE ProcessId)
{
	HANDLE		result		= NULL;
	PEPROCESS	pEProcess	= NULL;

	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &pEProcess)))
	{
		ObOpenObjectByPointer(pEProcess, OBJ_KERNEL_HANDLE , NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &result);

		ObDereferenceObject(pEProcess);
	}

	return result;
}

//由于有些程序的导入表大小并不准确，需要自己遍历导入表，获取大小。
//
int getImportTableSize(PIMAGE_IMPORT_DESCRIPTOR pDes)
{
	int i=0;
	while (pDes->Name != 0)
	{
		i++;
		pDes++;
	}
	return ++i;//包含最后全0项
}

//判断是否为pe文件
bool isPeFile(ULONG ImageBase);


VOID Start (
			IN PUNICODE_STRING    FullImageName,
			IN HANDLE    ProcessId, // where image is mapped
			IN PIMAGE_INFO    ImageInfo
			)
{
	NTSTATUS ntStatus;
	PIMAGE_IMPORT_DESCRIPTOR pImportNew;
	HANDLE hProcessHandle;
	int allocSize,tempSize;
	IMAGE_IMPORT_DESCRIPTOR Add_ImportDesc;
	PIMAGE_IMPORT_BY_NAME pApiName;
	IMAGE_THUNK_DATA *pOriginalThunkData;
	IMAGE_THUNK_DATA *pFirstThunkData;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImport;

	typedef struct 
	{
		char dllName[128];
		char apiName[128];
		DWORD thunk;
		DWORD thunkEnd;
		DWORD orgthunk;
		DWORD orgthunkEnd;
	}ExtData,*PExtData;



	PVOID lpBuffer = NULL;




	ULONG ulBaseImage = (ULONG)ImageInfo->ImageBase;// 进程基地址
	KdPrint(("ImageBase:%x\n",ulBaseImage));

	//判断是否为PE文件
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER) ulBaseImage;
	if (0x5a4d != pDos->e_magic)
		return;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(ulBaseImage+(ULONG)pDos->e_lfanew);
	if (0x4550 != pHeader->Signature)
		return;

	//判断是否为可执行文件
	if(0 == (pHeader->FileHeader.Characteristics&IMAGE_FILE_EXECUTABLE_IMAGE))
		return;
	//不对dll注入
	if (0 != (pHeader->FileHeader.Characteristics&IMAGE_FILE_DLL))
		return;


	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG)pHeader->OptionalHeader.DataDirectory[1].VirtualAddress + ulBaseImage);
	ULONG nImportDllCount =  getImportTableSize(pImportDesc);
	PExtData pExtData = NULL;

	//获取句柄
	hProcessHandle = OpenProcess(ProcessId);
	if(NULL == hProcessHandle)
		return ;

	//加上一个导入表描述，再加上一个自己的结构,ExtData。
	allocSize =sizeof(ExtData) + sizeof(IMAGE_IMPORT_DESCRIPTOR) * (nImportDllCount + 1);

	//分配导入表
	tempSize = allocSize;
	ntStatus = ZwAllocateVirtualMemory(hProcessHandle, &lpBuffer, 0, (PSIZE_T)&tempSize,
		MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);

	if(!NT_SUCCESS(ntStatus)) 
	{
		ZwClose(hProcessHandle);
		return ;
	}

	//指向新导入表后面的额外数据（用于存放dll名，函数名等信息）
	pExtData = (PExtData)((char *)lpBuffer + sizeof(IMAGE_IMPORT_DESCRIPTOR) * (nImportDllCount + 1));
	RtlZeroMemory(lpBuffer,allocSize);


	pImportNew = (PIMAGE_IMPORT_DESCRIPTOR)lpBuffer;

	// 把原来数据移至新空间。
	RtlCopyMemory(pImportNew , pImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR) * nImportDllCount );

	// 构造自己的DLL    IMAGE_IMPORT_DESCRIPTOR结构
	pExtData->thunkEnd = 0;
	pExtData->orgthunkEnd = 0;
	pOriginalThunkData = (PIMAGE_THUNK_DATA)&(pExtData->orgthunk);
	pFirstThunkData = (PIMAGE_THUNK_DATA)&(pExtData->thunk);
	pApiName = (PIMAGE_IMPORT_BY_NAME)pExtData->apiName;
	pApiName->Hint = 0;
	// 至少要一个导出API，并让thunk指向函数名
	RtlCopyMemory(pApiName->Name,"noapi",strlen("noapi"));
	pOriginalThunkData[0].u1.AddressOfData = (ULONG)pApiName-ulBaseImage;
	pFirstThunkData[0].u1.AddressOfData = (ULONG)pApiName-ulBaseImage;

	//构造加入项
	Add_ImportDesc.FirstThunk = (ULONG)pFirstThunkData-ulBaseImage;
	Add_ImportDesc.TimeDateStamp = 0;
	Add_ImportDesc.ForwarderChain = 0;
	//
	// DLL名字的RVA

	RtlCopyMemory(pExtData->dllName,"TEST.dll",strlen("TEST.dll"));
	Add_ImportDesc.Name = (ULONG)pExtData->dllName-ulBaseImage;
	Add_ImportDesc.Characteristics = (ULONG)pOriginalThunkData-ulBaseImage;

	//将自己的表追加在末尾
	pImportNew += (nImportDllCount-1);
	RtlCopyMemory(pImportNew, &Add_ImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR));

	//表尾清零
	pImportNew += 1;
	RtlZeroMemory(pImportNew, sizeof(IMAGE_IMPORT_DESCRIPTOR));




	ULONG  *pVirtualAddr = &(pHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
	ULONG *pSize = &(pHeader->OptionalHeader.DataDirectory[1].Size);
	ULONG *temp_BaseAddr = NULL;
	//将8个表项设置为可写
	SIZE_T protectSize = 16*sizeof(IMAGE_DATA_DIRECTORY);

	ULONG oldProtect;


	//调用nt函数前将先前模式设置为内核模式
	setKernelMode();
	temp_BaseAddr = pVirtualAddr;
	//更改内存属性为可写
	ntStatus = g_NtProtectVirtualMemory(hProcessHandle,(PVOID *)&temp_BaseAddr,(PULONG)&protectSize,PAGE_EXECUTE_READWRITE,&oldProtect);
	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(hProcessHandle);
		return;
	}

	KdPrint(("orgSize :%d,trueSize :%d ,changeSize: %d\n",pHeader->OptionalHeader.DataDirectory[1].Size,nImportDllCount*(sizeof(IMAGE_IMPORT_DESCRIPTOR)),pHeader->OptionalHeader.DataDirectory[1].Size+sizeof(IMAGE_IMPORT_DESCRIPTOR)));
	// 改导出表
	//*pSize = sizeof(IMAGE_IMPORT_DESCRIPTOR) * (nImportDllCount + 1);
	*pSize = pHeader->OptionalHeader.DataDirectory[1].Size+sizeof(IMAGE_IMPORT_DESCRIPTOR);
	*pVirtualAddr = (ULONG)lpBuffer - ulBaseImage;
	/*ULONG baseBuffer;
	baseBuffer = (ULONG)lpBuffer - ulBaseImage;
	ULONG retLength= 0;
	MyZwWriteVirtualMemory pfun = (MyZwWriteVirtualMemory)0x8050033c ;
	KdPrint(("before write: %x ",pHeader->OptionalHeader.DataDirectory[1].VirtualAddress));
	__try
	{
	ntStatus = pfun(hProcessHandle,pVirtualAddr,&baseBuffer,sizeof(baseBuffer),&retLength);
	}

	__finally
	{
	KdPrint(("fail :%x\n",ntStatus));
	}


	KdPrint(("after write: %x \n",baseBuffer));*/


	//取消绑定输入表里的所有东西
	pBoundImport = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((PIMAGE_DATA_DIRECTORY)pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);

	if( (ULONG)pBoundImport != 0)
	{
		pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
		pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	}


	temp_BaseAddr = pVirtualAddr;
	protectSize = 16*sizeof(IMAGE_DATA_DIRECTORY);
	ntStatus = g_NtProtectVirtualMemory(hProcessHandle,(PVOID *)&temp_BaseAddr,(PULONG)&protectSize,oldProtect,&oldProtect);


	ZwClose(hProcessHandle);


}