#include <ntddk.h>

#define RESTORE true
#define RESTORE_EVENT L"\\BaseNamedObjects\\RestoreDrv"

int TestGloabl = 0;

NTSTATUS CustomDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	TestGloabl = 1;
	DbgPrint("[*] mapped driver :: I'm executing : ) \n");


	return STATUS_SUCCESS;
}