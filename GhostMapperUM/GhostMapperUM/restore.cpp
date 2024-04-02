#include <Windows.h>
#include <iostream>
#include "intel_driver.hpp"
#include <pte.h>
#include <vector>


bool RestoreOriginalDriver(HANDLE IntelDrvHandle ,uint64_t OriginalDriverBase, uint64_t OriginalDriverEnd, void* OriginalDriverMemory,uint64_t PatchSize, const std::vector<pte>& OriginalPtes ,uint64_t PteBaseAddress)
{
	if (!OriginalDriverBase || !OriginalDriverMemory)
		return false;

	// make ghost driver writeable again 
	for (uint64_t CurrentAddress = OriginalDriverBase; CurrentAddress < OriginalDriverEnd; CurrentAddress += USN_PAGE_SIZE)
	{
		uint64_t PteAddress = (uint64_t)GetPTEForVA(IntelDrvHandle, CurrentAddress, PteBaseAddress);

		pte PteMemory;
		if (!intel_driver::ReadMemory(IntelDrvHandle, PteAddress, &PteMemory, sizeof(pte)))
		{
			Log(L"[-] failed to read ghost driver pte" << std::endl);
			return false;
		}
		PteMemory.rw = true;
		if (!intel_driver::WriteMemory(IntelDrvHandle, PteAddress, &PteMemory, sizeof(pte)))
		{
			Log(L"[-] failed to patch ghost driver pte" << std::endl);
			return false;
		}
	}

	// copy original driver image 
	if (!intel_driver::WriteMemory(IntelDrvHandle, OriginalDriverBase, OriginalDriverMemory, PatchSize))
	{
		Log(L"[*] failed to restore original driver image" << std::endl);
		return false;
	}

	// restore original ptes 
	uint64_t CurrentDriverAddress = OriginalDriverBase;

	for (pte OriginalPte : OriginalPtes)
	{
		uint64_t PteAddress = (uint64_t)GetPTEForVA(IntelDrvHandle, CurrentDriverAddress, PteBaseAddress);
		if (!intel_driver::WriteMemory(IntelDrvHandle, PteAddress, &OriginalPte, sizeof(pte)))
		{
			Log(L"[-] failed to restore original driver pte" << std::endl);
			return false;
		}
		CurrentDriverAddress += USN_PAGE_SIZE;
	}

	Log(L"[*] restored original driver in memory" << std::endl);

}