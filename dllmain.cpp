// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "ipfd.h"
#include <cstdint>



Address_Info *_addresses = nullptr;  //one we monitor
int _sizeofAddresses = 0; 
void* VectoredExceptionHandlerPtr = nullptr;
Access_Info* _accessInfo = nullptr;
int _framesToCapture = 3;
int _sizeOfInfo = 20;
unsigned long long _addressHit = 0;
bool _unhook = false;
PMEMORY_BASIC_INFORMATION info = new MEMORY_BASIC_INFORMATION;


bool AttachVEH() {
	if (VectoredExceptionHandlerPtr != nullptr)
		return true;
	VectoredExceptionHandlerPtr = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
	if (VectoredExceptionHandlerPtr == nullptr)
		return false;
	return true;
}
bool DetachVEH() {
	for (int i = 0; i < _sizeofAddresses; i++) {
		if (_addresses[i].watched)
			RemoveAddress(_addresses[i].addressToWatch);
	}
	int out = RemoveVectoredExceptionHandler(VectoredExceptionHandlerPtr);

	if (out == 0)
		return true;
	return false;

}
bool RefreshAddresses() {
	if (_addresses == nullptr)
		return false;

	bool retval = true;
	for (int i = 0; i < _sizeofAddresses; i++) {
		if (_addresses[i].addressToWatch != 0) {
			_addresses[i].watched = true;
			retval &= GuardPage(_addresses[i].addressToWatch);
		}
		else {
			break;
		}
	}
	

	return retval;
}
bool RemoveAddress(unsigned __int64 address) {
	_unhook = true;
	return RemoveGuardPage(address);
}

void SetupParams(Access_Info* array, int sizeOfInfo, int framesToCap, Address_Info* addresses, int sizeOfAddresses) {
	_accessInfo = array;
	_sizeOfInfo = sizeOfInfo;
	_framesToCapture = framesToCap;
	_addresses = addresses;
	_sizeofAddresses = sizeOfAddresses;
}

bool GuardPage(unsigned __int64 Address) {
	if (VectoredExceptionHandlerPtr == nullptr)
		return false;

	int e = VirtualQueryEx(GetCurrentProcess(), (void*)Address, info, sizeof(MEMORY_BASIC_INFORMATION));

	if (e == 0) {
		HRESULT err = HRESULT_FROM_WIN32(GetLastError());
		return false;
	}


	if (info->Protect & PAGE_GUARD) 
		return true; //we already guarded this section of memory



	info->Protect |= PAGE_GUARD;
	DWORD tmp = 0;
	e = VirtualProtect((void*)Address, 1, info->Protect, &tmp);
	if (e == 0) {
		HRESULT err = HRESULT_FROM_WIN32(GetLastError());
		return false;
	}
	return true;
}

bool RemoveGuardPage(unsigned __int64 Address) {
	bool test = false;
	for (int i = 0; i < _sizeofAddresses; i++) {
		if (_addresses[i].addressToWatch == Address)
			test = true;
	}
	if (!test)
		return false;


	HANDLE proc = GetCurrentProcess();
	int e = VirtualQueryEx(GetCurrentProcess(), (void*)Address, info, sizeof(MEMORY_BASIC_INFORMATION));

	if (e == 0) {
		HRESULT err = HRESULT_FROM_WIN32(GetLastError());
		return false;
	}


	if (info->Protect & PAGE_GUARD) {
		info->Protect &= ~PAGE_GUARD;
		DWORD tmp = 0;
		e = VirtualProtect((void*)Address, 1, info->Protect, &tmp);
		if (e == 0) {
			HRESULT err = HRESULT_FROM_WIN32(GetLastError());
			return false;
		}

	}
	return true;
}

static long CALLBACK VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
	if (_unhook) {
		constexpr uint64_t DR0_MASK = 0x000F0003ull;
		constexpr uint64_t DR1_MASK = 0x00F0000Cull;
		constexpr uint64_t DR2_MASK = 0x0F000030ull;
		constexpr uint64_t DR3_MASK = 0xF00000C0ull;
		uint64_t newBits = DR0_MASK | DR1_MASK | DR2_MASK | DR3_MASK;

		ExceptionInfo->ContextRecord->Dr0 = ExceptionInfo->ContextRecord->Dr1 = ExceptionInfo->ContextRecord->Dr2 = ExceptionInfo->ContextRecord->Dr3 =  0;

		ExceptionInfo->ContextRecord->Dr7 = ~newBits;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT || ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
		for (int i = 0; i < _sizeOfInfo; i++) {
			if (!_accessInfo[i].inUse) {
				
				int hit = ExceptionInfo->ContextRecord->Dr6 & 0xF;
				if (hit & 8) {
					_accessInfo[i].addressAccessed = ExceptionInfo->ContextRecord->Dr3;
				}else if (hit & 4) {
					_accessInfo[i].addressAccessed = ExceptionInfo->ContextRecord->Dr2;
				}else if (hit & 2) {
					_accessInfo[i].addressAccessed = ExceptionInfo->ContextRecord->Dr1;
				}else if (hit & 1) {
					_accessInfo[i].addressAccessed = ExceptionInfo->ContextRecord->Dr0;
				}

				RtlCaptureStackBackTrace(4, _framesToCapture, (void**)(_accessInfo[i].frameTrace), nullptr);
				_accessInfo[i].inUse = true;
			}
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
		_addressHit = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
		for (int i = 0; i < _sizeofAddresses; i++) {
				if (_addresses[i].addressToWatch == 0)
					goto end;
				if (_addresses[i].addressToWatch != 0 && ExceptionInfo->ExceptionRecord->ExceptionInformation[1] >= (unsigned __int64)_addresses[i].addressToWatch && ExceptionInfo->ExceptionRecord->ExceptionInformation[1] <= (unsigned __int64)_addresses[i].addressToWatch + _addresses[i].sizeOfType) {//page needs to be reset
					if (_addresses->operation == ReadWrite || _addresses->operation == ExceptionInfo->ExceptionRecord->ExceptionInformation[0])
					{
						for (int i = 0; i < _sizeOfInfo; i++) {
							if (!_accessInfo[i].inUse) {
								_accessInfo[i].addressAccessed = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
								RtlCaptureStackBackTrace(4, _framesToCapture, (void**)(_accessInfo[i].frameTrace), nullptr);
								_accessInfo[i].inUse = true;
								goto end;
							}
						}
					}
					else {
						goto end;
					}
			}
		}
	end:
		// for simplicity
		auto* ctx = ExceptionInfo->ContextRecord;

		const uint64_t oneAddressdr7 = 0x0000000000dd0405;
		const uint64_t twoAddressdr7 = 0x00000000dddd0455;


		ExceptionInfo->ContextRecord->Dr0 = static_cast<DWORD64>(_addresses[0].addressToWatch + 0x4);
		ExceptionInfo->ContextRecord->Dr1 = static_cast<DWORD64>(_addresses[0].addressToWatch + 0x1E);
		ExceptionInfo->ContextRecord->Dr7 = oneAddressdr7;

		if (_sizeofAddresses > 1 && _addresses[1].addressToWatch != 0) {
			ExceptionInfo->ContextRecord->Dr2 = static_cast<DWORD64>(_addresses[1].addressToWatch + 0x4);
			ExceptionInfo->ContextRecord->Dr3 = static_cast<DWORD64>(_addresses[1].addressToWatch + 0x1E);

			ExceptionInfo->ContextRecord->Dr7 = twoAddressdr7;
		}


		return EXCEPTION_CONTINUE_EXECUTION;	//Swallow all the page guards cause idgaf
	}
	return EXCEPTION_CONTINUE_SEARCH;
}