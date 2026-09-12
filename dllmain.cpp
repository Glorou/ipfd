// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "ipfd.h"



Address_Info *_addresses = nullptr;  //one we monitor
int _sizeofAddresses = 0;  //Size of the type
void* VectoredExceptionHandlerPtr = nullptr;
Access_Info* _accessInfo = nullptr;
int _framesToCapture = 3;
int _sizeOfInfo = 20;



bool AttachVEH() {
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
	int out = RemoveVectoredExceptionHandler(VectoredExceptionHandler);

	if (out == 0)
		return true;
	return false;

}
bool RefreshAddresses() {
	if (_addresses == nullptr)
		return false;

	bool retval = true;
	for (int i = 0; i < _sizeofAddresses; i++) {
		if (_addresses[i].addressToWatch != 0 && !_addresses[i].watched) {
			_addresses[i].watched = true;
			retval &= GuardPage(_addresses[i].addressToWatch);
		}
	}
	

	return retval;
}
bool RemoveAddress(unsigned __int64 address) {
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
	PMEMORY_BASIC_INFORMATION info = new MEMORY_BASIC_INFORMATION;

	int e = VirtualQueryEx(GetCurrentProcess(), (void*)Address, info, sizeof(MEMORY_BASIC_INFORMATION));

	if (e == 0) {
		HRESULT err = HRESULT_FROM_WIN32(GetLastError());
		delete info;
		return false;
	}

	if (info->Protect & PAGE_GUARD) {
		delete info;
		return true; //we already guarded this section of memory

	}


	info->Protect |= PAGE_GUARD;
	DWORD tmp = 0;
	e = VirtualProtectEx(GetCurrentProcess(), info->BaseAddress, 1, info->Protect, &tmp);
	if (e == 0) {
		HRESULT err = HRESULT_FROM_WIN32(GetLastError());
		delete info;
		return false;
	}
	delete info;
	return true;
}

bool RemoveGuardPage(unsigned __int64 Address) {

	PMEMORY_BASIC_INFORMATION info = new MEMORY_BASIC_INFORMATION;

	int e = VirtualQueryEx(GetCurrentProcess(), (void*)Address, info, sizeof(MEMORY_BASIC_INFORMATION));

	if (e == 0) {
		HRESULT err = HRESULT_FROM_WIN32(GetLastError());
		delete info;
		return false;
	}


	if (info->Protect & PAGE_GUARD) {
		info->Protect &= ~PAGE_GUARD;
		DWORD tmp = 0;
		e = VirtualProtectEx(GetCurrentProcess(), info->BaseAddress, 1, info->Protect, &tmp);
		if (e == 0) {
			HRESULT err = HRESULT_FROM_WIN32(GetLastError());
			delete info;
			return false;
		}

	}
	delete info;
	return true;
}

long VectoredExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo) {


	if (HRESULT_FROM_WIN32(ExceptionInfo->ExceptionRecord->ExceptionCode) == STATUS_GUARD_PAGE_VIOLATION) {
		if(ExceptionInfo->ExceptionRecord->ExceptionInformation[1] == 0xffffffffffffffff)
			return EXCEPTION_CONTINUE_SEARCH;
		for (int i = 0; i < _sizeofAddresses; i++) {
			if(_addresses->watched)
				if (_addresses[i].addressToWatch != 0 && ExceptionInfo->ExceptionRecord->ExceptionInformation[1] >= (unsigned long)_addresses[i].addressToWatch && ExceptionInfo->ExceptionRecord->ExceptionInformation[1] <= (unsigned long)_addresses[i].addressToWatch + _addresses[i].sizeOfType) {
					_addresses[i].watched = false; //page needs to be reset
					for (int i = 0; i < _sizeOfInfo; i++) {
						if (!_accessInfo[i].inUse) {
							_accessInfo[i].addressAccessed = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
							RtlCaptureStackBackTrace(0, _framesToCapture, (void**)(_accessInfo[i].frameTrace), nullptr);
							_accessInfo[i].inUse = true;
							break;
						}
					}
				}
		}

		ExceptionInfo->ContextRecord->ContextFlags |= CONTEXT_CONTROL;
		ExceptionInfo->ContextRecord->EFlags |= 0x0100;
		return EXCEPTION_CONTINUE_EXECUTION;	//Swallow all the page guards cause idgaf
	}
	else if (HRESULT_FROM_WIN32(ExceptionInfo->ExceptionRecord->ExceptionCode) == STATUS_SINGLE_STEP) {
		ExceptionInfo->ContextRecord->ContextFlags &= ~CONTEXT_CONTROL;
		ExceptionInfo->ContextRecord->EFlags &= ~0x0100;
		for (int i = 0; i < _sizeofAddresses; i++) {
			if (_addresses[i].addressToWatch != 0 && !_addresses[i].watched) {
				GuardPage(_addresses[i].addressToWatch);
				_addresses[i].watched = true;
			}
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}