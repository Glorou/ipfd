// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "ipfd.h"



static void* Address = nullptr;  //one we monitor
static unsigned int sizeOf = 0;  //Size of the type
static void* VectoredExceptionHandlerPtr = nullptr;
static void* _callback = nullptr;
static void* _referencedAddress = nullptr;//actual address that got referenced
const int framesToCapture = 3;
static PVOID FramePointers[framesToCapture] = {0};



static bool AttachVEH() {
	VectoredExceptionHandlerPtr = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
	if (VectoredExceptionHandlerPtr == nullptr)
		return false;
	return true;
}
static bool DetachVEH() {
	int out = RemoveVectoredExceptionHandler(VectoredExceptionHandler);
	if (out == 0)
		return true;
	return false;

}
static bool MonitorAddress(void* address, unsigned int sizeOfObject) {
	if (Address != nullptr)
		RemoveGuardPage();
	Address = address;
	sizeOf = sizeOfObject;	
	return GuardPage();
}
static void SetCallback(void* callback) {
	_callback = callback;
}
static bool GuardPage() {
	if (VectoredExceptionHandlerPtr == nullptr)
		return false;
	PMEMORY_BASIC_INFORMATION info = new MEMORY_BASIC_INFORMATION;

	int e = VirtualQueryEx(GetCurrentProcess(), Address, info, sizeof(MEMORY_BASIC_INFORMATION));

	if (e == 0) {
		HRESULT err = HRESULT_FROM_WIN32(GetLastError());
		delete info;
		return false;
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

static bool RemoveGuardPage() {

	PMEMORY_BASIC_INFORMATION info = new MEMORY_BASIC_INFORMATION;

	int e = VirtualQueryEx(GetCurrentProcess(), Address, info, sizeof(MEMORY_BASIC_INFORMATION));

	if (e == 0) {
		HRESULT err = HRESULT_FROM_WIN32(GetLastError());
		delete info;
		return false;
	}


	if (info->Protect && PAGE_GUARD) {
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

static long VectoredExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo) {


	if (HRESULT_FROM_WIN32(ExceptionInfo->ExceptionRecord->ExceptionCode) == STATUS_GUARD_PAGE_VIOLATION) {
		if (ExceptionInfo->ExceptionRecord->ExceptionInformation[2] >= (unsigned long)Address && ExceptionInfo->ExceptionRecord->ExceptionInformation[2] <= (unsigned long)Address + sizeOf) {
			_referencedAddress = (void*)ExceptionInfo->ExceptionRecord->ExceptionInformation[2];
			RtlCaptureStackBackTrace(0, 3, FramePointers, nullptr);
		}
		ExceptionInfo->ContextRecord->ContextFlags |= CONTEXT_CONTROL;
		ExceptionInfo->ContextRecord->EFlags |= 0x0100;
		return EXCEPTION_CONTINUE_EXECUTION;	//Swallow all the page guards cause idgaf
	}
	else if (HRESULT_FROM_WIN32(ExceptionInfo->ExceptionRecord->ExceptionCode) == STATUS_SINGLE_STEP) {
		ExceptionInfo->ContextRecord->ContextFlags &= ~CONTEXT_CONTROL;
		ExceptionInfo->ContextRecord->EFlags &= ~0x0100;
		GuardPage();
		
		if (_callback != nullptr)
			((void(*)(void*, PVOID*))_callback)(_referencedAddress, FramePointers);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}