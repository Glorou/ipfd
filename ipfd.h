#pragma once

struct Access_Info {
	bool inUse;
	unsigned __int64 addressAccessed;
	unsigned __int64 frameTrace[];
};
struct Address_Info {
	unsigned __int64 addressToWatch;
	unsigned __int64 sizeOfType;
	bool watched;
};

extern "C" __declspec(dllexport) bool AttachVEH();
extern "C" __declspec(dllexport) bool DetachVEH();
extern "C" __declspec(dllexport) bool RefreshAddresses();
extern "C" __declspec(dllexport) bool RemoveAddress(unsigned __int64 address);
extern "C" __declspec(dllexport) void SetupParams(Access_Info* array, int sizeOfInfo, int framesToCap, Address_Info* addresses, int sizeOfAddresses);

bool GuardPage(unsigned __int64 Address);
bool RemoveGuardPage(unsigned __int64 Address);
long VectoredExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo);

