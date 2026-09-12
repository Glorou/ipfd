#pragma once

extern "C" __declspec(dllexport) bool AttachVEH();
extern "C" __declspec(dllexport) bool DetachVEH();
extern "C" __declspec(dllexport) bool MonitorAddress(void* address, unsigned int sizeOfObject);
extern "C" __declspec(dllexport) void SetCallback(void* callback);
static bool GuardPage();
static bool RemoveGuardPage();
static long VectoredExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo);