#pragma once
#include <Windows.h>


class AutoHandle
{
public:
	AutoHandle(HANDLE Handle) : m_handle(Handle) {};
	~AutoHandle() { CloseHandle(m_handle); };
private:
	HANDLE m_handle;
};