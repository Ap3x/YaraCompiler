#pragma once
#include <Windows.h>
#include <string>
#include <shlwapi.h>

#define STATUS_PRINT(format, ...) \
    do { \
        printf("[+] "); \
        printf(format, ##__VA_ARGS__); \
    } while (0)

#define ERROR_PRINT(format, ...) \
    do { \
        printf("[-] "); \
        printf(format, ##__VA_ARGS__); \
    } while (0)

#define WARNING_PRINT(format, ...) \
    do { \
        printf("[!] "); \
        printf(format, ##__VA_ARGS__); \
    } while (0)

struct YARA_COMPILE_RESULTS
{
	LPCSTR error;
	BOOL success;
};