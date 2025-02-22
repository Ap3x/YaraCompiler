#include "YaraCompiler.h"
#include "yara.h"

using namespace std;

YARA_COMPILE_RESULTS CompileYaraRules(string folderPath, YR_COMPILER* compiler) {
	WIN32_FIND_DATAA findData;
	HANDLE hFind;
	YARA_COMPILE_RESULTS results;
	string searchPattern = folderPath + "\\*";

	hFind = FindFirstFileA(searchPattern.c_str(), &findData);
	if (hFind == INVALID_HANDLE_VALUE) {
		results.success = FALSE;
		results.error = "Failed to find files or folders in the current folder.\n";
		return results;
	}

	do {
		// Check if the found item is a directory
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			// Skip "." and ".." directories
			if (strcmp((LPCSTR)findData.cFileName, ".") != 0 && strcmp((LPCSTR)findData.cFileName, "..") != 0) {

				string subFolderPath = folderPath + "\\" + findData.cFileName;

				// Recursively process the subfolder
				CompileYaraRules(subFolderPath, compiler);
			}
		}
		else {
			LPCSTR extension = PathFindExtensionA(findData.cFileName);
			if (strcmp(extension, ".yar") == 0) {

				string filePath = folderPath + "\\" + findData.cFileName;

				HANDLE hFile = CreateFileA(
					(LPCSTR)filePath.c_str(),
					GENERIC_READ,
					FILE_SHARE_READ,
					NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL
				);


				if (hFile != INVALID_HANDLE_VALUE && yr_compiler_add_fd(compiler, hFile, NULL, NULL) != ERROR_SUCCESS) {
					CloseHandle(hFile);
					results.success = FALSE;
					char* errMsg = (char*)malloc(sizeof(char*));
					if (errMsg != NULL) {
						const char* errMsgFmt = "Failed to open .yar file: %s\n";
						sprintf_s(errMsg, strlen(errMsgFmt), errMsgFmt, filePath);
					}
					return results;
				}
			}
		}
	} while (FindNextFileA(hFind, &findData) != 0);

	FindClose(hFind);

	results.success = TRUE;
	return results;
}

int main(int argc, char* argv[])
{
	YR_COMPILER* compiler;
	YR_RULES* rules;
	yr_initialize();
	yr_compiler_create(&compiler);

	if (argc < 2) {
		printf("%s <YARA_RULES_FOLDER> <SAVE_PATH>\n", argv[0]);
		return 1;
	}

	STATUS_PRINT("Attempting to compile the yara rules\n");
	YARA_COMPILE_RESULTS results = CompileYaraRules(argv[1], compiler);
	if (!results.success) {
		ERROR_PRINT("Unable to compile yara rules: %s\n", results.error);
		return 1;
	}

	STATUS_PRINT("Successfully compiled the yara rules\n");

	if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
		ERROR_PRINT("Error attempting to retrieve the rules\n");
		return 1;
	}

	STATUS_PRINT("Attempting to save the yara rules to: %s\n", argv[2]);

	if (yr_rules_save(rules, argv[2]) != ERROR_SUCCESS) {
		ERROR_PRINT("Error attempting to save yara rules to file\n");
		return 1;
	}

	STATUS_PRINT("Successfully saved compiled the yara rules to %s\n", argv[2]);
	return 0;
}