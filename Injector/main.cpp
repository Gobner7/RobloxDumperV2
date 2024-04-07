// Injector/main.cpp

#include "Process.h"
#include <filesystem>
#include <vector>
#include <iostream>
#include <commdlg.h> // Include the common dialog box library

// Function to log to console
void Log(const char* message) {
    std::cout << message << std::endl;
}

// Function to prompt the user to select a file
std::wstring OpenFileSelector() {
    OPENFILENAME ofn;       // common dialog box structure
    wchar_t szFile[260];    // buffer for file name
    HWND hwnd = NULL;       // owner window

    // Initialize OPENFILENAME
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    // Set lpstrFile[0] to '\0' so that GetOpenFileName does not use the contents of szFile to initialize itself.
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = L"Executable Files\0*.EXE\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn) == TRUE) {
        return ofn.lpstrFile;
    }
    return L"";
}

int main() {
    Log("Starting Roblox DLL Injector...");

    // Try to find the Roblox process
    Process* robloxProcess = Process::ByName(L"RobloxPlayerBeta.exe");

    // If the Roblox process is not found, prompt user to select the file
    if (!robloxProcess) {
        Log("RobloxPlayerBeta.exe not found. Please select the executable.");
        std::wstring manualPath = OpenFileSelector();
        if (!manualPath.empty()) {
            robloxProcess = Process::ByName(manualPath.c_str());
        }
    }

    // If the Roblox process is still not found, exit
    if (!robloxProcess) {
        Log("RobloxPlayerBeta.exe not selected or found. Exiting injector.");
        return -1;
    }

    Log("Roblox process found. Attempting to inject Dumper.dll...");

    // Get the full path to the Dumper.dll
    auto dllPath = GetBinPath() / "Dumper.dll";
    if (!std::filesystem::exists(dllPath)) {
        Log("Dumper.dll not found. Make sure to compile the DLL.");
        return -1;
    }

    // Attempt DLL injection
    DWORD result = InjectLL(robloxProcess->ph, dllPath.string().c_str());
    if (result == 0) {
        Log("Dumper.dll successfully injected.");
    } else {
        Log(("Injection failed with error code: " + std::to_string(result)).c_str());
    }

    return 0;
}

