# reflective-dotnet-extractor

rde.py

```
usage: rde.py [-h] File Directory

.Net Assembly Dumper V 1.0. Author: Mohammed Almodawah. This tool allows you to dump .Net Assemblies from a process memory dump.

positional arguments:
  File        Path to your process memory dump file
  Directory   Path of where you want to dump the extracted .Net Assemblies

optional arguments:
  -h, --help  show this help message and exit
```

Example:

```
user@host:~/# python rde.py YourProcessDump.mem YourOutputFolder/

Author: Mohammed Almodawah

.Net Assembly Dumper V 1.0

Dumping .Net Assemblies.....

File Name:  ToBeInjected.dll
MD5 Hash:   b25963c28e958c3686362dd3ea7774fd
Load Type:  [Reflective Loading]

```

Whatch this video for more information (Arabic):
https://youtu.be/HCPM0CAipbc
