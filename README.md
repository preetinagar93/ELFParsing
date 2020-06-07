Overview:

Program to find the number of libraries present and architecture type of all the libraries inside the path provided. The approach used is parsing of the ELF header information to identify the target architecture type. Further, in case of ARM architecture, section information is also parsed to identify the target CPU attributes to confim if architecture is ARM v7 or previous version.

Steps to Run:
1. Run make
2. ./output "path of the directory"

NOTE: if no path passed, default value is take as (.)  current directory

References:
[1] https://linux.die.net/man/5/elf
[2] https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
