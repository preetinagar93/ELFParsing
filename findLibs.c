#define _XOPEN_SOURCE 500
#include <ftw.h>
#include <inttypes.h>
#include <sys/mman.h>
#include "elfHeader.h"

static int numLibs = 0;
unsigned char hostEd = 0, fileEd = 0;

static void changeEndian(char * buffer, size_t size)
{
	if(size == 1)
	return;

	if(hostEd == fileEd)
	return;

	unsigned char temp, start, end;

	for(size_t i=0, j=size-1;i<size && i<j;i++, j--)
	{
		temp=buffer[i];
		buffer[i]=buffer[j];
		buffer[j]=temp;
	}
}

#define getdata(value) changeEndian((char*)&value, sizeof(value))

static void processFile(const char * filePath, int size, const char *fileName)
{
	FILE *fp = NULL;

	unsigned char elfMagic[4] = {0x7f, 'E', 'L', 'F'};
	unsigned char magicVal[4] = {0x0}, class={0x0}, endins={0x0};
        uint16_t machine = {0x0};

	fp = fopen(filePath, "rb");
	if(fp == NULL)
	{
		fclose(fp);
		return;
	}

	fread(&magicVal, sizeof(magicVal), 1, fp);

	if (memcmp(magicVal, elfMagic, sizeof(elfMagic)) == 0)
	{
		numLibs++;

		fileEd = 0;

		if(numLibs == 1)
			printf(" File\t\t: ArchType\n ==============  ====================================\n");

		fseek(fp, 0x05, SEEK_SET);
		fread(&endins, sizeof(endins), 1, fp);

		fileEd = endins;

		fseek(fp, 0x12, SEEK_SET);
		fread(&machine, sizeof(machine), 1, fp);

		printf("\n %s : ", filePath);

		getdata(machine);

		switch(machine)
		{
			case EM_MIPS:    printf("mips");
					 break;
			case EM_X86_64:  printf("x86_64");
					 break;
			case EM_386:     printf("x86");
					 break;
			case EM_AARCH64: printf("arm64-v8a");
				         break; 
			case EM_ARM:     printf("armeabi");
					 {
						/* To distinguish ARM arch version, reading CPU arch attribute from
						   ARM attributes section */

						fseek(fp, 0, SEEK_END);					

						long int fsize = ftell(fp);

						fseek(fp, 0, SEEK_SET);

						char * base = mmap(0, fsize, PROT_READ, MAP_PRIVATE, fileno(fp), 0);

						if (base == MAP_FAILED)
						{
							printf("mmap failed %s", strerror(errno));
							goto end;
						}

						uint32_t shoff = {0x0}, shstrsection_offset = {0x0}, sh_name={0x0};
						uint16_t shnum = {0x0}, shstrndx ={0x0}, i=0, flag=0;
						uint32_t armAttrSecOffset = {0x0}, size={0x0};
						char armSectionName[] = ".ARM.attributes";

						Elf32_Ehdr *header32 = (Elf32_Ehdr*)base;

						shoff = header32->e_shoff;
						getdata(shoff);

						shnum= header32->e_shnum;
						getdata(shnum);

						Elf32_Shdr *sectionHdr32 = (Elf32_Shdr*)(base + shoff);

						shstrndx = header32->e_shstrndx;
						getdata(shstrndx);

						Elf32_Shdr *shstrsection = &sectionHdr32[shstrndx];

						shstrsection_offset = shstrsection->sh_offset;
						getdata(shstrsection_offset);

						const char * const shstr= base + shstrsection_offset;

						// Finding ARM attributes section offset and size
						while(i<shnum)
						{
							sh_name=sectionHdr32[i].sh_name;
							getdata(sh_name);

							if (strcmp(armSectionName, shstr + sh_name) == 0)
							{
								armAttrSecOffset=sectionHdr32[i].sh_offset;
								size=sectionHdr32[i].sh_size;
								getdata(armAttrSecOffset);
								getdata(size);

								flag=1;
								break;
							}	
							i++;
						}

						if(flag == 0)
							break;
						else if(flag == 1)
						{
							// Parsing ARM attributes section to find "aeabi" vendor subsection
							char *temp, *buf = base + armAttrSecOffset;
							unsigned char armCPUTarget[] = "v7", *curr ={0x0}, subfound=0;
							uint32_t vendor_subsection_size = {0x0}, attrsection_len={0x0}, curr_subsection_size = {0x0};

							curr = buf;
							if( *curr == 'A')
							{	curr++;
								attrsection_len = size-1;
								while(attrsection_len > 0)
								{	vendor_subsection_size=*(uint32_t *)curr;
									getdata(vendor_subsection_size);

									if(vendor_subsection_size > attrsection_len)
										break;

									curr+=4;
									curr_subsection_size = vendor_subsection_size-4;

									if(strcmp(curr, "aeabi")==0)
									{	subfound=1;
										curr+=strlen("aeabi");
										curr_subsection_size-=strlen("aeabi");
										break;
									}
									curr+=curr_subsection_size;
									attrsection_len-=(vendor_subsection_size+4);
								}
							}

							if(subfound == 1)
							{
								// Parsing aeabi subsection tags and values to find File attributes
								int tag ={0x0}, fileattrfound = {0x0};
								uint32_t attrsize= {0x0}, attrlen = curr_subsection_size;

								while(attrlen > 0)
								{
									curr++;
									tag=*curr;

									curr++;
									attrsize=*(uint32_t *)curr;
									getdata(attrsize);

									if(attrsize > attrlen)
										break;

									curr+=4;

									if(tag == 1)
									{
										fileattrfound = 1;
										break;
									}

									attrlen-=attrsize;
									curr+=(attrsize-5);
								}

								if(fileattrfound == 1)
								{
									// parsing File attributes for CPU_Arch tag
									unsigned char * limit = {0x0};
									attrsize -= 5;

									limit = curr + attrsize;

									while(curr < limit)
									{
										unsigned char tag = {0x0};
										tag= *curr;
										curr ++;

										if( tag == 0x06)
										{
											if(*(curr) == 0x0a)
												printf("-v7");
											break;
										}

										/* Assuming only 0x04 and 0x05 tags have public value
											of a NULL-terminated string*/
										if( tag == 0x04 || tag == 0x05)
										{	while(curr < limit && *(curr)!='\0')
												curr++;
										}
										curr++;
									}

								}
							}

						}

						if ( munmap(base, fsize) == -1 ){
							printf("munmap failed with error");
						}

					 }

					 break;
			default: break;
		}			
	}	

end:
	fclose(fp);

	return;
}

static int processFiles(const char *fpath, const struct stat *sb,
                    int tflag, struct FTW *ftwbuf)
{
        if(tflag == FTW_F)
                processFile(fpath, sizeof(fpath), fpath + ftwbuf->base);

        return 0;
}

static void check_host_endianness(void)
{
	int i=1;
	char * ch = (char*)&i;
	if(ch[0] == 0)
	{
		hostEd = 2;
	}
	else
	{
		hostEd = 1;
	}
}

int main(int argc, char **argv)
{
	int flags =0;

	check_host_endianness();

	if (nftw((argc < 2) ? "." : argv[1], processFiles, 20, flags) == -1) {
               perror("nftw");
               exit(EXIT_FAILURE);
        }

	printf("\n\n Total number of libraries: %d\n", numLibs);
	return 0;
}
