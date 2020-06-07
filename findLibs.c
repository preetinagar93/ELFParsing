#define _XOPEN_SOURCE 500
#include <ftw.h>
#include <inttypes.h>
#include <sys/mman.h>
#include "elfHeader.h"

#define maxLen 4096
static int numLibs = 0;

static void bigToLittleEndian(char * buffer, int size)
{
	if(size == 1)
	return;

	unsigned char temp, start, end;

	for(int i=0, j=size-1;i<size && i<j;i++, j--)
	{
		temp=buffer[i];
		buffer[i]=buffer[j];
		buffer[j]=temp;
	}
}

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

		if(numLibs == 1)
			printf(" File\t\t: ArchType\n ==============  ====================================\n");

		fseek(fp, 0x05, SEEK_SET);
		fread(&endins, sizeof(endins), 1, fp);

		fseek(fp, 0x12, SEEK_SET);
		fread(&machine, sizeof(machine), 1, fp);

		if(endins == 2)
		{
			bigToLittleEndian((char *)&machine, sizeof(machine));
		}

		printf("\n %s: ", filePath);
		
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
						fseek(fp, 0, SEEK_END);					

						long int fsize = ftell(fp);

						fseek(fp, 0, SEEK_SET);

						char * base = mmap(0, fsize, PROT_READ, MAP_PRIVATE, fileno(fp), 0);

						if (base == MAP_FAILED)
						{
							printf("mmap failed %s", strerror(errno));
							goto end;
						}

						Elf32_Ehdr *header32 = (Elf32_Ehdr*)base;
						Elf32_Shdr *sectionHdr32 = (Elf32_Shdr*)(base + header32->e_shoff);

                                                uint16_t shnum= header32->e_shnum, i=0, flag=0;
						Elf32_Shdr *shstrndx = &sectionHdr32[header32->e_shstrndx];

						const char * const shstr= base + shstrndx->sh_offset;
						uint32_t armAttrSecOffset = {0x0}, size={0x0};
						char armSectionName[] = ".ARM.attributes";

						while(i<shnum)
						{
							if (strcmp(armSectionName, shstr + sectionHdr32[i].sh_name) == 0)
							{
								armAttrSecOffset=sectionHdr32[i].sh_offset;
								size=sectionHdr32[i].sh_size;
								flag=1;
								break;
							}	
							i++;
						}

						if(flag == 0)
							break;
						else if(flag == 1)
						{
							char *temp, *buf = base + armAttrSecOffset;
							unsigned char armCPUTarget[] = "ARM v7";
							for(temp=buf;temp<buf+size;temp++)
							{ 
								if(strcmp(temp, armCPUTarget)==0)
								{	printf("-v7");
									break;
								}
							}
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

int main(int argc, char **argv)
{
	int flags =0;

	if (nftw((argc < 2) ? "." : argv[1], processFiles, 20, flags) == -1) {
               perror("nftw");
               exit(EXIT_FAILURE);
        }

	printf("\n\n Total number of libraries: %d\n", numLibs);
	return 0;
}
