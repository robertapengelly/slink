/******************************************************************************
 * @file            pe.h
 *****************************************************************************/
#ifndef     _PE_H
#define     _PE_H

#define     DEFAULT_SECTION_ALIGNMENT       0x1000
#define     DEFAULT_FILE_ALIGNMENT          0x0200

struct msdos_header {

    unsigned char e_magic[2];           /* Magic number                         */
    unsigned char e_cblp[2];            /* Bytes on last page of file           */
    unsigned char e_cp[2];              /* Pages in file                        */
    unsigned char e_crlc[2];            /* Relocations                          */
    unsigned char e_cparhdr[2];         /* Size of header in paragraphs         */
    unsigned char e_minalloc[2];        /* Minimum extra paragraphs needed      */
    unsigned char e_maxalloc[2];        /* Maximum extra paragraphs needed      */
    unsigned char e_ss[2];              /* Initial (relative) SS value          */
    unsigned char e_sp[2];              /* Initial SP value                     */
    unsigned char e_csum[2];            /* Checksum                             */
    unsigned char e_ip[2];              /* Initial IP value                     */
    unsigned char e_cs[2];              /* Initial (relative) CS value          */
    unsigned char e_lfarlc[2];          /* File address of relocation table     */
    unsigned char e_ovno[2];            /* Overlay number                       */
    unsigned char e_res[8];             /* Reserved words                       */
    unsigned char e_oemid[2];           /* OEM identifier (for e_oeminfo)       */
    unsigned char e_oeminfo[2];         /* OEM information; e_oemid specific    */
    unsigned char e_res2[20];           /* Reserved words                       */
    unsigned char e_lfanew[4];          /* File address of new exe header       */

};

#define     IMAGE_SUBSYSTEM_UNKNOWN                         0
#define     IMAGE_SUBSYSTEM_NATIVE                          1
#define     IMAGE_SUBSYSTEM_WINDOWS_GUI                     2
#define     IMAGE_SUBSYSTEM_WINDOWS_CUI                     3
#define     IMAGE_SUBSYSTEM_OS2_CUI                         5
#define     IMAGE_SUBSYSTEM_POSIX_CUI                       7
#define     IMAGE_SUBSYSTEM_EFI_APPLICATION                 10
#define     IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER         11
#define     IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER              12
#define     IMAGE_SUBSYSTEM_EFI_ROM                         13
#define     IMAGE_SUBSYSTEM_XBOX                            14
#define     IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPILCATION        16

struct pe_header {

    unsigned char Signature[4];
    
    unsigned char Machine[2];
    unsigned char NumberOfSections[2];
    
    unsigned char TimeDateStamp[4];
    unsigned char PointerToSymbolTable[4];
    unsigned char NumberOfSymbols[4];
    
    unsigned char SizeOfOptionalHeader[2];
    unsigned char Characteristics[2];

};

#define     IMAGE_FILE_MACHINE_I386                         0x014C

#define     IMAGE_FILE_RELOCS_STRIPPED                      0x0001
#define     IMAGE_FILE_EXECUTABLE_IMAGE                     0x0002
#define     IMAGE_FILE_LINE_NUMS_STRIPPED                   0x0004
#define     IMAGE_FILE_LOCAL_SYMS_STRIPPED                  0x0008
#define     IMAGE_FILE_32BIT_MACHINE                        0x0100
#define     IMAGE_FILE_DEBUG_STRIPPED                       0x0200

struct pe_optional_header {

    unsigned char Magic[2];
    
    unsigned char MajorLinkerVersion;
    unsigned char MinorLinkerVersion;
    
    unsigned char SizeOfCode[4];
    unsigned char SizeOfInitializedData[4];
    unsigned char SizeOfUninitializedData[4];
    
    unsigned char AddressOfEntryPoint[4];
    
    unsigned char BaseOfCode[4];
    unsigned char BaseOfData[4];
    
    
    unsigned char ImageBase[4];
    unsigned char SectionAlignment[4];
    unsigned char FileAlignment[4];
    
    unsigned char MajorOperatingSystemVersion[2];
    unsigned char MinorOperatingSystemVersion[2];
    unsigned char MajorImageVersion[2];
    unsigned char MinorImageVersion[2];
    unsigned char MajorSubsystemVersion[2];
    unsigned char MinorSubsystemVersion[2];
    
    unsigned char Win32VersionValue[4];
    unsigned char SizeOfImage[4];
    unsigned char SizeOfHeaders[4];
    unsigned char Checksum[4];
    
    unsigned char Subsystem[2];
    unsigned char DllCharacteristics[2];
    
    unsigned char SizeOfStackReserved[4];
    unsigned char SizeOfStackCommit[4];
    unsigned char SizeOfHeapReserved[4];
    unsigned char SizeOfHeapCommit[4];
    
    unsigned char LoaderFlags[4];
    unsigned char NumberOfRvaAndSizes[4];
    
    
    /*unsigned char Reserved[128];*/
    unsigned char Reserved[32 * 4];

};

#define     IMAGE_FILE_MAGIC_I386                           0x010B

struct pe_section_table_entry {

    char Name[8];
    
    unsigned char VirtualSize[4];
    unsigned char VirtualAddress[4];
    
    unsigned char SizeOfRawData[4];
    unsigned char PointerToRawData[4];
    unsigned char PointerToRelocations[4];
    unsigned char PointerToLinenumbers[4];
    
    unsigned char NumberOfRelocations[2];
    unsigned char NumberOfLinenumbers[2];
    
    unsigned char Characteristics[4];

};

#define     IMAGE_SCN_TYPE_NOLOAD                           0x00000002
#define     IMAGE_SCN_CNT_CODE                              0x00000020
#define     IMAGE_SCN_CNT_INITIALIZED_DATA                  0x00000040
#define     IMAGE_SCN_CNT_UNINITIALIZED_DATA                0x00000080
#define     IMAGE_SCN_LNK_INFO                              0x00000200
#define     IMAGE_SCN_LNK_REMOVE                            0x00000800
#define     IMAGE_SCN_ALIGN_4BYTES                          0x00300000
#define     IMAGE_SCN_MEM_SHARED                            0x10000000
#define     IMAGE_SCN_MEM_EXECUTE                           0x20000000
#define     IMAGE_SCN_MEM_READ                              0x40000000
#define     IMAGE_SCN_MEM_WRITE                             0x80000000

struct pe_image_data_directory {

    unsigned char VirtualAddress[4];
    unsigned char Size[4];

};

struct pe_base_relocation {

    unsigned char RVAOfBlock[4];
    unsigned char SizeOfBlock[4];

};

#define     BASE_RELOCATION_PAGE_SIZE                       4096

#define     IMAGE_REL_BASED_ABSOLUTE                        0
#define     IMAGE_REL_BASED_HIGH                            1
#define     IMAGE_REL_BASED_LOW                             2
#define     IMAGE_REL_BASED_HIGHLOW                         3
#define     IMAGE_REL_BASED_HIGHADJ                         4
#define     IMAGE_REL_BASED_MIPS_JMPADDR                    5
#define     IMAGE_REL_BASED_ARM_MOV32                       5
#define     IMAGE_REL_BASED_RISCV_HIGH20                    5
#define     IMAGE_REL_BASED_THUMB_MOV32                     7
#define     IMAGE_REL_BASED_RISCV_LOW12I                    7
#define     IMAGE_REL_BASED_RISCV_LOW12S                    8
#define     IMAGE_REL_BASED_MIPS_JMPADDR16                  9
#define     IMAGE_REL_BASED_DIR64                           10

struct pe_import_directory_table {

    unsigned char ImportNameTableRVA[4];
    unsigned char TimeDateStamp[4];
    unsigned char ForwarderChain[4];
    unsigned char NameRVA[4];
    unsigned char ImportAddressTableRVA[4];

};

int pe_check_option (const char *cmd_arg, int argc, char **argv, int *optind, const char **optarg);

void pe_after_link (void);
void pe_before_link (void);
void pe_print_help (void);

unsigned long pe_get_first_section_rva (void);

void pe_write (const char *filename);
void pe_use_option (const char *cmd_arg, int idx, const char *optarg);

#endif      /* _PE_H */
