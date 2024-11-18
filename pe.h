/******************************************************************************
 * @file            pe.h
 *****************************************************************************/
#ifndef     _PE_H
#define     _PE_H

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

struct section_table_entry {

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

#define     IMAGE_SCN_CNT_CODE                              0x00000020
#define     IMAGE_SCN_CNT_INITIALIZED_DATA                  0x00000040
#define     IMAGE_SCN_CNT_UNINITIALIZED_DATA                0x00000080
#define     IMAGE_SCN_ALIGN_4BYTES                          0x00300000
#define     IMAGE_SCN_MEM_EXECUTE                           0x20000000
#define     IMAGE_SCN_MEM_READ                              0x40000000
#define     IMAGE_SCN_MEM_WRITE                             0x80000000

struct relocation_entry {

    unsigned int VirtualAddress;
    unsigned int SymbolTableIndex;
    
    unsigned short Type;

};

#define     RELOCATION_ENTRY_SIZE                           10

#define     IMAGE_REL_I386_ABSOLUTE                         0x0000
#define     IMAGE_REL_I386_DIR32                            0x0006
#define     IMAGE_REL_I386_DIR32NB                          0x0007
#define     IMAGE_REL_I386_REL32                            0x0014

struct symbol_table_entry {

    char Name[8];
    unsigned int Value;
    
    signed short SectionNumber;
    unsigned short Type;
    
    unsigned char StorageClass;
    unsigned char NumberOfAuxSymbols;

};

#define     SYMBOL_TABLE_ENTRY_SIZE                         18
#define     IMAGE_SYM_UNDEFINED                             0

#define     IMAGE_SYM_ABSOLUTE                              -1
#define     IMAGE_SYM_DEBUG                                 -2

#define     IMAGE_SYM_TYPE_NULL                             0
#define     IMAGE_SYM_DTYPE_NULL                            0

#define     IMAGE_SYM_CLASS_EXTERNAL                        2
#define     IMAGE_SYM_CLASS_STATIC                          3
#define     IMAGE_SYM_CLASS_FILE                            103

#endif      /* _PE_H */
