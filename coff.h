/******************************************************************************
 * @file            coff.h
 *****************************************************************************/
#ifndef     _COFF_H
#define     _COFF_H

#define     IMAGE_FILE_MACHINE_I386                         0x014C

struct coff_header {

    unsigned char Machine[2];
    unsigned char NumberOfSections[2];
    
    unsigned char TimeDateStamp[4];
    unsigned char PointerToSymbolTable[4];
    unsigned char NumberOfSymbols[4];
    
    unsigned char SizeOfOptionalHeader[2];
    unsigned char Characteristics[2];

};

#define     IMAGE_FILE_RELOCS_STRIPPED                      0x0001
#define     IMAGE_FILE_EXECUTABLE_IMAGE                     0x0002
#define     IMAGE_FILE_LINE_NUMS_STRIPPED                   0x0004
#define     IMAGE_FILE_LOCAL_SYMS_STRIPPED                  0x0008
#define     IMAGE_FILE_LITTLE_ENDIAN                        0x0100

struct coff_optional_header {

    unsigned char Magic[2];
    
    unsigned char MajorLinkerVersion;
    unsigned char MinorLinkerVersion;
    
    unsigned char SizeOfCode[4];
    unsigned char SizeOfInitializedData[4];
    unsigned char SizeOfUninitializedData[4];
    
    unsigned char AddressOfEntryPoint[4];
    
    unsigned char BaseOfCode[4];
    unsigned char BaseOfData[4];

};

#define     IMAGE_FILE_MAGIC_I386                           0x010B

struct coff_section_table_entry {

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

struct coff_relocation_entry {

    unsigned char VirtualAddress[4];
    unsigned char SymbolTableIndex[4];
    
    unsigned char Type[2];

};

#define     IMAGE_REL_I386_ABSOLUTE                         0x0000
#define     IMAGE_REL_I386_DIR16                            0x0001
#define     IMAGE_REL_I386_REL16                            0x0002
#define     IMAGE_REL_I386_DIR32                            0x0006
#define     IMAGE_REL_I386_DIR32NB                          0x0007
#define     IMAGE_REL_I386_REL32                            0x0014

void coff_after_link (void);
void coff_before_link (void);

void coff_write (const char *filename);

#endif      /* _COFF_H */
