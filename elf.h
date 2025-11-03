/******************************************************************************
 * @file            elf.h
 *****************************************************************************/
#ifndef     _ELF_H
#define     _ELF_H

#define     EI_CLASS                    4
# define        ELF_CLASS32             1
# define        ELF_CLASS64             2
#define     EI_DATA                     5
# define        ELF_DATA2LSB            1
# define        ELF_DATA2MSB            2
#define     EI_VERSION                  6
# define        EV_CURRENT              1

#define     ELF_DATA2MSB                2

#define     ET_REL                      1
#define     ET_EXEC                     2

struct elf32_exec {

    unsigned char e_ident[16];
    unsigned char e_type[2];
    unsigned char e_machine[2];
    unsigned char e_version[4];
    unsigned char e_entry[4];
    unsigned char e_phoff[4];
    unsigned char e_shoff[4];
    unsigned char e_flags[4];
    unsigned char e_ehsize[2];
    unsigned char e_phentsize[2];
    unsigned char e_phnum[2];
    unsigned char e_shentsize[2];
    unsigned char e_shnum[2];
    unsigned char e_shstrndx[2];

};

#define     SHT_NULL                    0
#define     SHT_PROGBITS                1
#define     SHT_SYMTAB                  2
#define     SHT_STRTAB                  3
#define     SHT_NOBITS                  8

struct elf32_shdr {
    
    unsigned char sh_name[4];
    unsigned char sh_type[4];
    unsigned char sh_flags[4];
    unsigned char sh_addr[4];
    unsigned char sh_offset[4];
    unsigned char sh_size[4];
    unsigned char sh_link[4];
    unsigned char sh_info[4];
    unsigned char sh_addralign[4];
    unsigned char sh_entsize[4];

};

#define     SHF_WRITE                   0x01
#define     SHF_ALLOC                   0x02
#define     SHF_EXEC_INSTR              0x04

struct elf32_sym {

    unsigned char st_name[4];
    unsigned char st_value[4];
    unsigned char st_size[4];
    unsigned char st_info[1];
    unsigned char st_other[1];
    unsigned char st_shndx[2];

};

#define     SHN_UNDEF                   0x0000
#define     SHN_LORESERVE               0xFF00
#define     SHN_ABS                     0xFFF1
#define     SHN_COMMON                  0xFFF2
#define     SHN_HIRESERVE               0xFFFF

struct elf32_rela {

    unsigned char r_offset[4];
    unsigned char r_info[4];
    unsigned char r_addend[4];

};

struct elf32_rel {

    unsigned char r_offset[4];
    unsigned char r_info[4];

};

#define     R_386_NONE                  0
#define     R_386_32                    1
#define     R_386_PC32                  2

struct elf32_phdr {

    unsigned char p_type[4];
    unsigned char p_offset[4];
    unsigned char p_vaddr[4];
    unsigned char p_paddr[4];
    unsigned char p_filesz[4];
    unsigned char p_memsz[4];
    unsigned char p_flags[4];
    unsigned char p_align[4];

};

void read_elf32_object (const char *filename, unsigned char *data, unsigned long data_size, int endianess);

void elf_before_link (void);
void elf32_write (const char *filename);

#include    "stdint.h"
uint64_t elf_get_first_section_rva (void);

#endif      /* _ELF_H */
