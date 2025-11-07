/******************************************************************************
 * @file            macho.h
 *****************************************************************************/
#ifndef     _MACHO_H
#define     _MACHO_H

struct macho_header_64 {

    unsigned char magic[4];
    unsigned char cpu_type[4];
    unsigned char cpu_subtype[4];
    unsigned char file_type[4];
    unsigned char num_cmds[4];
    unsigned char sizeof_cmds[4];
    unsigned char flags[4];
    unsigned char reserved[4];

};

#define     MH_MAGIC_64                 0xFEEDFACF

#define     MH_CPU_TYPE_AMD64           0x01000007
#define     MH_CPU_TYPE_ARM64           0x0100000C

#define     MH_CPU_SUBTYPE_I386_ALL     3

#define     MH_OBJECT                   1
#define     MH_EXECUTE                  2

#define     MH_NOUNDEFS                 0x000001
#define     MH_DYLDLINK                 0x000004
#define     MH_TWOLEVEL                 0x000080
#define     MH_PIE                      0x200000

struct load_command {

    unsigned char command[4];
    unsigned char command_size[4];

};

#define     LC_SEGMENT_64               0x19
#define     LC_SYMTAB                   0x02
#define     LC_UNIXTHREAD               0x05
#define     LC_DYSYMTAB                 0x0B
#define     LC_LOAD_DYLIB               0x0C
#define     LC_LOAD_DYLINKER            0x0E
#define     LC_VERSION_MIN              0x24
#define     LC_FUNCTION_STARTS          0x26
#define     LC_DATA_IN_CODE             0x29
#define     LC_SOURCE_VERSION           0x2A

#define     LC_MAIN                     (0x80000000 | 0x28)
#define     LC_DYLD_EXPORTS_TRIE        (0x80000000 | 0x33)
#define     LC_DYLD_CHAINED_FIXUPS      (0x80000000 | 0x34)

struct segment_command_64 {

    unsigned char command[4];
    unsigned char command_size[4];
    
    char seg_name[16];
    
    unsigned char vm_addr[8];
    unsigned char vm_size[8];
    unsigned char file_off[8];
    unsigned char file_size[8];
    
    unsigned char max_prot[4];
    unsigned char init_prot[4];
    unsigned char num_sects[4];
    unsigned char flags[4];

};

struct section_64 {

    char sect_name[16];
    char seg_name[16];
    
    unsigned char addr[8];
    unsigned char size[8];
    
    unsigned char offset[4];
    unsigned char align[4];
    unsigned char rel_off[4];
    unsigned char num_reloc[4];
    
    unsigned char flags[4];
    
    unsigned char reserved1[4];
    unsigned char reserved2[4];
    unsigned char reserved3[4];

};

#define     S_REGULAR                   0x0400
#define     S_ZEROFILL                  0x0001
#define     S_CSTRING_LITERALS          0x0002

struct nlist_64 {

    unsigned char n_strx[4];
    unsigned char n_type[1];
    unsigned char n_sect[1];
    unsigned char n_desc[2];
    unsigned char n_value[8];

};

#define     MACHO_N_STAB                0xE0
#define     MACHO_N_PEXT                0x10

#define     MACHO_N_TYPE                0x0E
#define     MACHO_N_EXT                 0x01

#define     MACHO_N_UNDF                0x00
#define     MACHO_N_SECT                0x0E

struct unixthread_command {

    unsigned char command[4];
    unsigned char command_size[4];
    
    unsigned char flavor[4];
    unsigned char count[4];

};

struct amd64_thread_state64 {

    unsigned char rax[8];
    unsigned char rbx[8];
    unsigned char rcx[8];
    unsigned char rdx[8];
    unsigned char rdi[8];
    unsigned char rsi[8];
    unsigned char rbp[8];
    unsigned char rsp[8];
    unsigned char r8[8];
    unsigned char r9[8];
    unsigned char r10[8];
    unsigned char r11[8];
    unsigned char r12[8];
    unsigned char r13[8];
    unsigned char r14[8];
    unsigned char r15[8];
    unsigned char rip[8];
    unsigned char rflags[8];
    unsigned char cs[8];
    unsigned char fs[8];
    unsigned char gs[8];

};

struct macho_relocation_info {

    unsigned char r_address[4];
    unsigned char r_symbolnum[4];

};

#define     ARM64_RELOC_UNSIGNED                            0
#define     ARM64_RELOC_SUBTRACTOR                          1
#define     ARM64_RELOC_BRANCH26                            2
#define     ARM64_RELOC_PAGE21                              3
#define     ARM64_RELOC_PAGEOFF12                           4
#define     ARM64_RELOC_GOT_LOAD_PAGE21                     5
#define     ARM64_RELOC_GOT_LOAD_PAGEOFF12                  6
#define     ARM64_RELOC_POINTER_TO_GOT                      7
#define     ARM64_RELOC_TLVP_LOAD_PAGE21                    8
#define     ARM64_RELOC_TLVP_LOAD_PAGEOFF12                 9
#define     ARM64_RELOC_ADDEND                              10

#define     AMD64_RELOC_UNSIGNED        0
#define     AMD64_RELOC_SIGNED          1
#define     AMD64_RELOC_BRANCH          2
#define     AMD64_RELOC_GOT_LOAD        3
#define     AMD64_RELOC_GOT             4
#define     AMD64_RELOC_SUBTRACTOR      5
#define     AMD64_RELOC_SIGNED_1        6
#define     AMD64_RELOC_SIGNED_2        7
#define     AMD64_RELOC_SIGNED_4        8
#define     AMD64_RELOC_TLV             9

struct symtab_command {

    unsigned char command[4];
    unsigned char command_size[4];
    unsigned char symbol_offset[4];
    unsigned char num_symbols[4];
    unsigned char string_offset[4];
    unsigned char string_size[4];

};

struct dyld_chained_fixups_command {

    unsigned char command[4];
    unsigned char command_size[4];
    
    unsigned char data_offset[4];
    unsigned char data_size[4];

};

struct dyld_exports_trie {

    unsigned char command[4];
    unsigned char command_size[4];
    
    unsigned char data_offset[4];
    unsigned char data_size[4];

};

struct dylib_command {

    unsigned char command[4];
    unsigned char command_size[4];
    unsigned char name_offset[4];
    unsigned char timestamp[4];
    unsigned char current_version[4];
    unsigned char compatibility_version[4];

};

struct function_starts {

    unsigned char command[4];
    unsigned char command_size[4];
    
    unsigned char data_offset[4];
    unsigned char data_size[4];

};

struct data_in_code {

    unsigned char command[4];
    unsigned char command_size[4];
    
    unsigned char data_offset[4];
    unsigned char data_size[4];

};

struct version_min {

    unsigned char command[4];
    unsigned char command_size[4];
    
    unsigned char version[4];
    unsigned char sdk[4];

};

struct dylinker_command {

    unsigned char command[4];
    unsigned char command_size[4];
    unsigned char name_offset[4];

};

struct main_command {

    unsigned char command[4];
    unsigned char command_size[4];
    unsigned char entry_offset[8];
    unsigned char stack_size[8];

};

struct source_version {

    unsigned char command[4];
    unsigned char command_size[4];
    unsigned char version[8];

};

struct dysymtab_command {

    unsigned char cmd[4];
    unsigned char cmdsize[4];
    unsigned char ilocalsym[4];
    unsigned char nlocalsym[4];
    unsigned char iextdefsym[4];
    unsigned char nextdefsym[4];
    unsigned char iundefsym[4];
    unsigned char nundefsym[4];
    unsigned char tocoff[4];
    unsigned char ntoc[4];
    unsigned char modtaboff[4];
    unsigned char nmodtab[4];
    unsigned char extrefsymoff[4];
    unsigned char nextrefsyms[4];
    unsigned char indirectsymoff[4];
    unsigned char nindirectsyms[4];
    unsigned char extreloff[4];
    unsigned char nextrel[4];
    unsigned char locreloff[4];
    unsigned char nlocrel[4];

};

struct dyld_chained_fixups_header {

    unsigned char fixups_version[4];
    unsigned char starts_offset[4];
    unsigned char imports_offset[4];
    unsigned char symbols_offset[4];
    unsigned char imports_counts[4];
    unsigned char imports_format[4];
    unsigned char symbols_format[4];
    unsigned char padding[4];

};

#define     DYLD_CHAINED_IMPORT                             1
#define     DYLD_CHAINED_IMPORT_ADDEND                      2
#define     DYLD_CHAINED_IMPORT_ADDEND64                    3

struct dyld_chained_starts_in_image {

    unsigned char seg_count[4];
    unsigned char seg_into_offset[4][1];

};

struct dyld_chained_starts_in_segment {

    unsigned char size[4];
    unsigned char page_size[2];
    unsigned char pointer_format[2];
    unsigned char segment_offset[8];
    unsigned char max_valid_pointer[4];
    unsigned char page_count[2];
    unsigned char page_start[2];

};

#define     DYLD_CHAINED_PTR_START_NONE                     0xFFFF
#define     DYLD_CHAINED_PTR_START_MULTI                    0x8000
#define     DYLD_CHAINED_PTR_START_LAST                     0x8000

void read_macho_object (const char *filename, unsigned char *data, unsigned long data_size);

uint64_t macho_get_first_section_rva (void);
void macho_before_link (void);
void macho_write (const char *filename);


int macho_check_option (const char *cmd_arg, int argc, char **argv, int *optind, const char **optarg);

void macho_print_help (void);
void macho_use_option (const char *cmd_arg, int idx, const char *optarg);

#endif      /* _MACHO_H */
