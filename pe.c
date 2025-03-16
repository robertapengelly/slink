/******************************************************************************
 * @file            pe.c
 *****************************************************************************/
#include    <ctype.h>
#include    <errno.h>
#include    <limits.h>
#include    <stddef.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>
#include    <time.h>

#include    "ld.h"
#include    "lib.h"
#include    "pe.h"
#include    "report.h"
#include    "section.h"
#include    "write7x.h"

static unsigned short subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;

static unsigned long section_alignment = DEFAULT_SECTION_ALIGNMENT;
static unsigned long file_alignment = DEFAULT_FILE_ALIGNMENT;

struct exclude_symbol {

    char *name;
    struct exclude_symbol *next;

};

static struct exclude_symbol *exclude_symbols = 0;

#define     LD_OPTION_IGNORED                               0
#define     LD_OPTION_FILE_ALIGNMENT                        1
#define     LD_OPTION_SECTION_ALIGNMENT                     2
#define     LD_OPTION_STACK                                 3
#define     LD_OPTION_SUBSYSTEM                             4

static struct ld_option opts[] = {

    {   "--file-alignment",         LD_OPTION_FILE_ALIGNMENT,       LD_OPTION_HAS_ARG   },
    {   "--section-alignment",      LD_OPTION_SECTION_ALIGNMENT,    LD_OPTION_HAS_ARG   },
    {   "--subsystem",              LD_OPTION_SUBSYSTEM,            LD_OPTION_HAS_ARG   },
    
    
    {   0,                          0,                              0                   }

};

int pe_check_option (const char *cmd_arg, int argc, char **argv, int *optind, const char **optarg) {

    struct ld_option *popt;
    
    for (popt = opts; ; popt++) {
    
        const char *p1 = popt->name;
        const char *r1 = cmd_arg;
        
        if (!p1) {
            break;    
        }
        
        if (!strstart (p1, &r1)) {
            continue;
        }
        
        (*optarg) = r1;
        
        if (popt->flgs & LD_OPTION_HAS_ARG) {
        
            if (*r1 == '\0') {
            
                if ((*optind) >= argc) {
                
                    report_at (program_name, 0, REPORT_ERROR, "argument to '%s' is missing", cmd_arg);
                    exit (EXIT_FAILURE);
                
                }
                
                (*optarg) = argv[(*optind)++];
            
            }
        
        } else if (*r1 != '\0') {
            continue;
        }
        
        return popt->idx;
    
    }
    
    return -1;

}

void pe_use_option (const char *cmd_arg, int idx, const char *optarg) {

    switch (idx) {
    
        case LD_OPTION_IGNORED: {
        
            break;
        
        }
        
        case LD_OPTION_FILE_ALIGNMENT: {
        
            long conversion;
            char *temp;
            
            errno = 0;
            conversion = strtol (optarg, &temp, 0);
            
            if (!*optarg || isspace ((int) *optarg) || errno || *temp) {
            
                report_at (program_name, 0, REPORT_ERROR, "invalid file alignment number '%s'", optarg);
                exit (EXIT_FAILURE);
            
            }
            
            file_alignment = (unsigned long) conversion;
            
            if (file_alignment < 512 || file_alignment > 0x10000 || (file_alignment & (file_alignment - 1))) {
                report_at (program_name, 0, REPORT_WARNING, "file alignment should be a power of two between 512 and 64 KiB (0x10000) inclusive according to the specification");
            }
            
            break;
        
        }
        
        case LD_OPTION_SECTION_ALIGNMENT: {
        
            long conversion;
            char *temp;
            
            errno = 0;
            conversion = strtol (optarg, &temp, 0);
            
            if (!*optarg || isspace ((int) *optarg) || errno || *temp) {
            
                report_at (program_name, 0, REPORT_ERROR, "invalid section alignment number '%s'", optarg);
                exit (EXIT_FAILURE);
            
            }
            
            section_alignment = (unsigned long) conversion;
            
            if (section_alignment < file_alignment) {
                report_at (program_name, 0, REPORT_WARNING, "section alignment must be greater than or equal to file alignment according to the specification");
            }
            
            break;
        
        }
        
        case LD_OPTION_SUBSYSTEM: {
        
            long conversion;
            char *temp;
            
            errno = 0;
            conversion = strtol (optarg, &temp, 0);
            
            if (!*optarg || isspace ((int) *optarg) || errno || *temp) {
            
                report_at (program_name, 0, REPORT_ERROR, "invalid subsystem type '%s'", optarg);
                exit (EXIT_FAILURE);
            
            }
            
            subsystem = (unsigned short) conversion;
            break;
        
        }
        
        default: {
        
            report_at (program_name, 0, REPORT_ERROR, "unsupported option '%s'", cmd_arg);
            exit (EXIT_FAILURE);
        
        }
    
    }

}


#define     NUMBER_OF_DATA_DIRECTORIES                      16

unsigned char dos_stub[] = {

    0x0E,   0x1F,   0xBA,   0x0E,   0x00,   0xB4,   0x09,   0xCD,
    0x21,   0xB8,   0x01,   0x4C,   0xCD,   0x21,   0x54,   0x68,
    
    0x69,   0x73,   0x20,   0x70,   0x72,   0x6F,   0x67,   0x72,
    0x61,   0x6D,   0x20,   0x63,   0x61,   0x6E,   0x6E,   0x6F,
    
    0x74,   0x20,   0x62,   0x65,   0x20,   0x72,   0x75,   0x6E,
    0x20,   0x69,   0x6E,   0x20,   0x44,   0x4F,   0x53,   0x20,
    
    0x6D,   0x6F,   0x64,   0x65,   0x2E,   0x0D,   0x0D,   0x0A,
    0x24,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00

};

static int generate_reloc_section = 1;
static int can_be_relocated = 0;

static struct section_part *iat_first_part = 0, *iat_last_part = 0;

static int check_reloc_section_needed_section_part (struct section_part *part) {

    struct reloc_howto *reloc_howto;
    unsigned long i;
    
    for (i = 0; i < part->reloc_cnt; i++) {
    
        reloc_howto = part->reloc_arr[i].howto;
        
        if (reloc_howto == &reloc_howtos[RELOC_TYPE_64] || reloc_howto == &reloc_howtos[RELOC_TYPE_32]) {
            return 1;
        }
    
    }
    
    return 0;

}

static int check_reloc_section_needed (void) {

    struct section *section;
    struct section_part *part;
    struct subsection *subsection;
    
    for (section = all_sections; section; section = section->next) {
    
        for (part = section->first_part; part; part = part->next) {
        
            if (check_reloc_section_needed_section_part (part)) {
                return 1;
            }
        
        }
        
        for (subsection = section->all_subsections; subsection; subsection = subsection->next) {
        
            for (part = subsection->first_part; part; part = part->next) {
            
                if (check_reloc_section_needed_section_part (part)) {
                    return 1;
                }
            
            }
        
        }
    
    }
    
    return 0;

}

static int translate_characteristics_to_section_flags (unsigned long characteristics) {

    int flags = 0;
    
    if (!(characteristics & IMAGE_SCN_MEM_WRITE)) {
        flags |= SECTION_FLAG_READONLY;
    }
    
    if (characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) {
        flags |= SECTION_FLAG_CODE;
    }
    
    if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
        flags |= SECTION_FLAG_DATA;
    }
    
    if (characteristics & IMAGE_SCN_TYPE_NOLOAD) {
        flags |= SECTION_FLAG_NEVER_LOAD;
    }
    
    if (characteristics & IMAGE_SCN_LNK_INFO) {
        flags |= SECTION_FLAG_DEBUGGING;
    }
    
    if (characteristics & IMAGE_SCN_LNK_REMOVE) {
        flags |= SECTION_FLAG_EXCLUDE;
    }
    
    if (!(characteristics & IMAGE_SCN_MEM_READ)) {
        flags |= SECTION_FLAG_NOREAD;
    }
    
    if (characteristics & IMAGE_SCN_MEM_SHARED) {
        flags |= SECTION_FLAG_SHARED;
    }
    
    if (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
        flags |= SECTION_FLAG_ALLOC;
    }
    
    return flags;

}

static void exclude_symbols_free (void) {

    struct exclude_symbol *exclude_symbol;
    
    for (exclude_symbol = exclude_symbols; exclude_symbol; exclude_symbol = exclude_symbols) {
    
        exclude_symbols = exclude_symbol->next;
        
        free (exclude_symbol->name);
        free (exclude_symbol);
    
    }

}

#define     FLOOR_TO(a, b)              ((a) / (b) * (b))

static void generate_base_relocation_block (struct section *reloc_section, struct pe_base_relocation *ibr_hdr_p, unsigned long num_relocs, struct section *saved_section, struct section_part *saved_part, unsigned long saved_i) {

    struct section_part *reloc_part;
    struct reloc_entry *relocs;
    
    unsigned char *write_pos;
    unsigned long i;
    
    struct section *section;
    struct section_part *part;
    
    integer_to_array (ALIGN (sizeof (*ibr_hdr_p) + num_relocs * 2, 4), ibr_hdr_p->SizeOfBlock, 4);
    
    reloc_part = section_part_new (reloc_section, object_file_make (FAKE_LD_FILENAME, 0));
    reloc_part->content_size = array_to_integer (ibr_hdr_p->SizeOfBlock, 4);
    
    reloc_part->content = xmalloc (reloc_part->content_size);
    reloc_part->content[reloc_part->content_size - 2] = reloc_part->content[reloc_part->content_size - 1] = 0;
    
    memcpy (reloc_part->content, ibr_hdr_p, sizeof (*ibr_hdr_p));
    write_pos = reloc_part->content + sizeof (*ibr_hdr_p);
    
    for (section = saved_section; section; section = section->next) {
    
        for (part = ((section = saved_section) ? saved_part : section->first_part); part; part = part->next) {
        
            relocs = part->reloc_arr;
            
            for (i = ((part == saved_part) ? saved_i : 0); i < part->reloc_cnt; i++) {
            
                unsigned short base_relocation_type, rel_word;
                
                if (relocs[i].howto == &reloc_howtos[RELOC_TYPE_64]) {
                    base_relocation_type = IMAGE_REL_BASED_DIR64;
                } else if (relocs[i].howto == &reloc_howtos[RELOC_TYPE_32]) {
                    base_relocation_type = IMAGE_REL_BASED_HIGHLOW;
                } else {
                    continue;
                }
                
                rel_word  = (part->rva + relocs[i].offset - array_to_integer (ibr_hdr_p->RVAOfBlock, 4)) & 0xfff;
                rel_word |= base_relocation_type << 12;
                
                integer_to_array (rel_word, write_pos, 2);
                write_pos += 2;
                
                if (!--num_relocs) {
                    goto _finish;
                }
            
            }
        
        }
    
    }
    
    report_at (program_name, 0, REPORT_INTERNAL_ERROR, "num_relocs mismatch while generating .reloc section");
    
_finish:
    
    section_append_section_part (reloc_section, reloc_part);
    reloc_section->total_size += reloc_part->content_size;

}

static struct section *last_section = 0;

static unsigned long base_of_code = 0;
static unsigned long base_of_data = 0;

static unsigned long size_of_code = 0;
static unsigned long size_of_initialized_data = 0;
static unsigned long size_of_uninitialized_data = 0;

static unsigned long translate_section_flags_to_characteristics (int flags) {

    unsigned long characteristics = 0;
    
    if (!(flags & SECTION_FLAG_READONLY)) {
        characteristics |= IMAGE_SCN_MEM_WRITE;
    }
    
    if (flags & SECTION_FLAG_CODE) {
        characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
    }
    
    if (flags & SECTION_FLAG_DATA) {
        characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
    }
    
    if (flags & SECTION_FLAG_NEVER_LOAD) {
        characteristics |= IMAGE_SCN_TYPE_NOLOAD;
    }
    
    if (flags & SECTION_FLAG_DEBUGGING) {
        characteristics |= IMAGE_SCN_LNK_INFO;
    }
    
    if (flags & SECTION_FLAG_EXCLUDE) {
        characteristics |= IMAGE_SCN_LNK_REMOVE;
    }
    
    if (!(flags & SECTION_FLAG_NOREAD)) {
        characteristics |= IMAGE_SCN_MEM_READ;
    }
    
    if (flags & SECTION_FLAG_SHARED) {
        characteristics |= IMAGE_SCN_MEM_SHARED;
    }
    
    if ((flags & SECTION_FLAG_ALLOC) && !(flags & SECTION_FLAG_LOAD)) {
        characteristics |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
    }
    
    return characteristics;

}

static void write_sections (unsigned char *data) {

    unsigned char *pos = data + state->size_of_headers;
    unsigned long characteristics = 0;
    
    struct pe_section_table_entry *hdr;
    struct section *section;
    
    for (section = all_sections; section; section = section->next) {
    
        section->object_dependent_data = (hdr = xmalloc (sizeof (*hdr)));
        
        memset (hdr->Name, 0, sizeof (hdr->Name));
        memcpy (hdr->Name, section->name, (strlen (section->name) >= sizeof (hdr->Name)) ? sizeof (hdr->Name) : strlen (section->name));
        
        write741_to_byte_array (hdr->VirtualSize, section->total_size);
        write741_to_byte_array (hdr->VirtualAddress, section->rva);
        
        if (!section->is_bss) {
        
            write741_to_byte_array (hdr->SizeOfRawData, ALIGN (section->total_size, file_alignment));
            write741_to_byte_array (hdr->PointerToRawData, pos - data);
            
            section_write (section, pos);
            pos += ALIGN (section->total_size, file_alignment);
        
        }
        
        characteristics = translate_section_flags_to_characteristics (section->flags);
        write741_to_byte_array (hdr->Characteristics, characteristics);
        
        if (characteristics & IMAGE_SCN_CNT_CODE) {
        
            if (!base_of_code) {
                base_of_code = array_to_integer (hdr->VirtualAddress, 4);
            }
            
            size_of_code += array_to_integer (hdr->VirtualSize, 4);
        
        } else if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
        
            if (!base_of_data) {
                base_of_data = array_to_integer (hdr->VirtualAddress, 4);
            }
            
            size_of_initialized_data += array_to_integer (hdr->VirtualSize, 4);
        
        } else if (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            size_of_uninitialized_data += array_to_integer (hdr->VirtualSize, 4);
        }
        
        last_section = section;
    
    }

}

static unsigned long bytearray_read_4_bytes (unsigned char *src) {

    unsigned long value = 0;
    int i;
    
    for (i = 0; i < 4; i++) {
        value |= (unsigned long) src[i] << (CHAR_BIT * i);
    }
    
    return value;

}

static unsigned long calculate_checksum (unsigned char *base, unsigned long chksum_off, unsigned long size) {

    unsigned long checksum = 0, data, i;
    int carry;
    
    for (i = 0; i < size / 4; i++) {
    
        if (i == chksum_off / 4) {
            continue;
        }
        
        data  = bytearray_read_4_bytes (base + i * 4);
        
        carry = checksum > 0xFFFFFFFFLU - data;
        
        checksum += data;
        checksum += carry;
        
        checksum &= 0xFFFFFFFFLU;
    
    }
    
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    
    checksum += checksum >> 16;
    checksum &= 0xFFFF;
    checksum += size;
    
    return checksum & 0xFFFFFFFFLU;

}

void pe_after_link (void) {

    unsigned long num_relocs = 0, saved_i = 0, i;
    
    struct section *saved_section = 0, *section, *reloc_section;
    struct section_part *saved_part = 0, *part;
    
    struct pe_base_relocation ibr_hdr;
    struct reloc_entry *relocs;
    
    if (!generate_reloc_section) {
        return;
    }
    
    if (!(reloc_section = section_find (".reloc"))) {
        report_at (program_name, 0, REPORT_INTERNAL_ERROR, ".reloc section count not be found");
    }
    
    integer_to_array (0, ibr_hdr.RVAOfBlock, 4);
    
    for (section = all_sections; section; section = section->next) {
    
        for (part = section->first_part; part; part = part->next) {
        
            relocs = part->reloc_arr;
            
            for (i = 0; i < part->reloc_cnt; i++) {
            
                if (relocs[i].howto != &reloc_howtos[RELOC_TYPE_64] && relocs[i].howto != &reloc_howtos[RELOC_TYPE_32]) {
                    continue;
                }
                
                if (num_relocs && (part->rva + relocs[i].offset >= array_to_integer (ibr_hdr.RVAOfBlock, 4) + BASE_RELOCATION_PAGE_SIZE || part->rva + relocs[i].offset < array_to_integer (ibr_hdr.RVAOfBlock, 4))) {
                
                    generate_base_relocation_block (reloc_section, &ibr_hdr, num_relocs, saved_section, saved_part, saved_i);
                    num_relocs = 0;
                
                }
                
                if (num_relocs == 0) {
                
                    integer_to_array (FLOOR_TO (part->rva + relocs[i].offset, BASE_RELOCATION_PAGE_SIZE), ibr_hdr.RVAOfBlock, 4);
                    
                    saved_section = section;
                    saved_part = part;
                    
                    saved_i = i;
                
                }
                
                num_relocs++;
            
            }
        
        }
    
    }
    
    if (num_relocs) {
        generate_base_relocation_block (reloc_section, &ibr_hdr, num_relocs, saved_section, saved_part, saved_i);
    }

}

void pe_before_link (void) {

    struct section *section;
    struct section_part *part;
    struct subsection *subsection;
    
    if (state->base_address % 0x10000) {
        report_at (program_name, 0, REPORT_WARNING, "base address must be a multiple of 64 KiB (0x10000) according to the specification");
    }
    
    exclude_symbols_free ();
    
    if (!check_reloc_section_needed ()) {
    
        can_be_relocated = 1;
        generate_reloc_section = 0;
    
    }
    
    if (generate_reloc_section) {
    
        can_be_relocated = 1;
        
        section = section_find_or_make (".reloc");
        section->flags = translate_characteristics_to_section_flags (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    
    }
    
    for (section = all_sections; section; section = section->next) {
    
        if (section->section_alignment < section_alignment) {
            section->section_alignment = section_alignment;
        }
    
    }
    
    state->size_of_headers = sizeof (struct msdos_header) + sizeof (dos_stub) + sizeof (struct pe_header) + sizeof (struct pe_optional_header);
    
    state->size_of_headers += NUMBER_OF_DATA_DIRECTORIES * sizeof (struct pe_image_data_directory);
    state->size_of_headers += sizeof (struct pe_section_table_entry) * section_count ();
    
    state->size_of_headers = ALIGN (state->size_of_headers, file_alignment);
    
    if (!(section = section_find (".idata"))) {
        return;
    }
    
    if (!(subsection = subsection_find (section, "2"))) {
        return;
    }
    
    part = section_part_new (section, object_file_make (FAKE_LD_FILENAME, 0));
    
    part->content_size = sizeof (struct pe_import_directory_table);
    part->content = xmalloc (part->content_size);
    
    subsection_append_section_part (subsection, part);
    
    if (!(subsection = subsection_find (section, "5"))) {
        return;
    }
    
    iat_first_part = subsection->first_part;
    
    if (!iat_first_part) {
        return;
    }
    
    for (part = iat_first_part; ; part = part->next) {
    
        if (!part->next) {
            break;
        }
    
    }
    
    iat_last_part = part;

}

void pe_write (const char *filename) {

    FILE *fp;
    
    unsigned long data_size = 0, checksum_pos = 0;
    unsigned char *data, *pos;
    
    struct msdos_header *doshdr;
    struct pe_header *pehdr;
    struct pe_optional_header *opthdr;
    
    struct section *section;
    
    if (!(fp = fopen (filename, "wb"))) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to open '%s' for writing", filename);
        return;
    
    }
    
    for (section = all_sections; section; section = section->next) {
    
        if (!section->is_bss) {
            data_size += ALIGN (section->total_size, file_alignment);
        }
    
    }
    
    data_size += state->size_of_headers;
    
    data = xmalloc (data_size);
    write_sections (data);
    
    doshdr = (struct msdos_header *) data;
    pehdr = (struct pe_header *) ((char *) doshdr + sizeof (*doshdr) + sizeof (dos_stub));
    
    opthdr = (struct pe_optional_header *) ((char *) pehdr + sizeof (*pehdr));
    pos = (unsigned char *) opthdr + sizeof (*opthdr);
    
    doshdr->e_magic[0] = 'M';
    doshdr->e_magic[1] = 'Z';
    
    write721_to_byte_array (doshdr->e_cblp, 0x0090);
    write721_to_byte_array (doshdr->e_cp, 0x0003);
    
    write721_to_byte_array (doshdr->e_cparhdr, ALIGN (sizeof (*doshdr), 16) / 16);
    
    write721_to_byte_array (doshdr->e_maxalloc, 0xFFFF);
    write721_to_byte_array (doshdr->e_sp, 0x00B8);
    
    write721_to_byte_array (doshdr->e_lfarlc, sizeof (*doshdr));
    write741_to_byte_array (doshdr->e_lfanew, sizeof (*doshdr) + sizeof (dos_stub));
    
    memcpy ((char *) data + array_to_integer (doshdr->e_lfarlc, 2), dos_stub, sizeof (dos_stub));
    
    
    pehdr->Signature[0] = 'P';
    pehdr->Signature[1] = 'E';
    
    write721_to_byte_array (pehdr->Machine, IMAGE_FILE_MACHINE_I386);
    write721_to_byte_array (pehdr->NumberOfSections, section_count ());
    write741_to_byte_array (pehdr->TimeDateStamp, time (0));
    write721_to_byte_array (pehdr->SizeOfOptionalHeader, sizeof (*opthdr));
    
    {
    
        unsigned short characteristics = 0;
        
        characteristics |= IMAGE_FILE_EXECUTABLE_IMAGE;
        /*characteristics |= IMAGE_FILE_LINE_NUMS_STRIPPED;*/
        /*characteristics |= IMAGE_FILE_LOCAL_SYMS_STRIPPED;*/
        characteristics |= IMAGE_FILE_32BIT_MACHINE;
        characteristics |= IMAGE_FILE_DEBUG_STRIPPED;
        
        if (!can_be_relocated) {
            characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
        }
        
        write721_to_byte_array (pehdr->Characteristics, characteristics);
    
    }
    
    
    write721_to_byte_array (opthdr->Magic, IMAGE_FILE_MAGIC_I386);
    
    opthdr->MajorLinkerVersion = 0;
    opthdr->MinorLinkerVersion = 10;
    
    write741_to_byte_array (opthdr->SizeOfCode, ALIGN (size_of_code, file_alignment));
    write741_to_byte_array (opthdr->SizeOfInitializedData, ALIGN (size_of_initialized_data, file_alignment));
    write741_to_byte_array (opthdr->SizeOfUninitializedData, ALIGN (size_of_uninitialized_data, file_alignment));
    
    write741_to_byte_array (opthdr->AddressOfEntryPoint, state->entry_point);
    
    write741_to_byte_array (opthdr->BaseOfCode, base_of_code);
    write741_to_byte_array (opthdr->BaseOfData, base_of_data);
    
    write741_to_byte_array (opthdr->ImageBase, state->base_address);
    
    write741_to_byte_array (opthdr->SectionAlignment, section_alignment);
    write741_to_byte_array (opthdr->FileAlignment, file_alignment);
    
    write721_to_byte_array (opthdr->MajorOperatingSystemVersion, 4);
    write721_to_byte_array (opthdr->MajorImageVersion, 1);
    write721_to_byte_array (opthdr->MajorSubsystemVersion, 4);
    
    if (last_section) {
        write741_to_byte_array (opthdr->SizeOfImage, ALIGN (last_section->rva + last_section->total_size, section_alignment));
    } else {
        write741_to_byte_array (opthdr->SizeOfImage, state->size_of_headers);
    }
    
    write741_to_byte_array (opthdr->SizeOfHeaders, state->size_of_headers);
    write721_to_byte_array (opthdr->Subsystem, subsystem);
    
    {
    
        struct section *bss_section;
        
        if (!(bss_section = section_find (".bss"))) {
        
            write741_to_byte_array (opthdr->SizeOfStackReserved, section_alignment << 9);
            write741_to_byte_array (opthdr->SizeOfStackCommit, 0x1000);
            write741_to_byte_array (opthdr->SizeOfHeapReserved, section_alignment << 8);
            write741_to_byte_array (opthdr->SizeOfHeapCommit, 0x1000);
        
        } else {
        
            unsigned long ibss_addr = bss_section->rva;
            unsigned long ibss_size = bss_section->total_size;
            
            unsigned long stack_addr = ibss_addr + ibss_size;
            unsigned long stack_size = ALIGN (stack_addr, section_alignment);
            
            write741_to_byte_array (opthdr->SizeOfStackReserved, section_alignment << 9);
            write741_to_byte_array (opthdr->SizeOfStackCommit, ALIGN (stack_addr % 16 + stack_size, section_alignment));
            write741_to_byte_array (opthdr->SizeOfHeapReserved, section_alignment << 8);
            write741_to_byte_array (opthdr->SizeOfHeapCommit, ALIGN (stack_addr % 16 + stack_size, section_alignment));
        
        }
    
    }
    
    write741_to_byte_array (opthdr->NumberOfRvaAndSizes, NUMBER_OF_DATA_DIRECTORIES);
    
    
    for (section = all_sections; section; section = section->next) {
    
        struct pe_section_table_entry *hdr = section->object_dependent_data;
        
        memcpy (pos, hdr, sizeof (*hdr));
        pos += sizeof (*hdr);
        
        free (hdr);
    
    }
    
    
    checksum_pos = sizeof (*doshdr) + sizeof (dos_stub) + sizeof (*pehdr) + offsetof (struct pe_optional_header, Checksum);
    write741_to_byte_array (opthdr->Checksum, calculate_checksum (data, checksum_pos, data_size));
    
    if (fwrite (data, data_size, 1, fp) != 1) {
        report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", filename);
    }
    
    free (data);
    fclose (fp);

}

void pe_print_help (void) {

    fprintf (stderr, "i386pe:\n\n");
    
    fprintf (stderr, "    --file-alignment <size>           Set file alignment.\n");
    fprintf (stderr, "    --section-alignment <size>        Set section alignment.\n");
    fprintf (stderr, "    --subsystem <name>                Set required OS subsystem.\n");

}

unsigned long pe_get_first_section_rva (void) {
    return ALIGN (state->size_of_headers, section_alignment);
}

unsigned long pe_align_to_file_alignment (unsigned long value) {
    return ALIGN (value, file_alignment);
}
