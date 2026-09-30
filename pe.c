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

#include    "ar.h"
#include    "ld.h"
#include    "lib.h"
#include    "ll.h"
#include    "pe.h"
#include    "report.h"
#include    "section.h"
#include    "write7x.h"

static unsigned short subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
static int kill_at = 0;

static uint64_t section_alignment = DEFAULT_SECTION_ALIGNMENT;
static uint64_t file_alignment = DEFAULT_FILE_ALIGNMENT;

static const char **def_list = 0;
long nb_def_list = 0;

struct exclude_symbol {

    char *name;
    struct exclude_symbol *next;

};

static struct exclude_symbol *exclude_symbols = 0;

#define     LD_OPTION_IGNORED                               0
#define     LD_OPTION_DEF_LIST                              1
#define     LD_OPTION_FILE_ALIGNMENT                        2
#define     LD_OPTION_KILL_AT                               3
#define     LD_OPTION_OUT_IMPLIB                            4
#define     LD_OPTION_SECTION_ALIGNMENT                     5
#define     LD_OPTION_SHARED                                6
#define     LD_OPTION_STACK                                 7
#define     LD_OPTION_SUBSYSTEM                             8

static struct ld_option opts[] = {

    {   "--file-alignment",         LD_OPTION_TYPE_LONG,        LD_OPTION_FILE_ALIGNMENT,       LD_OPTION_HAS_ARG   },
    {   "--section-alignment",      LD_OPTION_TYPE_LONG,        LD_OPTION_SECTION_ALIGNMENT,    LD_OPTION_HAS_ARG   },
    
    {   "--def-list",               LD_OPTION_TYPE_LONG,        LD_OPTION_DEF_LIST,             LD_OPTION_HAS_ARG   },
    {   "--subsystem",              LD_OPTION_TYPE_LONG,        LD_OPTION_SUBSYSTEM,            LD_OPTION_HAS_ARG   },
    
    {   "--shared",                 LD_OPTION_TYPE_LONG,        LD_OPTION_SHARED,               LD_OPTION_NO_ARG    },
    {   "-Bshareable",              LD_OPTION_TYPE_LONG,        LD_OPTION_SHARED,               LD_OPTION_NO_ARG    },
    
    {   "--kill-at",                LD_OPTION_TYPE_LONG,        LD_OPTION_KILL_AT,              LD_OPTION_NO_ARG    },
    {   "--out-implib",             LD_OPTION_TYPE_LONG,        LD_OPTION_OUT_IMPLIB,           LD_OPTION_HAS_ARG   },
    
    {   0,                          0,                          0,                              0                   }

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
        
            if (popt->type == LD_OPTION_TYPE_LONG) {
            
                if (*r1 != '-') {
                    continue;
                }
                
                p1 = popt->name + 1;
                r1 = cmd_arg;
                
                if (!strstart (p1, &r1)) {
                    continue;
                }
            
            } else {
                continue;
            }
        
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
        
        case LD_OPTION_DEF_LIST: {
        
            const char *fn = optarg, *arg, *p;
            
            for (;;) {
            
                fn = skip_whitespace ((char *) fn);
                
                if ((p = strchr (fn, ','))) {
                
                    arg = p;
                    
                    while (isspace ((int) *arg)) {
                        arg--;
                    }
                    
                    dynarray_add (&def_list, &nb_def_list, xstrndup (fn, arg - fn));
                    fn = p + 1;
                    
                    continue;
                
                }
                
                dynarray_add (&def_list, &nb_def_list, xstrdup (fn));
                break;
            
            }
            
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
        
        case LD_OPTION_KILL_AT: {
        
            kill_at = 1;
            break;
        
        }
        
        case LD_OPTION_OUT_IMPLIB: {
        
            if (state->output_implib_filename) {
                free ((char *) state->output_implib_filename);
            }
            
            state->output_implib_filename = xstrdup (optarg);
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
        
        case LD_OPTION_SHARED: {
        
            state->create_shared_library = 1;
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
    
    0x6D,   0x6F,   0x64,   0x65,   0x2E,   0x0D,   0x0A,   0x24,
    0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00

};

struct name_list {

    char *name, *real_name;
    int info;
    
    struct name_list *next;

};

static struct name_list *export_name_list = 0;
static struct name_list **last_export_name_list_p = &export_name_list;

static void export_symbol_callback (struct symbol *symbol) {

    struct name_list *name_list;
    
    if (symbol_is_undefined (symbol)) {
        return;
    }
    
    name_list = xmalloc (sizeof (*name_list));
    
    if (state->leading_underscore && symbol->name[0] == '_') {
    
        name_list->name = xstrdup (symbol->name + 1);
        
        if (symbol->real_name) {
            name_list->real_name = xstrdup (symbol->real_name + 1);
        }
    
    } else {
    
        name_list->name = xstrdup (symbol->name);
        
        if (symbol->real_name) {
            name_list->real_name = xstrdup (symbol->real_name);
        }
    
    }
    
    name_list->info = (symbol->part->section->flags & SECTION_FLAG_CODE) ? 0 : 1;
    name_list->next = 0;
    
    *last_export_name_list_p = name_list;
    last_export_name_list_p = &name_list->next;

}

static void parse_def (const char *ifile) {

    char *line, *line_end, *real_line, *caret;
    unsigned long real_line_len;
    
    unsigned long new_line_number = 1, line_number = 1;
    unsigned long newlines;
    
    char *symbol_name, *real_symbol_name;
    int has_exports = 0;
    
    struct symbol *symbol;
    FILE *fp;
    
    void *load_line_internal_data = NULL;
    
    if (!(fp = fopen (ifile, "r"))) {
    
        report_at (program_name, 0, REPORT_FATAL_ERROR, "Failed to open '%s' for reading", ifile);
        return;
    
    }
    
    load_line_internal_data = load_line_create_internal_data (&new_line_number);
    
    while (!load_line (&line, &line_end, &real_line, &real_line_len, &newlines, fp, &load_line_internal_data)) {
    
        line_number = new_line_number;
        new_line_number += newlines + 1;
        
        caret = (line = skip_whitespace (line));
        
        if (line < line_end) {
        
            if (!isalnum ((int) *caret) && *caret != '_') {
            
                report_at (ifile, 0, REPORT_ERROR, "expected ident");
                continue;
            
            }
            
            while (isalnum ((int) *caret) || *caret == '_') {
                caret++;
            }
            
            if (*caret == '@') {
            
                caret++;
                
                while (isdigit ((int) *caret)) {
                    caret++;
                }
            
            }
           
            symbol_name = xstrndup (line, caret - line);
            line = skip_whitespace (caret);
            
            if (!has_exports) {
            
                if (strcmp (symbol_name, "EXPORTS")) {
                
                    report_at (ifile, 0, REPORT_ERROR, "invalid command");
                    continue;
                
                }
                
                has_exports = 1;
                
                free (symbol_name);
                continue;
            
            }
            
            if (*line == '=') {
            
                real_symbol_name = symbol_name;
                caret = (line = skip_whitespace (line + 1));
                
                if (!isalnum ((int) *caret) && *caret != '_') {
                
                    report_at (ifile, 0, REPORT_ERROR, "expected ident");
                    continue;
                
                }
                
                while (isalnum ((int) *caret) || *caret == '_') {
                    caret++;
                }
                
                if (*caret == '@') {
                
                    caret++;
                    
                    while (isdigit ((int) *caret)) {
                        caret++;
                    }
                
                }
                
                symbol_name = xstrndup (line, caret - line);
                line = skip_whitespace (caret);
                
                if ((symbol = symbol_find (symbol_name))) {
                
                    symbol->real_name = real_symbol_name;
                    export_symbol_callback (symbol);
                
                }
            
            } else if ((symbol = symbol_find (symbol_name))) {
                export_symbol_callback (symbol);
            }
            
            if (*line != '\0' && *line != '\n') {
                report_at (program_name, 0, REPORT_ERROR, "Stray '%c' on line %lu in %s", *line, line_number, ifile);
            }
        
        }
    
    }
    
    load_line_destroy_internal_data (load_line_internal_data);

}

void pe_interpret_dot_drectve_section (/*const char *filename, unsigned char *data, unsigned long data_size, */unsigned char *pos, unsigned long size) {

    char *temp_buf = xmalloc (size + 1), *p;
    
    memcpy (temp_buf, pos, size);
    temp_buf[size] = '\0';
    
    if (pos[0] == 0xEF && pos[1] == 0xBB && pos[2] == 0xBF) {
    
        report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "UTF-8 byte order marker not yet supported at the start of .drectve section");
        exit (EXIT_FAILURE);
    
    }
    
    p = temp_buf;
    
    while (*p) {
    
        while (*p == ' ') {
            p++;
        }
        
        if (strncmp (p, "-export:", 8) == 0 || strncmp (p, "/EXPORT:", 8) == 0) {
        
            struct name_list *name_list;
            char *q, saved_ch;
            
            char *comma;
            int data = 0;
            
            p += 8;
            
            if (!(q = strchr (p, ' '))) {
                q = p + strlen (p);
            }
            
            saved_ch = *q;
            *q = '\0';
            
            if ((comma = strchr (p, ','))) {
            
                if (strcmp (comma, ",data") == 0 || strcmp (comma, ",DATA") == 0) {
                    data = 1;
                } else {
                
                    report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "unsupported comma argument to option -export: '%s'", comma);
                    exit (EXIT_FAILURE);
                
                }
                
                *comma = '\0';
            
            }
            
            if (*p == '"') {
                p++;
            }
            
            if (p[strlen (p) - 1] == '"') {
                p[strlen (p) - 1] = '\0';
            }
            
            name_list = xmalloc (sizeof (*name_list));
            
            name_list->name = xstrdup (p);
            name_list->info = data;
            
            *last_export_name_list_p = name_list;
            last_export_name_list_p = &name_list->next;
            
            *q = saved_ch;
            p = q;
        
        } else {
        
            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "unsupported .drectve option: %s", p);
            exit (EXIT_FAILURE);
        
        }
    
    }
    
    free (temp_buf);

}

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
    
    integer_to_array (ALIGN (sizeof (*ibr_hdr_p) + num_relocs * 2, 4), ibr_hdr_p->SizeOfBlock, 4, 0);
    
    reloc_part = section_part_new (reloc_section, object_file_make (FAKE_LD_FILENAME, 0));
    reloc_part->content_size = array_to_integer (ibr_hdr_p->SizeOfBlock, 4, 0);
    
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
                
                if (part->rva + relocs[i].offset < array_to_integer (ibr_hdr_p->RVAOfBlock, 4, 0)) {
                    continue;
                }
                
                rel_word  = (part->rva + relocs[i].offset - array_to_integer (ibr_hdr_p->RVAOfBlock, 4, 0)) & 0xfff;
                rel_word |= base_relocation_type << 12;
                
                integer_to_array (rel_word, write_pos, 2, 0);
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

static uint64_t base_of_code = 0;
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
                base_of_code = array_to_integer (hdr->VirtualAddress, 4, 0);
            }
            
            size_of_code += array_to_integer (hdr->VirtualSize, 4, 0);
        
        } else if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
        
            if (!base_of_data) {
                base_of_data = array_to_integer (hdr->VirtualAddress, 4, 0);
            }
            
            size_of_initialized_data += array_to_integer (hdr->VirtualSize, 4, 0);
        
        } else if (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            size_of_uninitialized_data += array_to_integer (hdr->VirtualSize, 4, 0);
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

/*static unsigned long write_archive_member (unsigned char *pos, const char *name, unsigned long size, unsigned long lu_timestamp) {

    struct ar_header *member_hdr = (struct ar_header *) pos;
    memset (member_hdr, ' ', sizeof (*member_hdr));
    
    memcpy (member_hdr->name, name, strlen (name));
    member_hdr->mtime[sprintf (member_hdr->mtime, "%lu", lu_timestamp)] = ' ';
    
    member_hdr->owner[0] = '0';
    member_hdr->group[0] = '0';
    member_hdr->mode[0] = '0';
    
    member_hdr->size[sprintf (member_hdr->size, "%lu", size)] = ' ';
    memcpy (member_hdr->endsig, "`\n", 2);
    
    return sizeof (*member_hdr);

}*/

enum export_type {

    EXPORT_TYPE_CODE,
    EXPORT_TYPE_DATA,
    EXPORT_TYPE_CONST

};

struct export_name {

    char *name, *name_no_at;
    char *real_name, *real_name_no_at;
    
    enum export_type export_type;

};

struct symbol_info {

    char *name;
    
    unsigned long name_length;
    unsigned long offset_index;
    
    struct symbol_info *next;

};

struct symbol_info *create_symbol_list (struct export_name *export_name, unsigned long num_names) {

    char *predefined[3] = { "__IMPORT_DESCRIPTOR_", "__NULL_IMPORT_DESCRIPTOR", "_NULL_THUNK_DATA" };
    
    struct symbol_info *info_list = 0;
    struct symbol_info **last_info_list_p = &info_list;
    
    const char *module_name, *p;
    char *name;
    
    struct symbol_info *symbol_info;
    unsigned long i, j;
    
    module_name = state->output_filename;
    name = xstrdup (module_name);
    
    if ((p = strrchr (module_name, '/')) || (p = strrchr (module_name, '\\'))) {
    
        free (name);
        
        name = xstrndup (p + 1, (p - module_name) - 1);
        module_name = p + 1;
    
    }
    
    if ((p = strrchr (module_name, '.'))) {
    
        free (name);
        name = xstrndup (module_name, p - module_name);
    
    }
    
    for (i = 0, j = 0; i < 3; i++, j++) {
    
        symbol_info = xmalloc (sizeof (*symbol_info));
        
        if (i == 0) {
        
            symbol_info->name = xmalloc (strlen (predefined[i]) + strlen (name) + 1);
            symbol_info->name_length = sprintf (symbol_info->name, "%s%s", predefined[i], name);
        
        }
        
        if (i == 1) {
        
            symbol_info->name = xmalloc (strlen (predefined[i]) + 1);
            symbol_info->name_length = sprintf (symbol_info->name, "%s", predefined[i]);
        
        }
        
        if (i == 2) {
        
            symbol_info->name = xmalloc (1 + strlen (predefined[i]) + strlen (name) + 1);
            symbol_info->name_length = sprintf (symbol_info->name, "\x7F%s%s", name, predefined[i]);
        
        }
        
        symbol_info->offset_index = j;
        
        *last_info_list_p = symbol_info;
        last_info_list_p = &symbol_info->next;
    
    }
    
    free (name);
    
    for (i = 0, j = 0; i < num_names; i++, j++) {
    
        symbol_info = xmalloc (sizeof (*symbol_info));
        
        if (export_name[i].real_name) {
            symbol_info->name = xmalloc (7 + strlen (export_name[i].real_name) + 1);
        } else {
            symbol_info->name = xmalloc (7 + strlen (export_name[i].name) + 1);
        }
        
        if (state->leading_underscore) {
        
            if (export_name[i].real_name) {
                sprintf (symbol_info->name, "__imp__%s", export_name[i].real_name);
            } else {
                sprintf (symbol_info->name, "__imp__%s", export_name[i].name);
            }
        
        } else {
        
            if (export_name[i].real_name) {
                sprintf (symbol_info->name, "__imp_%s", export_name[i].real_name);
            } else {
                sprintf (symbol_info->name, "__imp_%s", export_name[i].name);
            }
        
        }
        
        symbol_info->name_length = strlen (symbol_info->name);
        symbol_info->offset_index = j;
        
        *last_info_list_p = symbol_info;
        last_info_list_p = &symbol_info->next;
    
    }
    
    return info_list;

}

static unsigned long swap_bytes (unsigned long value, int size) {

    unsigned long new_value = 0;
    int i;
    
    for (i = 0; i < size; i++) {
        new_value = (new_value << CHAR_BIT) | ((value >> (i * CHAR_BIT)));
    }
    
    return new_value;

}

static unsigned long write_data (FILE *outfile, void *data, unsigned long data_size) {

    if (fwrite (data, data_size, 1, outfile) != 1) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed whilst writing data to '%s'", state->output_implib_filename);
        return 0;
    
    }
    
    return data_size;

}

static unsigned long write_file_header (FILE *outfile, char *name, int b, unsigned long size, unsigned long lu_timestamp) {

    struct ar_header member_hdr;
    memset (&member_hdr, ' ', sizeof (member_hdr));
    
    if (!b) {
    
        memcpy (member_hdr.name, name, strlen (name));
        member_hdr.name[strlen(name)] = 0x2F;
    
    } else {
    
        member_hdr.name[0] = 0x2F;
        memcpy (member_hdr.name + 1, name, strlen (name));
    
    }
    
    member_hdr.mtime[sprintf (member_hdr.mtime, "%lu", lu_timestamp)] = ' ';
    
    member_hdr.owner[0] = '0';
    member_hdr.group[0] = '0';
    member_hdr.mode[0] = '0';
    
    member_hdr.size[sprintf (member_hdr.size, "%lu", size)] = ' ';
    memcpy (member_hdr.endsig, "`\n", 2);
    
    return write_data (outfile, &member_hdr, sizeof (member_hdr));

}

struct data_descriptor {

    unsigned char Architecture[2];
    unsigned char a[2];
    unsigned char Id[4];
    unsigned char Length[4];
    unsigned char b[4];
    unsigned char Flags[4];

};

struct section_descriptor_long {

    unsigned char SectionName[16];
    unsigned char Length[4];
    unsigned char Offset[4];
    unsigned char AOffset[4];
    unsigned char a[4];
    unsigned char ACount[4];
    unsigned char b[4];

};

struct section_descriptor_short {

    union {
    
        unsigned char SectionName[8];
        
        struct {
        
            unsigned char a[4];
            unsigned char Offset[4];
        
        } x;
    
    } z;
    
    unsigned char b[4];
    unsigned char c[4];
    unsigned char type[2];

};

unsigned char g_Data0[12] = {

    0x02,   0x00,   0x00,   0x00,   0x34,   0x00,
    0x09,   0x00,   0x00,   0x00,   0x00,   0x00

};

unsigned char g_Data1[23] = {

    0x27,   0x00,   0x13,   0x10,   0x07,   0x00,
    0x00,   0x00,   0x03,   0x00,   0x00,   0x00,
    0x00,   0x00,   0x00,   0x00,   0x0C,   0x00,
    0x00,   0x00,   0x0D,   0x52,   0x12

};

unsigned char g_Data2[20] = {

    0x00,   0x00,   0x00,   0x00,   0x00,
    0x00,   0x00,   0x00,   0x00,   0x00,
    0x00,   0x00,   0x00,   0x00,   0x00,
    0x00,   0x00,   0x00,   0x00,   0x00

};

struct data_entry {

    unsigned char a[4];
    unsigned char b[4];
    unsigned char c[2];

};

static void write_implib (struct export_name *export_names, unsigned long num_names, unsigned long ordinal_base) {

    struct symbol_info *info_list, *info;
    
    unsigned long *offsets, offset_count, symbol_count, length, i;
    unsigned long module_name_length;
    
    const char *p;
    char *header_name, *module_name;
    
    unsigned long offset = 0, offset2 = 0, offset3 = 0;
    int bHeaderName;
    
    unsigned long pad_length, pad[2];
    FILE *outfile;
    
    struct section_descriptor_short section_descriptor_short;
    struct section_descriptor_long section_descriptor_long;
    
    struct data_descriptor data_descriptor;
    struct data_entry data_entry;
    
    info_list = create_symbol_list (export_names, num_names);
    
    offset_count = 2 + 3 + num_names;
    offsets = xmalloc (offset_count * 8);
    
    module_name = xstrdup (state->output_filename);
    
    if ((p = strrchr (state->output_filename, '/')) || (p = strrchr (state->output_filename, '\\'))) {
    
        free (module_name);
        module_name = xstrndup (p + 1, (p - state->output_filename) - 1);
    
    }
    
    module_name_length = strlen (module_name);
    
    if (module_name_length + 1 > 16) {
    
        header_name = xstrdup ("0");
        bHeaderName = 1;
    
    } else {
    
        header_name = xstrdup (module_name);
        bHeaderName = 0;
    
    }
    
    if (!(outfile = fopen (state->output_implib_filename, "wb"))) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to open '%s' for writing", state->output_implib_filename);
        return;
    
    }
    
    offsets[0] = (offset += write_data (outfile, "!<arch>\n", 8));
    
    fseek (outfile, sizeof (struct ar_header), SEEK_CUR);
    offset2 = ftell (outfile);
    
    symbol_count = swap_bytes (3 + (num_names * 2), 4);
    offset2 += write_data (outfile, &symbol_count, 4);
    
    fseek (outfile, (3 + (num_names * 2)) * 4, SEEK_CUR);
    offset2 = ftell (outfile);
    
    for (info = info_list, i = 0; info; info = info->next, i++) {
    
        if (i >= 3) {
            offset2 += write_data (outfile, info->name + 6, (info->name_length - 6) + 1);
        }
        
        offset2 += write_data (outfile, info->name, info->name_length + 1);
    
    }
    
    fseek (outfile, offset, SEEK_SET);
    offset += write_file_header (outfile, "", 0, (offset2 - (offset + sizeof (struct ar_header))), 0);
    
    fseek (outfile, offset2, SEEK_SET);
    
    if ((offset2 & 1)) {
        offset2 += write_data (outfile, "\n", 1);
    }
    
    length = module_name_length + 1;
    
    if (length > 16) {
    
        offset2 += write_file_header (outfile, "/", 0, length, 0);
        offset2 += write_data (outfile, module_name, length);
        
        if ((length + 1) & 1) {
            offset2 += write_data (outfile, "\n", 1);
        }
    
    }
    
    offsets[1] = offset = offset2;
    
    fseek (outfile, sizeof (struct ar_header), SEEK_CUR);
    offset2 += sizeof (struct ar_header);
    
    length  = sizeof (struct data_descriptor) + (sizeof (struct section_descriptor_long) * 3);
    length += sizeof (g_Data0) + 1 + module_name_length + sizeof (g_Data1);
    length += sizeof (g_Data2) + (sizeof (struct data_entry) * 3);
    length += module_name_length + 1;
    
    integer_to_array (IMAGE_FILE_MACHINE_I386, data_descriptor.Architecture, 2, 0);
    integer_to_array (3, data_descriptor.a, 2, 0);
    integer_to_array (0, data_descriptor.Id, 4, 0);
    integer_to_array (length, data_descriptor.Length, 4, 0);
    integer_to_array (8, data_descriptor.b, 4, 0);
    integer_to_array (0x1000000, data_descriptor.Flags, 4, 0);
    
    offset2 += write_data (outfile, &data_descriptor, sizeof (data_descriptor));
    
    length = sizeof (g_Data0) + 1 + module_name_length + sizeof (g_Data1);
    offset3 = sizeof (struct data_descriptor) + (sizeof (struct section_descriptor_long) * 3);
    
    memset (&section_descriptor_long, 0, sizeof (section_descriptor_long));
    strcpy ((char *) section_descriptor_long.SectionName, ".debug$S");
    
    integer_to_array (length, section_descriptor_long.Length, 4, 0);
    integer_to_array (offset3, section_descriptor_long.Offset, 4, 0);
    integer_to_array (0x42100040, section_descriptor_long.b, 4, 0);
    
    offset2 += write_data (outfile, &section_descriptor_long, sizeof (section_descriptor_long));
    
    offset3 += length;
    length = sizeof (g_Data2);
    
    memset (&section_descriptor_long, 0, sizeof (section_descriptor_long));
    strcpy ((char *) section_descriptor_long.SectionName, ".idata$2");
    
    integer_to_array (length, section_descriptor_long.Length, 4, 0);
    integer_to_array (offset3, section_descriptor_long.Offset, 4, 0);
    integer_to_array (offset3 + length, section_descriptor_long.AOffset, 4, 0);
    integer_to_array (3, section_descriptor_long.ACount, 4, 0);
    integer_to_array (0xC0300040, section_descriptor_long.b, 4, 0);
    
    offset2 += write_data (outfile, &section_descriptor_long, sizeof (section_descriptor_long));
    
    offset3 += length + (sizeof (struct data_entry) * 3);
    length = module_name_length + 1;
    
    memset (&section_descriptor_long, 0, sizeof (section_descriptor_long));
    strcpy ((char *) section_descriptor_long.SectionName, ".idata$6");
    
    integer_to_array (length, section_descriptor_long.Length, 4, 0);
    integer_to_array (offset3, section_descriptor_long.Offset, 4, 0);
    integer_to_array (0xC0200040, section_descriptor_long.b, 4, 0);
    
    offset2 += write_data (outfile, &section_descriptor_long, sizeof (section_descriptor_long));
    offset2 += write_data (outfile, g_Data0, sizeof (g_Data0));
    offset2 += write_data (outfile, &module_name_length, 1);
    offset2 += write_data (outfile, module_name, module_name_length);
    offset2 += write_data (outfile, g_Data1, sizeof (g_Data1));
    offset2 += write_data (outfile, g_Data2, sizeof (g_Data2));
    
    integer_to_array (12, data_entry.a, 4, 0);
    integer_to_array (3, data_entry.b, 4, 0);
    integer_to_array (7, data_entry.c, 2, 0);
    
    offset2 += write_data (outfile, &data_entry, sizeof (data_entry));
    
    integer_to_array (0, data_entry.a, 4, 0);
    integer_to_array (4, data_entry.b, 4, 0);
    integer_to_array (7, data_entry.c, 2, 0);
    
    offset2 += write_data (outfile, &data_entry, sizeof (data_entry));
    
    integer_to_array (16, data_entry.a, 4, 0);
    integer_to_array (5, data_entry.b, 4, 0);
    integer_to_array (7, data_entry.c, 2, 0);
    
    offset2 += write_data (outfile, &data_entry, sizeof (data_entry));
    offset2 += write_data (outfile, module_name, module_name_length + 1);
    
    memset (&section_descriptor_short, 0, sizeof (section_descriptor_short));
    memcpy ((char *) section_descriptor_short.z.SectionName, "@comp.id", 8);
    
    integer_to_array (0xDD520D, section_descriptor_short.b, 4, 0);
    integer_to_array (0xFFFF, section_descriptor_short.c, 4, 0);
    integer_to_array (3, section_descriptor_short.type, 2, 0);
    
    offset2 += write_data (outfile, &section_descriptor_short, sizeof (section_descriptor_short));
    offset3 = 4;
    
    memset (&section_descriptor_short, 0, sizeof (section_descriptor_short));
    
    integer_to_array (offset3, section_descriptor_short.z.x.Offset, 4, 0);
    integer_to_array (2, section_descriptor_short.c, 4, 0);
    integer_to_array (2, section_descriptor_short.type, 2, 0);
    
    offset2 += write_data (outfile, &section_descriptor_short, sizeof (section_descriptor_short));
    
    memset (&section_descriptor_short, 0, sizeof (section_descriptor_short));
    memcpy ((char *) section_descriptor_short.z.SectionName, ".idata$2", 8);
    
    integer_to_array (0xC0000040, section_descriptor_short.b, 4, 0);
    integer_to_array (2, section_descriptor_short.c, 4, 0);
    integer_to_array (0x68, section_descriptor_short.type, 2, 0);
    
    offset2 += write_data (outfile, &section_descriptor_short, sizeof (section_descriptor_short));
    
    memset (&section_descriptor_short, 0, sizeof (section_descriptor_short));
    memcpy ((char *) section_descriptor_short.z.SectionName, ".idata$6", 8);
    
    integer_to_array (0, section_descriptor_short.b, 4, 0);
    integer_to_array (3, section_descriptor_short.c, 4, 0);
    integer_to_array (3, section_descriptor_short.type, 2, 0);
    
    offset2 += write_data (outfile, &section_descriptor_short, sizeof (section_descriptor_short));
    
    memset (&section_descriptor_short, 0, sizeof (section_descriptor_short));
    memcpy ((char *) section_descriptor_short.z.SectionName, ".idata$4", 8);
    
    integer_to_array (0xC0000040, section_descriptor_short.b, 4, 0);
    integer_to_array (0, section_descriptor_short.c, 4, 0);
    integer_to_array (0x68, section_descriptor_short.type, 2, 0);
    
    offset2 += write_data (outfile, &section_descriptor_short, sizeof (section_descriptor_short));
    
    memset (&section_descriptor_short, 0, sizeof (section_descriptor_short));
    memcpy ((char *) section_descriptor_short.z.SectionName, ".idata$5", 8);
    
    integer_to_array (0xC0000040, section_descriptor_short.b, 4, 0);
    integer_to_array (0, section_descriptor_short.c, 4, 0);
    integer_to_array (0x68, section_descriptor_short.type, 2, 0);
    
    offset2 += write_data (outfile, &section_descriptor_short, sizeof (section_descriptor_short));
    
    for (info = info_list, i = 0; i < 2; info = info->next, i++) {
    
        memset (&section_descriptor_short, 0, sizeof (section_descriptor_short));
        offset3 += info->name_length + 1;
        
        integer_to_array (offset3, section_descriptor_short.z.x.Offset, 4, 0);
        integer_to_array (0, section_descriptor_short.c, 4, 0);
        integer_to_array (2, section_descriptor_short.type, 2, 0);
        
        offset2 += write_data (outfile, &section_descriptor_short, sizeof (section_descriptor_short));
    
    }
    
    offset3 += info->name_length + 1;
    offset2 += write_data (outfile, &offset3, 4);
    
    for (info = info_list, i = 0; i < 3; info = info->next, i++) {
        offset2 += write_data (outfile, (char *) info->name, info->name_length + 1);
    }
    
    fseek (outfile, offset, SEEK_SET);
    
    offset3 = offset2 + write_file_header (outfile, header_name, bHeaderName, offset2 - (offset + sizeof (struct ar_header)), 0);
    fseek (outfile, offset2, SEEK_SET);
    
    if ((offset2 & 1)) {
        offset2 += write_data (outfile, "\n", 1);
    }
    
    offsets[2] = offset = offset2;
    
    fseek (outfile, sizeof (struct ar_header), SEEK_CUR);
    offset2 += sizeof (struct ar_header);
    
    length  = sizeof (struct data_descriptor) + (sizeof (struct section_descriptor_long) * 2);
    length += sizeof (g_Data0) + 1 + module_name_length + sizeof (g_Data1);
    length += sizeof (g_Data2);
    
    integer_to_array (IMAGE_FILE_MACHINE_I386, data_descriptor.Architecture, 2, 0);
    integer_to_array (2, data_descriptor.a, 2, 0);
    integer_to_array (0, data_descriptor.Id, 4, 0);
    integer_to_array (length, data_descriptor.Length, 4, 0);
    integer_to_array (2, data_descriptor.b, 4, 0);
    integer_to_array (0x1000000, data_descriptor.Flags, 4, 0);
    
    offset2 += write_data (outfile, &data_descriptor, sizeof (data_descriptor));
    
    length = sizeof (g_Data0) + 1 + module_name_length + sizeof (g_Data1);
    offset3 = sizeof (struct data_descriptor) + (sizeof (struct section_descriptor_long) * 2);
    
    memset (&section_descriptor_long, 0, sizeof (section_descriptor_long));
    strcpy ((char *) section_descriptor_long.SectionName, ".debug$S");
    
    integer_to_array (length, section_descriptor_long.Length, 4, 0);
    integer_to_array (offset3, section_descriptor_long.Offset, 4, 0);
    integer_to_array (0x42100040, section_descriptor_long.b, 4, 0);
    
    offset2 += write_data (outfile, &section_descriptor_long, sizeof (section_descriptor_long));
    
    offset3 += length;
    length = sizeof (g_Data2);
    
    memset (&section_descriptor_long, 0, sizeof (section_descriptor_long));
    strcpy ((char *) section_descriptor_long.SectionName, ".idata$3");
    
    integer_to_array (length, section_descriptor_long.Length, 4, 0);
    integer_to_array (offset3, section_descriptor_long.Offset, 4, 0);
    integer_to_array (0xC0300040, section_descriptor_long.b, 4, 0);
    
    offset2 += write_data (outfile, &section_descriptor_long, sizeof (section_descriptor_long));
    offset2 += write_data (outfile, g_Data0, sizeof (g_Data0));
    offset2 += write_data (outfile, &module_name_length, 1);
    offset2 += write_data (outfile, module_name, module_name_length);
    offset2 += write_data (outfile, g_Data1, sizeof (g_Data1));
    offset2 += write_data (outfile, g_Data2, sizeof (g_Data2));
    
    memset (&section_descriptor_short, 0, sizeof (section_descriptor_short));
    memcpy ((char *) section_descriptor_short.z.SectionName, "@comp.id", 8);
    
    integer_to_array (0xDD520D, section_descriptor_short.b, 4, 0);
    integer_to_array (0xFFFF, section_descriptor_short.c, 4, 0);
    integer_to_array (3, section_descriptor_short.type, 2, 0);
    
    offset2 += write_data (outfile, &section_descriptor_short, sizeof (section_descriptor_short));
    
    memset (&section_descriptor_short, 0, sizeof (section_descriptor_short));
    offset3 = 4;
    
    integer_to_array (offset3, section_descriptor_short.z.x.Offset, 4, 0);
    integer_to_array (2, section_descriptor_short.c, 4, 0);
    integer_to_array (2, section_descriptor_short.type, 2, 0);
    
    offset2 += write_data (outfile, &section_descriptor_short, sizeof (section_descriptor_short));
    length = offset3 + (info_list->next->name_length + 1);
    
    offset2 += write_data (outfile, &length, 4);
    offset2 += write_data (outfile, info_list->next->name, info_list->next->name_length + 1);
    
    fseek (outfile, offset, SEEK_SET);
    
    offset3 = offset2 + write_file_header (outfile, header_name, bHeaderName, offset2 - (offset + sizeof (struct ar_header)), 0);
    fseek (outfile, offset2, SEEK_SET);
    
    if ((offset2 & 1)) {
        offset2 += write_data (outfile, "\n", 1);
    }
    
    offsets[3] = offset = offset2;
    
    fseek (outfile, sizeof (struct ar_header), SEEK_CUR);
    offset2 += sizeof (struct ar_header);
    
    memset (pad, 0, sizeof (*pad));
    pad_length = 4;
    
    length  = sizeof (struct data_descriptor) + (sizeof (struct section_descriptor_long) * 3);
    length += sizeof (g_Data0) + 1 + module_name_length + sizeof (g_Data1);
    length += pad_length + pad_length;
    
    integer_to_array (IMAGE_FILE_MACHINE_I386, data_descriptor.Architecture, 2, 0);
    integer_to_array (3, data_descriptor.a, 2, 0);
    integer_to_array (0, data_descriptor.Id, 4, 0);
    integer_to_array (length, data_descriptor.Length, 4, 0);
    integer_to_array (2, data_descriptor.b, 4, 0);
    integer_to_array (0x1000000, data_descriptor.Flags, 4, 0);
    
    offset2 += write_data (outfile, &data_descriptor, sizeof (data_descriptor));
    
    length = sizeof (g_Data0) + 1 + module_name_length + sizeof (g_Data1);
    offset3 = sizeof (struct data_descriptor) + (sizeof (struct section_descriptor_long) * 3);
    
    memset (&section_descriptor_long, 0, sizeof (section_descriptor_long));
    strcpy ((char *) section_descriptor_long.SectionName, ".debug$S");
    
    integer_to_array (length, section_descriptor_long.Length, 4, 0);
    integer_to_array (offset3, section_descriptor_long.Offset, 4, 0);
    integer_to_array (0x42100040, section_descriptor_long.b, 4, 0);
    
    offset2 += write_data (outfile, &section_descriptor_long, sizeof (section_descriptor_long));
    
    offset3 += length;
    length = pad_length;
    
    memset (&section_descriptor_long, 0, sizeof (section_descriptor_long));
    strcpy ((char *) section_descriptor_long.SectionName, ".idata$5");
    
    integer_to_array (length, section_descriptor_long.Length, 4, 0);
    integer_to_array (offset3, section_descriptor_long.Offset, 4, 0);
    integer_to_array (0xC0300040, section_descriptor_long.b, 4, 0);
    
    offset2 += write_data (outfile, &section_descriptor_long, sizeof (section_descriptor_long));
    
    offset3 += length;
    length = pad_length;
    
    memset (&section_descriptor_long, 0, sizeof (section_descriptor_long));
    strcpy ((char *) section_descriptor_long.SectionName, ".idata$4");
    
    integer_to_array (length, section_descriptor_long.Length, 4, 0);
    integer_to_array (offset3, section_descriptor_long.Offset, 4, 0);
    integer_to_array (0xC0300040, section_descriptor_long.b, 4, 0);
    
    offset2 += write_data (outfile, &section_descriptor_long, sizeof (section_descriptor_long));
    offset2 += write_data (outfile, g_Data0, sizeof (g_Data0));
    offset2 += write_data (outfile, &module_name_length, 1);
    offset2 += write_data (outfile, module_name, module_name_length);
    offset2 += write_data (outfile, g_Data1, sizeof (g_Data1));
    
    offset2 += write_data (outfile, pad, pad_length);
    offset2 += write_data (outfile, pad, pad_length);
    
    memset (&section_descriptor_short, 0, sizeof (section_descriptor_short));
    memcpy ((char *) section_descriptor_short.z.SectionName, "@comp.id", 8);
    
    integer_to_array (0xDD520D, section_descriptor_short.b, 4, 0);
    integer_to_array (0xFFFF, section_descriptor_short.c, 4, 0);
    integer_to_array (3, section_descriptor_short.type, 2, 0);
    
    offset2 += write_data (outfile, &section_descriptor_short, sizeof (section_descriptor_short));
    
    memset (&section_descriptor_short, 0, sizeof (section_descriptor_short));
    offset3 = 4;
    
    integer_to_array (offset3, section_descriptor_short.z.x.Offset, 4, 0);
    integer_to_array (2, section_descriptor_short.c, 4, 0);
    integer_to_array (2, section_descriptor_short.type, 2, 0);
    
    offset2 += write_data (outfile, &section_descriptor_short, sizeof (section_descriptor_short));
    length = offset3 + (info_list->next->next->name_length + 1);
    
    offset2 += write_data (outfile, &length, 4);
    offset2 += write_data (outfile, info_list->next->next->name, info_list->next->next->name_length + 1);
    
    fseek (outfile, offset, SEEK_SET);
    
    offset3 = offset2 + write_file_header (outfile, header_name, bHeaderName, offset2 - (offset + sizeof (struct ar_header)), 0);
    fseek (outfile, offset2, SEEK_SET);
    
    if ((offset2 & 1)) {
        offset2 += write_data (outfile, "\n", 1);
    }
    
    for (i = 0; i < num_names; i++) {
    
        struct pe_import_library_header import_hdr;
        
        unsigned short type = 0;
        char *name;
        
        offsets[4 + i] = offset2;
        
        if (state->leading_underscore) {
        
            if (export_names[i].real_name) {
                offset2 += write_file_header (outfile, header_name, bHeaderName, sizeof (import_hdr) + 1 + strlen (export_names[i].real_name) + 1 + module_name_length + 1, 0);
            } else {
                offset2 += write_file_header (outfile, header_name, bHeaderName, sizeof (import_hdr) + 1 + strlen (export_names[i].name) + 1 + module_name_length + 1, 0);
            }
        
        } else {
        
            if (export_names[i].real_name) {
                offset2 += write_file_header (outfile, header_name, bHeaderName, sizeof (import_hdr) + strlen (export_names[i].real_name) + 1 + module_name_length + 1, 0);
            } else {
                offset2 += write_file_header (outfile, header_name, bHeaderName, sizeof (import_hdr) + strlen (export_names[i].name) + 1 + module_name_length + 1, 0);
            }
        
        }
        
        memset (&import_hdr, 0, sizeof (import_hdr));
        
        integer_to_array (IMAGE_FILE_MACHINE_UNKNOWN, import_hdr.Magic1, 2, 0);
        integer_to_array (0xFFFF, import_hdr.Magic2, 2, 0);
        
        if (state->format == LD_FORMAT_AMD64_PE) {
            integer_to_array (IMAGE_FILE_MACHINE_AMD64, import_hdr.Machine, 2, 0);
        } else {
            integer_to_array (IMAGE_FILE_MACHINE_I386, import_hdr.Machine, 2, 0);
        }
        
        if (state->leading_underscore) {
        
            if (export_names[i].real_name) {
                integer_to_array (1 + strlen (export_names[i].real_name) + 1 + module_name_length + 1, import_hdr.SizeOfData, 4, 0);
            } else {
                integer_to_array (1 + strlen (export_names[i].name) + 1 + module_name_length + 1, import_hdr.SizeOfData, 4, 0);
            }
        
        } else {
        
            if (export_names[i].real_name) {
                integer_to_array (strlen (export_names[i].real_name) + 1 + module_name_length + 1, import_hdr.SizeOfData, 4, 0);
            } else {
                integer_to_array (strlen (export_names[i].name) + 1 + module_name_length + 1, import_hdr.SizeOfData, 4, 0);
            }
        
        }
        
        integer_to_array (ordinal_base + i, import_hdr.OrdinalHint, 2, 0);
        
        switch (export_names[i].export_type) {
        
            case EXPORT_TYPE_CODE:
            
                type = IMPORT_CODE;
                break;
            
            case EXPORT_TYPE_DATA:
            
                type = IMPORT_DATA;
                break;
            
            case EXPORT_TYPE_CONST:
            
                type = IMPORT_CONST;
                break;
        
        }
        
        if (kill_at) {
            type |= IMPORT_NAME_UNDECORATE << 2;
        } else if (state->leading_underscore) {
            type |= IMPORT_NAME_NOPREFIX << 2;
        } else {
            type |= IMPORT_NAME << 2;
        }
        
        integer_to_array (type, import_hdr.Type, 2, 0);
        offset2 += write_data (outfile, &import_hdr, sizeof (import_hdr));
        
        if (state->leading_underscore) {
        
            if (export_names[i].real_name) {
            
                name = xmalloc (1 + strlen (export_names[i].real_name) + 1);
                sprintf (name, "_%s", export_names[i].real_name);
            
            } else {
            
                name = xmalloc (1 + strlen (export_names[i].name) + 1);
                sprintf (name, "_%s", export_names[i].name);
            
            }
        
        } else {
        
            if (export_names[i].real_name) {
            
                name = xmalloc (strlen (export_names[i].real_name) + 1);
                sprintf (name, "%s", export_names[i].real_name);
            
            } else {
            
                name = xmalloc (strlen (export_names[i].name) + 1);
                sprintf (name, "%s", export_names[i].name);
            
            }
        
        }
        
        offset2 += write_data (outfile, name, strlen (name) + 1);
        offset2 += write_data (outfile, module_name, module_name_length + 1);
        
        free (name);
        
        if ((offset2 & 1)) {
            offset2 += write_data (outfile, "\n", 1);
        }
    
    }
    
    offset = offset2;
    
    fseek (outfile, offsets[0] + sizeof (struct ar_header) + 4, SEEK_SET);
    offset2 = ftell (outfile);
    
    for (info = info_list, i = 0; info; info = info->next, i++) {
    
        offset3 = offsets[1 + i];
        offset3 = swap_bytes (offset3, 4);
        
        if (i >= 3) {
            offset2 += write_data (outfile, &offset3, 4);
        }
        
        offset2 += write_data (outfile, &offset3, 4);
    
    }
    
    fclose (outfile);

}

static int export_name_compar (const void *a, const void *b) {

    struct export_name *first = (struct export_name *) a;
    struct export_name *second = (struct export_name *) b;
    
    if (first->real_name) {
    
        if (second->real_name) {
            return strcmp (first->real_name, second->real_name);
        }
        
        return strcmp (first->real_name, second->name);
    
    }
    
    if (second->real_name) {
        return strcmp (first->name, second->real_name);
    }
    
    return strcmp (first->name, second->name);

}

static char *unat_name (const char *orig_name) {

    const char *at_p;
    return ((at_p = strchr (orig_name, '@')) ? xstrndup (orig_name, at_p - orig_name) : xstrdup (orig_name));

}

static void generate_edata (void) {

    struct object_file *of;
    struct symbol *symbol;
    
    struct section *section;
    struct section_part *part;
    
    struct name_list *name_list, *next_name_list;
    struct export_name *export_names;
    
    struct pe_export_directory *ied;
    struct reloc_entry *relocs;
    
    unsigned long ordinal_base = 1, i, num_names, name_table_size, name_table_offset;
    unsigned long name_len;
    
    char *name;
    
    for (name_list = export_name_list, num_names = 0, name_table_size = 0; name_list; name_list = name_list->next) {
        num_names++;
    }
    
    export_names = xmalloc (sizeof (*export_names) * num_names);
    
    for (name_list = export_name_list, i = 0; name_list; name_list = next_name_list, i++) {
    
        next_name_list = name_list->next;
        export_names[i].name = name_list->name;
        
        if (name_list->real_name) {
            export_names[i].real_name = name_list->real_name;
        }
        
        if (kill_at) {
        
            export_names[i].name_no_at = unat_name (export_names[i].name);
            name_len = strlen (export_names[i].name_no_at) + 1;
            
            if (name_list->real_name) {
            
                export_names[i].real_name_no_at = unat_name (export_names[i].real_name);
                name_len = strlen (export_names[i].real_name_no_at) + 1;
            
            }
            
            name_table_size += name_len;
        
        } else {
        
            export_names[i].name_no_at = 0;
            name_len = strlen (export_names[i].name) + 1;
            
            if (name_list->real_name) {
            
                export_names[i].real_name_no_at = 0;
                name_len = strlen (export_names[i].real_name) + 1;
            
            }
            
            name_table_size += name_len;
        
        }
        
        export_names[i].export_type = name_list->info ? EXPORT_TYPE_DATA : EXPORT_TYPE_CODE;
        free (name_list);
    
    }
    
    qsort (export_names, num_names, sizeof (*export_names), &export_name_compar);
    
    if (state->output_implib_filename) {
        write_implib (export_names, num_names, ordinal_base);
    }
    
    name_table_size += strlen (state->output_filename) + 1;
    
    section = section_find_or_make (".edata");
    section->flags = translate_characteristics_to_section_flags (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    
    of = object_file_make (FAKE_LD_FILENAME, num_names + 1);
    
    part = section_part_new (section, of);
    section_append_section_part (section, part);
    
    part->content_size = (sizeof (*ied) + (num_names * (4 + 4 + 2)) + name_table_size);
    part->content = xmalloc (part->content_size);
    
    part->reloc_cnt = 4 + num_names * 2;
    part->reloc_arr = xmalloc (part->reloc_cnt * sizeof (*part->reloc_arr));
    
    relocs = part->reloc_arr;
    
    of->symbol_arr[0].name = xstrdup (section->name);
    of->symbol_arr[0].value = 0;
    of->symbol_arr[0].part = part;
    of->symbol_arr[0].section_number = 1;
    
    name_table_offset = sizeof (*ied) + (num_names * (4 + 4 + 2));
    
    ied = (struct pe_export_directory *) part->content;
    memset (ied, 0, sizeof (*ied));
    
    integer_to_array (name_table_offset, ied->NameRVA, 4, 0);
    integer_to_array (ordinal_base, ied->OrdinalBase, 4, 0);
    integer_to_array (num_names, ied->AddressTableEntries, 4, 0);
    integer_to_array (num_names, ied->NumberOfNamePointers, 4, 0);
    integer_to_array (sizeof (*ied), ied->ExportAddressTableRVA, 4, 0);
    
    integer_to_array (array_to_integer (ied->ExportAddressTableRVA, 4, 0) + num_names * 4, ied->NamePointerRVA, 4, 0);
    integer_to_array (array_to_integer (ied->NamePointerRVA, 4, 0) + num_names * 4, ied->OrdinalTableRVA, 4, 0);
    
    for (i = 0; i < 4; i++) {
    
        relocs[i].symbol = &of->symbol_arr[0];
        relocs[i].howto = &reloc_howtos[RELOC_TYPE_32_NO_BASE];
    
    }
    
    relocs[0].offset = offsetof (struct pe_export_directory, NameRVA);
    relocs[1].offset = offsetof (struct pe_export_directory, ExportAddressTableRVA);
    relocs[2].offset = offsetof (struct pe_export_directory, NamePointerRVA);
    relocs[3].offset = offsetof (struct pe_export_directory, OrdinalTableRVA);
    
    relocs += 4;
    
    strcpy ((char *) part->content + name_table_offset, state->output_filename);
    name_table_offset += strlen (state->output_filename) + 1;
    
    symbol = of->symbol_arr + 1;
    
    for (i = 0; i < num_names; i++) {
    
        if (state->leading_underscore) {
        
            symbol->name = xmalloc (1 + strlen (export_names[i].name) + 1);
            sprintf (symbol->name, "_%s", export_names[i].name);
            
            if (export_names[i].real_name) {
            
                symbol->real_name = xmalloc (1 + strlen (export_names[i].real_name) + 1);
                sprintf (symbol->real_name, "_%s", export_names[i].real_name);
            
            }
        
        } else {
        
            symbol->name = xmalloc (strlen (export_names[i].name) + 1);
            sprintf (symbol->name, "%s", export_names[i].name);
            
            if (export_names[i].real_name) {
            
                symbol->name = xmalloc (strlen (export_names[i].real_name) + 1);
                sprintf (symbol->real_name, "%s", export_names[i].real_name);
            
            }
        
        }
        
        symbol->value = 0;
        symbol->part = 0;
        symbol->section_number = 0;
        
        symbol_record_external_symbol (symbol);
        
        relocs[0].offset = array_to_integer (ied->ExportAddressTableRVA, 4, 0) + 4 * i;
        relocs[0].symbol = symbol;
        relocs[0].howto = &reloc_howtos[RELOC_TYPE_32_NO_BASE];
        
        symbol++;
        relocs++;
        
        relocs[0].offset = array_to_integer (ied->NamePointerRVA, 4, 0) + 4 * i;
        relocs[0].symbol = &of->symbol_arr[0];
        relocs[0].howto = &reloc_howtos[RELOC_TYPE_32_NO_BASE];
        
        integer_to_array (name_table_offset, part->content + relocs[0].offset, 4, 0);
        relocs++;
        
        integer_to_array (i, part->content + array_to_integer (ied->OrdinalTableRVA, 4, 0) + 2 * i, 2, 0);
        
        if (kill_at) {
            name = export_names[i].real_name_no_at ? export_names[i].real_name_no_at : export_names[i].name_no_at;
        } else {
            name = export_names[i].real_name ? export_names[i].real_name : export_names[i].name;
        }
        
        strcpy ((char *) part->content + name_table_offset, name);
        name_table_offset += strlen (name) + 1;
    
    }
    
    for (i = 0; i < num_names; i++) {
    
        if (export_names[i].name) {
            free (export_names[i].name);
        }
        
        if (export_names[i].name_no_at) {
            free (export_names[i].name_no_at);
        }
        
        if (export_names[i].real_name) {
            free (export_names[i].real_name);
        }
        
        if (export_names[i].real_name_no_at) {
            free (export_names[i].real_name_no_at);
        }
    
    }
    
    free (export_names);

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
        report_at (program_name, 0, REPORT_INTERNAL_ERROR, ".reloc section could not be found");
    }
    
    integer_to_array (0, ibr_hdr.RVAOfBlock, 4, 0);
    
    for (section = all_sections; section; section = section->next) {
    
        for (part = section->first_part; part; part = part->next) {
        
            relocs = part->reloc_arr;
            
            for (i = 0; i < part->reloc_cnt; i++) {
            
                if (relocs[i].howto != &reloc_howtos[RELOC_TYPE_64] && relocs[i].howto != &reloc_howtos[RELOC_TYPE_32]) {
                    continue;
                }
                
                if (num_relocs && (part->rva + relocs[i].offset >= array_to_integer (ibr_hdr.RVAOfBlock, 4, 0) + BASE_RELOCATION_PAGE_SIZE || part->rva + relocs[i].offset < array_to_integer (ibr_hdr.RVAOfBlock, 4, 0))) {
                
                    generate_base_relocation_block (reloc_section, &ibr_hdr, num_relocs, saved_section, saved_part, saved_i);
                    num_relocs = 0;
                
                }
                
                if (num_relocs == 0) {
                
                    integer_to_array (FLOOR_TO (part->rva + relocs[i].offset, BASE_RELOCATION_PAGE_SIZE), ibr_hdr.RVAOfBlock, 4, 0);
                    
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
    
    if (nb_def_list > 0) {
    
        long i;
        
        for (i = 0; i < nb_def_list; i++) {
            parse_def (def_list[i]);
        }
    
    }
    
    exclude_symbols_free ();
    
    if (export_name_list) {
        generate_edata ();
    } else if (state->output_implib_filename) {
        write_implib (0, 0, 0);
    }
    
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
    
    state->size_of_headers = sizeof (struct msdos_header) + sizeof (dos_stub) + sizeof (struct pe_header);
    
    if (state->format == LD_FORMAT_AMD64_PE) {
        state->size_of_headers += sizeof (struct pe_optional_header_plus);
    } else {
        state->size_of_headers += sizeof (struct pe_optional_header);
    }
    
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
    
    part->content = xmalloc (part->content_size = sizeof (struct pe_import_directory_table));
    subsection_append_section_part (subsection, part);
    
    if (!(subsection = subsection_find (section, "5"))) {
        return;
    }
    
    if (!(iat_first_part = subsection->first_part)) {
        return;
    }
    
    for (part = iat_first_part; part->next; part = part->next) {
        ;
    }
    
    iat_last_part = part;

}

void pe32_write (const char *filename) {

    FILE *fp;
    
    unsigned long data_size = 0, checksum_pos = 0;
    unsigned char *data, *pos;
    
    struct msdos_header *doshdr;
    struct pe_header *pehdr;
    struct pe_optional_header *opthdr;
    
    struct section *section;
    unsigned long size_of_optional_header;
    
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
    
    memcpy ((char *) data + array_to_integer (doshdr->e_lfarlc, 2, 0), dos_stub, sizeof (dos_stub));
    
    
    pehdr->Signature[0] = 'P';
    pehdr->Signature[1] = 'E';
    
    write721_to_byte_array (pehdr->Machine, IMAGE_FILE_MACHINE_I386);
    write721_to_byte_array (pehdr->NumberOfSections, section_count ());
    write741_to_byte_array (pehdr->TimeDateStamp, time (0));
    
    size_of_optional_header = sizeof (*opthdr);
    size_of_optional_header += NUMBER_OF_DATA_DIRECTORIES * sizeof (struct pe_image_data_directory);
    write721_to_byte_array (pehdr->SizeOfOptionalHeader, size_of_optional_header);
    
    {
    
        unsigned short characteristics = 0;
        
        characteristics |= IMAGE_FILE_EXECUTABLE_IMAGE;
        characteristics |= IMAGE_FILE_32BIT_MACHINE;
        characteristics |= IMAGE_FILE_DEBUG_STRIPPED;
        
        if (state->create_shared_library) {
            characteristics |= IMAGE_FILE_DLL;
        }
        
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
        write741_to_byte_array (opthdr->SizeOfImage, ALIGN (state->size_of_headers, section_alignment));
    }
    
    write741_to_byte_array (opthdr->SizeOfHeaders, state->size_of_headers);
    write721_to_byte_array (opthdr->Subsystem, subsystem);
    
    {
    
        unsigned short characteristics = 0;
        
        if (can_be_relocated) {
            characteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        }
        
        write721_to_byte_array (opthdr->DllCharacteristics, characteristics);
    
    }
    
    {
    
        unsigned long stack_reserve = section_alignment << 9;
        unsigned long stack_commit = 0x1000;
        
        unsigned long heap_reserve = section_alignment << 8;
        unsigned long heap_commit = 0x1000;
        
        struct section *bss_section;
        
        if ((bss_section = section_find (".bss"))) {
        
            unsigned long image_data_end = ALIGN (bss_section->rva + bss_section->total_size, section_alignment);
                    
            if (image_data_end > stack_commit) {
                stack_commit = image_data_end;
            }
            
            if (image_data_end > heap_commit) {
                heap_commit = image_data_end;
            }
            
            if (stack_commit > stack_reserve) {
                stack_reserve = stack_commit;
            }
            
            if (heap_commit > heap_reserve) {
                heap_reserve = heap_commit;
            }
        
        }
        
        write741_to_byte_array (opthdr->SizeOfStackReserved, stack_reserve);
        write741_to_byte_array (opthdr->SizeOfStackCommit, stack_commit);
        write741_to_byte_array (opthdr->SizeOfHeapReserved, heap_reserve);
        write741_to_byte_array (opthdr->SizeOfHeapCommit, heap_commit);
    
    }
    
    write741_to_byte_array (opthdr->NumberOfRvaAndSizes, NUMBER_OF_DATA_DIRECTORIES);
    
    
    {
    
        struct pe_image_data_directory *idd;
        int i;
        
        for (i = 0; i < NUMBER_OF_DATA_DIRECTORIES; i++) {
        
            idd = (struct pe_image_data_directory *) pos;
            
            switch (i) {
            
                case 0:
                
                    /* EXPORT Table. */
                    if ((section = section_find (".edata"))) {
                    
                        write741_to_byte_array (idd->VirtualAddress, section->rva);
                        write741_to_byte_array (idd->Size, section->total_size);
                    
                    }
                    
                    break;
                
                case 1:
                
                    /* IMPORT Table. */
                    if ((section = section_find (".idata"))) {
                    
                        write741_to_byte_array (idd->VirtualAddress, section->rva);
                        write741_to_byte_array (idd->Size, section->total_size);
                    
                    }
                    
                    break;
                
                case 5:
                
                    /* BASE RELOCATION Table. */
                    if ((section = section_find (".reloc"))) {
                    
                        write741_to_byte_array (idd->VirtualAddress, section->rva);
                        write741_to_byte_array (idd->Size, section->total_size);
                    
                    }
                    
                    break;
                
                case 12:
                
                    /* IMPORT Address Table. */
                    if ((section = section_find (".idata")) && iat_first_part) {
                    
                        write741_to_byte_array (idd->VirtualAddress, iat_first_part->rva);
                        write741_to_byte_array (idd->Size, iat_last_part->rva + iat_last_part->content_size - iat_first_part->rva);
                    
                    }
                    
                    break;
            
            }
            
            pos += sizeof (*idd);
        
        }
    
    }
    
    
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

void pe64_write (const char *filename) {

    FILE *fp;
    
    unsigned long data_size = 0, checksum_pos = 0;
    unsigned char *data, *pos;
    
    struct msdos_header *doshdr;
    struct pe_header *pehdr;
    struct pe_optional_header_plus *opthdr;
    
    struct section *section;
    unsigned long size_of_optional_header;
    
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
    opthdr = (struct pe_optional_header_plus *) ((char *) pehdr + sizeof (*pehdr));
    
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
    
    memcpy ((char *) data + array_to_integer (doshdr->e_lfarlc, 2, 0), dos_stub, sizeof (dos_stub));
    
    
    pehdr->Signature[0] = 'P';
    pehdr->Signature[1] = 'E';
    
    write721_to_byte_array (pehdr->Machine, IMAGE_FILE_MACHINE_AMD64);
    write721_to_byte_array (pehdr->NumberOfSections, section_count ());
    write741_to_byte_array (pehdr->TimeDateStamp, time (0));
    
    size_of_optional_header = sizeof (*opthdr);
    size_of_optional_header += NUMBER_OF_DATA_DIRECTORIES * sizeof (struct pe_image_data_directory);
    write721_to_byte_array (pehdr->SizeOfOptionalHeader, size_of_optional_header);
    
    {
    
        unsigned short characteristics = 0;
        
        characteristics |= IMAGE_FILE_EXECUTABLE_IMAGE;
        /*characteristics |= IMAGE_FILE_LINE_NUMS_STRIPPED;*/
        /*characteristics |= IMAGE_FILE_LOCAL_SYMS_STRIPPED;*/
        characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
        characteristics |= IMAGE_FILE_DEBUG_STRIPPED;
        
        if (state->create_shared_library) {
            characteristics |= IMAGE_FILE_DLL;
        }
        
        if (!can_be_relocated) {
            characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
        }
        
        write721_to_byte_array (pehdr->Characteristics, characteristics);
    
    }
    
    
    write721_to_byte_array (opthdr->Magic, IMAGE_FILE_MAGIC_AMD64);
    
    opthdr->MajorLinkerVersion = 0;
    opthdr->MinorLinkerVersion = 10;
    
    write741_to_byte_array (opthdr->SizeOfCode, ALIGN (size_of_code, file_alignment));
    write741_to_byte_array (opthdr->SizeOfInitializedData, ALIGN (size_of_initialized_data, file_alignment));
    write741_to_byte_array (opthdr->SizeOfUninitializedData, ALIGN (size_of_uninitialized_data, file_alignment));
    
    write741_to_byte_array (opthdr->AddressOfEntryPoint, state->entry_point);
    
    write741_to_byte_array (opthdr->BaseOfCode, base_of_code);
    integer_to_array (state->base_address, opthdr->ImageBase, 8, 0);
    
    write741_to_byte_array (opthdr->SectionAlignment, section_alignment);
    write741_to_byte_array (opthdr->FileAlignment, file_alignment);
    
    write721_to_byte_array (opthdr->MajorOperatingSystemVersion, 4);
    write721_to_byte_array (opthdr->MajorImageVersion, 1);
    write721_to_byte_array (opthdr->MajorSubsystemVersion, 4);
    
    if (last_section) {
        write741_to_byte_array (opthdr->SizeOfImage, ALIGN (last_section->rva + last_section->total_size, section_alignment));
    } else {
        write741_to_byte_array (opthdr->SizeOfImage, ALIGN (state->size_of_headers, section_alignment));
    }
    
    write741_to_byte_array (opthdr->SizeOfHeaders, state->size_of_headers);
    write721_to_byte_array (opthdr->Subsystem, subsystem);
    
    {
    
        unsigned short characteristics = 0;
        
        if (can_be_relocated) {
            characteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        }
        
        write721_to_byte_array (opthdr->DllCharacteristics, characteristics);
    
    }
    
    {
    
        unsigned long stack_reserve = section_alignment << 9;
        unsigned long stack_commit = 0x1000;
        
        unsigned long heap_reserve = section_alignment << 8;
        unsigned long heap_commit = 0x1000;
        
        struct section *bss_section;
        
        if ((bss_section = section_find (".bss"))) {
        
            unsigned long image_data_end = ALIGN (bss_section->rva + bss_section->total_size, section_alignment);
                    
            if (image_data_end > stack_commit) {
                stack_commit = image_data_end;
            }
            
            if (image_data_end > heap_commit) {
                heap_commit = image_data_end;
            }
            
            if (stack_commit > stack_reserve) {
                stack_reserve = stack_commit;
            }
            
            if (heap_commit > heap_reserve) {
                heap_reserve = heap_commit;
            }
        
        }
        
        integer_to_array (stack_reserve, opthdr->SizeOfStackReserved, 8, 0);
        integer_to_array (stack_commit, opthdr->SizeOfStackCommit, 8, 0);
        integer_to_array (heap_reserve, opthdr->SizeOfHeapReserved, 8, 0);
        integer_to_array (heap_commit, opthdr->SizeOfHeapCommit, 8, 0);
    
    }
    
    write741_to_byte_array (opthdr->NumberOfRvaAndSizes, NUMBER_OF_DATA_DIRECTORIES);
    
    
    {
    
        struct pe_image_data_directory *idd;
        int i;
        
        for (i = 0; i < NUMBER_OF_DATA_DIRECTORIES; i++) {
        
            idd = (struct pe_image_data_directory *) pos;
            
            switch (i) {
            
                case 0:
                
                    /* EXPORT Table. */
                    if ((section = section_find (".edata"))) {
                    
                        write741_to_byte_array (idd->VirtualAddress, section->rva);
                        write741_to_byte_array (idd->Size, section->total_size);
                    
                    }
                    
                    break;
                
                case 1:
                
                    /* IMPORT Table. */
                    if ((section = section_find (".idata"))) {
                    
                        write741_to_byte_array (idd->VirtualAddress, section->rva);
                        write741_to_byte_array (idd->Size, section->total_size);
                    
                    }
                    
                    break;
                
                case 5:
                
                    /* BASE RELOCATION Table. */
                    if ((section = section_find (".reloc"))) {
                    
                        write741_to_byte_array (idd->VirtualAddress, section->rva);
                        write741_to_byte_array (idd->Size, section->total_size);
                    
                    }
                    
                    break;
                
                case 12:
                
                    /* IMPORT Address Table. */
                    if ((section = section_find (".idata")) && iat_first_part) {
                    
                        write741_to_byte_array (idd->VirtualAddress, iat_first_part->rva);
                        write741_to_byte_array (idd->Size, iat_last_part->rva + iat_last_part->content_size - iat_first_part->rva);
                    
                    }
                    
                    break;
            
            }
            
            pos += sizeof (*idd);
        
        }
    
    }
    
    
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
    fprintf (stderr, "    --out-implib FILE                 Generate import library\n");
    fprintf (stderr, "    --section-alignment <size>        Set section alignment.\n");
    fprintf (stderr, "    --subsystem <name>                Set required OS subsystem.\n");
    
    fprintf (stderr, "\n");
    fprintf (stderr, "    --def-list LIST                   Create implib from a comma seperated\n");
    fprintf (stderr, "                                          list of files.\n");
    fprintf (stderr, "    -shared, -Bshareable              Create a shared library.\n");

}

unsigned long pe_get_first_section_rva (void) {
    return ALIGN (state->size_of_headers, section_alignment);
}

unsigned long pe_align_to_file_alignment (unsigned long value) {
    return ALIGN (value, file_alignment);
}

static char *unprefix_name (const char *orig_name) {
    return (orig_name[0] == '_' ? xstrdup (orig_name + 1) : xstrdup (orig_name));
}

static char *undecorate_name (const char *orig_name) {

    const char *at_p;
    
    if (orig_name[0] == '_') {
        orig_name++;
    }
    
    if ((at_p = strchr (orig_name, '@'))) {
        return xstrndup (orig_name, at_p - orig_name);
    }
    
    return xstrdup (orig_name);

}

static void import_generate_import (const char *import_name, short ordinal_hint, short import_type, short import_name_type, const char *filename) {

    struct object_file *of;
    struct symbol *symbol;
    
    struct section_part *part;
    struct section *section;
    
    struct reloc_entry *relocs;
    struct subsection *subsection;
    
    struct section_part *dot_idata5_part;
    char *real_import_name;
    
    of = object_file_make (filename, 2 + 1 + ((import_type == IMPORT_CODE) ? 1 : 0));
    symbol = of->symbol_arr;
    
    section = section_find_or_make (".idata");
    subsection = subsection_find_or_make (section, "4");
    
    part = section_part_new (section, of);
    subsection_append_section_part (subsection, part);
    
    part->content = xmalloc (part->content_size = (state->format == LD_FORMAT_AMD64_PE ? 8 : 4));
    part->reloc_cnt = 1;
    part->reloc_arr = xmalloc (part->reloc_cnt * sizeof (*part->reloc_arr));
    
    relocs = part->reloc_arr;
    
    relocs[0].symbol = &of->symbol_arr[1];
    relocs[0].howto = &reloc_howtos[RELOC_TYPE_32_NO_BASE];
    relocs[0].offset = 0;
    
    subsection = subsection_find_or_make (section, "5");
    
    part = section_part_new (section, of);
    subsection_append_section_part (subsection, part);
    
    part->content = xmalloc (part->content_size = (state->format == LD_FORMAT_AMD64_PE ? 8 : 4));
    
    symbol->name = xstrdup (".idata$5");
    symbol->value = 0;
    symbol->part = part;
    symbol->section_number = 2;
    
    symbol++;
    
    part->reloc_cnt = 1;
    part->reloc_arr = xmalloc (part->reloc_cnt * sizeof (*part->reloc_arr));
    
    relocs = part->reloc_arr;
    
    relocs[0].symbol = &of->symbol_arr[1];
    relocs[0].howto = &reloc_howtos[RELOC_TYPE_32_NO_BASE];
    relocs[0].offset = 0;
    
    dot_idata5_part = part;
    subsection = subsection_find_or_make (section, "6");
    
    part = section_part_new (section, of);
    subsection_append_section_part (subsection, part);
    
    switch (import_name_type) {
    
        case IMPORT_ORDINAL:
        
            report_at (program_name, 0, REPORT_INTERNAL_ERROR, "IMPORT_ORDINAL is not yet supported");
            exit (EXIT_FAILURE);
        
        case IMPORT_NAME:
        
            real_import_name = xstrdup (import_name);
            break;
        
        case IMPORT_NAME_NOPREFIX:
        
            real_import_name = unprefix_name (import_name);
            break;
        
        case IMPORT_NAME_UNDECORATE:
        
            real_import_name = undecorate_name (import_name);
            break;
        
        default:
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "invalid or unsupported ImportNameType: %i", import_name_type);
            exit (EXIT_FAILURE);
    
    }
    
    part->content = xmalloc (part->content_size = ALIGN (2 + strlen (real_import_name) + 1, 2));
    
    integer_to_array (ordinal_hint, part->content, 2, 0);
    strcpy ((char *) part->content + 2, real_import_name);
    
    free (real_import_name);
    
    symbol->name = xstrdup (".idata$6");
    symbol->value = 0;
    symbol->part = part;
    symbol->section_number = 3;
    
    symbol++;
    
    if (import_type == IMPORT_CODE) {
    
        section = section_find_or_make (".text");
        
        part = section_part_new (section, of);
        section_append_section_part (section, part);
        
        part->content = xmalloc (part->content_size = 8);
        memcpy (part->content, "\xFF\x25\x00\x00\x00\x00\x90\x90", 8);
        
        symbol->name = xstrdup (import_name);
        symbol->value = 0;
        symbol->part = part;
        symbol->section_number = 4;
        symbol_record_external_symbol (symbol);
        
        symbol++;
        
        part->reloc_cnt = 1;
        part->reloc_arr = xmalloc (part->reloc_cnt * sizeof (*part->reloc_arr));
        
        relocs = part->reloc_arr;
        
        relocs[0].symbol = &of->symbol_arr[0];
        relocs[0].offset = 2;
        
        if (state->format == LD_FORMAT_AMD64_PE) {
            relocs[0].howto = &reloc_howtos[RELOC_TYPE_PC32];
        } else {
            relocs[0].howto = &reloc_howtos[RELOC_TYPE_32];
        }
    
    }
    
    symbol->name = xmalloc (7 + strlen (import_name) + 1);
    
    if (state->leading_underscore) {
        sprintf (symbol->name, "__imp__%s", import_name);
    } else {
        sprintf (symbol->name, "__imp_%s", import_name);
    }
    
    symbol->value = 0;
    symbol->part = dot_idata5_part;
    symbol->section_number = 2;
    
    symbol_record_external_symbol (symbol);

}


/**
 * According to https://oldweb.today/?browser=ie6#19830101000000/https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 * the earliest archive that's available is from 2022 (date doesn't seem to be visible if you use firfox 10) so the presence of
 * the dll name in the short entries may not have always be present but after digging out and installing my old copy of
 * Visual Studio 2005 and the link.exe that's available with it includes the dll name in the entries I'll assume that it's
 * always been present (for now at least).
 */
char *current_import_dll_name = 0;

static void import_generate_head (const char *filename, const char *dll_name) {

    struct object_file *of;
    struct subsection *subsection;
    
    struct section *section;
    struct section_part *part;
    
    struct pe_import_directory_table *import_dt;
    struct reloc_entry *relocs;
    
    unsigned long i;
    of = object_file_make (filename, 3);
    
    section = section_find_or_make (".idata");
    section->flags = translate_characteristics_to_section_flags (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    
    subsection = subsection_find_or_make (section, "2");
    
    part = section_part_new (section, of);
    subsection_append_section_part (subsection, part);
    
    import_dt = (struct pe_import_directory_table *) (part->content = xmalloc (part->content_size = sizeof (*import_dt)));
    
    integer_to_array (0, import_dt->ImportNameTableRVA, 4, 0);
    integer_to_array (0, import_dt->TimeDateStamp, 4, 0);
    integer_to_array (0, import_dt->ForwarderChain, 4, 0);
    integer_to_array (0, import_dt->NameRVA, 4, 0);
    integer_to_array (0, import_dt->ImportAddressTableRVA, 4, 0);
    
    part->reloc_cnt = 3;
    part->reloc_arr = xmalloc (part->reloc_cnt * sizeof (*part->reloc_arr));
    
    relocs = part->reloc_arr;
    
    for (i = 0; i < 3; i++) {
    
        relocs[i].symbol = &of->symbol_arr[i];
        relocs[i].howto = &reloc_howtos[RELOC_TYPE_32_NO_BASE];
    
    }
    
    relocs[0].offset = offsetof (struct pe_import_directory_table, ImportNameTableRVA);
    relocs[1].offset = offsetof (struct pe_import_directory_table, ImportAddressTableRVA);
    relocs[2].offset = offsetof (struct pe_import_directory_table, NameRVA);
    
    subsection = subsection_find_or_make (section, "4");
    
    part = section_part_new (section, of);
    subsection_append_section_part (subsection, part);
    
    part->content_size = 0;
    
    of->symbol_arr[0].name = xstrdup (".idata$4");
    of->symbol_arr[0].value = 0;
    of->symbol_arr[0].part = part;
    of->symbol_arr[0].section_number = 2;
    
    subsection = subsection_find_or_make (section, "5");
    
    part = section_part_new (section, of);
    subsection_append_section_part (subsection, part);
    
    part->content_size = 0;
    
    of->symbol_arr[1].name = xstrdup (".idata$5");
    of->symbol_arr[1].value = 0;
    of->symbol_arr[1].part = part;
    of->symbol_arr[1].section_number = 3;
    
    subsection = subsection_find_or_make (section, "7");
    
    part = section_part_new (section, of);
    subsection_append_section_part (subsection, part);
    
    part->content = xmalloc (part->content_size = ALIGN (strlen (dll_name) + 1, 2));
    strcpy ((char *) part->content, dll_name);
    
    of->symbol_arr[2].name = xstrdup (".idata$7");
    of->symbol_arr[2].value = 0;
    of->symbol_arr[2].part = part;
    of->symbol_arr[2].section_number = 4;

}

static void import_generate_end (void) {

    struct object_file *of;
    struct subsection *subsection;
    
    struct section *section;
    struct section_part *part;
    
    of = object_file_make (FAKE_LD_FILENAME, 3);
    
    section = section_find_or_make (".idata");
    subsection = subsection_find_or_make (section, "4");
    
    part = section_part_new (section, of);
    subsection_append_section_part (subsection, part);
    
    part->content = xmalloc (part->content_size = (state->format == LD_FORMAT_AMD64_PE ? 8 : 4));
    subsection = subsection_find_or_make (section, "5");
    
    part = section_part_new (section, of);
    subsection_append_section_part (subsection, part);
    
    part->content = xmalloc (part->content_size = (state->format == LD_FORMAT_AMD64_PE ? 8 : 4));

}

void pe_archive_end (void) {

    if (current_import_dll_name) {
    
        import_generate_end ();
        free (current_import_dll_name);
        
        current_import_dll_name = 0;
    
    }

}

void read_pe_import_library (const char *filename, unsigned char *data) {

    struct pe_import_library_header *import_header = (struct pe_import_library_header *) data;
    
    const char *import_name;
    const char *dll_name;
    
    if (state->format != LD_FORMAT_I386_PE && state->format != LD_FORMAT_AMD64_PE) {
        return;
    }
    
    if ((array_to_integer (import_header->Type, 2, 0) & 0x03) == IMPORT_CONST) {
    
        report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++ not yet supported import header import Type: 0x%x", array_to_integer (import_header->Type, 2, 0) & 0x3);
        return;
    
    }
    
    import_name = (const char *) data + sizeof (*import_header);
    dll_name = import_name + strlen (import_name) + 1;
    
    if (current_import_dll_name && strcmp (dll_name, current_import_dll_name)) {
    
        import_generate_end ();
        free (current_import_dll_name);
        
        current_import_dll_name = 0;
    
    }
    
    if (!current_import_dll_name) {
    
        current_import_dll_name = xstrdup (dll_name);
        import_generate_head (filename, current_import_dll_name);
    
    }
    
    import_generate_import (import_name, array_to_integer (import_header->OrdinalHint, 2, 0), array_to_integer (import_header->Type, 2, 0) & 0x03, array_to_integer (import_header->Type, 2, 0) >> 2, filename);

}
