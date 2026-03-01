/******************************************************************************
 * @file            coff.c
 *****************************************************************************/
#include    <ctype.h>
#include    <errno.h>
#include    <limits.h>
#include    <stddef.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>
#include    <time.h>

#include    "coff.h"
#include    "ld.h"
#include    "lib.h"
#include    "pe.h"
#include    "report.h"
#include    "section.h"
#include    "write7x.h"

#define     IMAGE_SYM_ABSOLUTE          -1
#define     IMAGE_SYM_DEBUG             -2

#define     IMAGE_SYM_UNDEFINED         0
#define     IMAGE_SYM_CLASS_EXTERNAL    2
#define     IMAGE_SYM_CLASS_STATIC      3

struct string_table_header {
    unsigned char StringTableSize[4];
};

struct symbol_table_entry {

    unsigned char Name[8];
    unsigned char value[4];
    
    unsigned char SectionNumber[2];
    unsigned char Type[2];
    
    unsigned char StorageClass[1];
    unsigned char NumberOfAuxSymbols[1];

};

static void translate_relocation (struct reloc_entry *reloc, struct coff_relocation_entry *input, struct section_part *part) {

    uint16_t type;
    
    reloc->symbol = part->of->symbol_arr + array_to_integer (input->SymbolTableIndex, 4, 0);
    reloc->offset = array_to_integer (input->VirtualAddress, 4, 0);
    
    type = array_to_integer (input->Type, 2, 0);
    
    switch (type) {
    
        case IMAGE_REL_I386_ABSOLUTE:
        
            reloc->howto = &reloc_howtos[RELOC_TYPE_IGNORED];
            break;
        
        case IMAGE_REL_I386_DIR16:
        
            reloc->howto = &reloc_howtos[RELOC_TYPE_16];
            break;
        
        case IMAGE_REL_I386_DIR32:
        
            reloc->howto = &reloc_howtos[RELOC_TYPE_32];
            break;
        
        case IMAGE_REL_I386_DIR32NB:
        
            reloc->howto = &reloc_howtos[RELOC_TYPE_32_NO_BASE];
            break;
        
        case IMAGE_REL_I386_REL16:
        
            reloc->howto = &reloc_howtos[RELOC_TYPE_PC16];
            break;
        
        case IMAGE_REL_I386_REL32:
        
            reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
            break;
        
        default:
        
            /* There is no point in continuing, the object is broken. */
            report_at (program_name, 0, REPORT_FATAL_ERROR, "invalid relocation type 0x%04hx (origin object '%s')", array_to_integer (input->Type, 2, 0), part->of->filename);
            exit (EXIT_FAILURE);
    
    }
    
    if (reloc->symbol->section_number == IMAGE_SYM_CLASS_STATIC) {
        reloc->n_type = reloc->symbol->section_number;
    }

}

static unsigned long translate_Characteristics_to_alignment (unsigned long Characteristics) {

    unsigned long alignment = 1;
    Characteristics &= IMAGE_SCN_ALIGN_8192BYTES;
    
    if (Characteristics == IMAGE_SCN_ALIGN_1BYTES) {
        alignment = 1;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_2BYTES) {
        alignment = 2;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_4BYTES) {
        alignment = 4;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_8BYTES) {
        alignment = 8;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_16BYTES) {
        alignment = 16;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_32BYTES) {
        alignment = 32;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_64BYTES) {
        alignment = 64;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_128BYTES) {
        alignment = 128;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_256BYTES) {
        alignment = 256;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_512BYTES) {
        alignment = 512;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_1024BYTES) {
        alignment = 1024;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_2048BYTES) {
        alignment = 2048;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_4096BYTES) {
        alignment = 4096;
    }
    
    if (Characteristics == IMAGE_SCN_ALIGN_8192BYTES) {
        alignment = 8192;
    }
    
    return alignment;

}

static unsigned long translate_Characteristics_to_section_flags (unsigned long Characteristics) {

    unsigned long flags = 0;
    
    if (!(Characteristics & IMAGE_SCN_MEM_WRITE)) {
        flags |= SECTION_FLAG_READONLY;
    }
    
    if (Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) {
        flags |= SECTION_FLAG_CODE;
    }
    
    if (Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
        flags |= SECTION_FLAG_DATA;
    }
    
    if (Characteristics & IMAGE_SCN_TYPE_NOLOAD) {
        flags |= SECTION_FLAG_NEVER_LOAD;
    }
    
    if (Characteristics & IMAGE_SCN_LNK_INFO) {
        flags |= SECTION_FLAG_DEBUGGING;
    }
    
    if (Characteristics & IMAGE_SCN_LNK_REMOVE) {
        flags |= SECTION_FLAG_EXCLUDE;
    }
    
    if (!(Characteristics & IMAGE_SCN_MEM_READ)) {
        flags |= SECTION_FLAG_NOREAD;
    }
    
    if (Characteristics & IMAGE_SCN_MEM_SHARED) {
        flags |= SECTION_FLAG_SHARED;
    }
    
    if (Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
        flags |= SECTION_FLAG_ALLOC;
    }
    
    return flags;

}

void read_coff_object (const char *filename, unsigned char *data, unsigned long data_size) {

    struct coff_header *coff_hdr;
    struct coff_relocation_entry *reloc_info;
    
    struct coff_section_table_entry *section_hdr;
    struct string_table_header *string_table_hdr;
    
    struct section_part **part_p_array, *part;
    struct object_file *of;
    
    struct section *section;
    struct subsection *subsection;
    
    char *string_table = 0, *section_name, *p;
    unsigned long string_table_size, no_sections, no_syms;
    
    unsigned char *pos = (unsigned char *) data;
    unsigned long i;
    
    struct section_part *bss_part = 0;
    struct section *bss_section = 0;
    
    long bss_section_number = 0;
    
    if ((pos - data + sizeof (*coff_hdr) > data_size) || pos < data) {
    
        report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: corrupted input file", filename);
        return;
    
    }
    
    coff_hdr = (struct coff_header *) data;
    
    pos = (unsigned char *) data + array_to_integer (coff_hdr->PointerToSymbolTable, 4, 0) + sizeof (struct symbol_table_entry) * array_to_integer (coff_hdr->NumberOfSymbols, 4, 0);
    string_table_hdr = (struct string_table_header *) pos;
    
    if ((string_table_size = array_to_integer (string_table_hdr->StringTableSize, 4, 0)) < 4) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: invalid string table size: %lu", filename, string_table_size);
        return;
    
    }
    
    string_table = (char *) pos;
    
    part_p_array = xmalloc (sizeof (*part_p_array) * (array_to_integer (coff_hdr->NumberOfSections, 2, 0) + 1));
    of = object_file_make (filename, array_to_integer (coff_hdr->NumberOfSymbols, 4, 0));
    
    no_sections = array_to_integer (coff_hdr->NumberOfSections, 2, 0);
    
    for (i = 0; i < no_sections; i++) {
    
        section_hdr = (struct coff_section_table_entry *) (pos = (unsigned char *) data + sizeof (struct coff_header) + sizeof (struct coff_section_table_entry) * i);
        section_name = xstrndup (section_hdr->Name, 8);
        
        if (section_name[0] == '/') {
        
            unsigned long offset = strtoul (section_name + 1, NULL, 10);
            
            if (offset < array_to_integer (string_table_hdr->StringTableSize, 4, 0)) {
            
                free (section_name);
                section_name = xstrdup (string_table + offset);
            
            } else {
                report_at (program_name, 0, REPORT_ERROR, "%s: invalid offset into string table", filename);
            }
        
        }
        
        if ((p = strchr (section_name, '$'))) {
            *p++ = '\0';
        }
        
        if (state->format == LD_FORMAT_I386_PE && strcmp (section_name, ".drectve") == 0) {
        
            pe_interpret_dot_drectve_section (/*filename, data, data_size, */data + array_to_integer (section_hdr->PointerToRawData, 4, 0), array_to_integer (section_hdr->SizeOfRawData, 4, 0));
            
            part_p_array[i + 1] = 0;
            free (section_name);
            
            continue;
        
        }
        
        if (array_to_integer (section_hdr->Characteristics, 4, 0) & IMAGE_SCN_LNK_REMOVE) {
        
            part_p_array[i + 1] = 0;
            
            free (section_name);
            continue;
        
        }
        
        section = section_find_or_make (section_name);
        section->flags = translate_Characteristics_to_section_flags (array_to_integer (section_hdr->Characteristics, 4, 0));
        
        if (array_to_integer (section_hdr->PointerToRawData, 4, 0) == 0 && array_to_integer (section_hdr->SizeOfRawData, 4, 0)) {
            section->is_bss = 1;
        }
        
        if (p) {
            subsection = subsection_find_or_make (section, p);
        } else {
            subsection = 0;
        }
        
        free (section_name);
        
        part = section_part_new (section, of);
        part->alignment = translate_Characteristics_to_alignment (array_to_integer (section_hdr->Characteristics, 4, 0));
        part->content_size = array_to_integer (section_hdr->SizeOfRawData, 4, 0);
        
        if (array_to_integer (section_hdr->PointerToRawData, 4, 0)) {
        
            pos = (unsigned char *) data + array_to_integer (section_hdr->PointerToRawData, 4, 0);
            
            part->content = xmalloc (part->content_size);
            memcpy (part->content, pos, part->content_size);
        
        }
        
        if (section->is_bss) {
        
            bss_section_number = i + 1;
            bss_section = section;
        
        }
        
        if (array_to_integer (section_hdr->PointerToRelocations, 4, 0) && array_to_integer (section_hdr->NumberOfRelocations, 2, 0)) {
        
            unsigned long j, no_relocs;
            
            if (!array_to_integer (section_hdr->PointerToRawData, 4, 0)) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: section '%s' is BSS but has relocations", filename, section->name);
                exit (EXIT_FAILURE);
            
            }
            
            pos = (unsigned char *) data + array_to_integer (section_hdr->PointerToRelocations, 4, 0);
            
            part->reloc_arr = xmalloc (sizeof (struct reloc_entry) * array_to_integer (section_hdr->NumberOfRelocations, 2, 0));
            part->reloc_cnt = array_to_integer (section_hdr->NumberOfRelocations, 2, 0);
            
            no_relocs = array_to_integer (section_hdr->NumberOfRelocations, 2, 0);
            
            for (j = 0; j < no_relocs; j++) {
            
                reloc_info = (struct coff_relocation_entry *) (pos + (sizeof (*reloc_info) * j));
                translate_relocation (part->reloc_arr + j, reloc_info, part);
            
            }
        
        }
        
        if (subsection) {
            subsection_append_section_part (subsection, part);
        } else {
            section_append_section_part (section, part);
        }
        
        part_p_array[i + 1] = part;
    
    }
    
    no_syms = array_to_integer (coff_hdr->NumberOfSymbols, 4, 0);
    
    for (i = 0; i < no_syms; i++) {
    
        struct symbol *symbol = of->symbol_arr + i;
        
        struct symbol_table_entry *coff_symbol;
        short section_no, no_sections;
        
        coff_symbol = (struct symbol_table_entry *) ((unsigned char *) data + array_to_integer (coff_hdr->PointerToSymbolTable, 4, 0) + sizeof (struct symbol_table_entry) * i);
        
        if (memcmp (coff_symbol->Name, "\0\0\0\0", 4) == 0) {
        
            unsigned long offset = array_to_integer (coff_symbol->Name + 4, 4, 0);
            
            if (offset < array_to_integer (string_table_hdr->StringTableSize, 4, 0)) {
                symbol->name = xstrdup (string_table + offset);
            } else {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid offset into string table", filename);
                exit (EXIT_FAILURE);
            
            }
        
        } else {
            symbol->name = xstrndup ((char *) coff_symbol->Name, 8);
        }
        
        section_no = array_to_integer (coff_symbol->SectionNumber, 2, 0);
        
        symbol->value = array_to_integer (coff_symbol->value, 4, 0);
        symbol->size = 0;
        symbol->section_number = section_no;
        
        no_sections = array_to_integer (coff_hdr->NumberOfSections, 2, 0);
        
        if (section_no == IMAGE_SYM_UNDEFINED) {
        
            if (symbol->value) {
            
                struct symbol *old_symbol = symbol_find (symbol->name);
                
                if (!old_symbol || symbol_is_undefined (old_symbol)) {
                
                    if (!bss_section) {
                    
                        bss_section = section_find_or_make (".bss");
                        
                        bss_section->flags = translate_Characteristics_to_section_flags (IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
                        bss_section->is_bss = 1;
                        
                        bss_section_number = array_to_integer (coff_hdr->NumberOfSections, 2, 0) ? array_to_integer (coff_hdr->NumberOfSections, 2, 0) : 1;
                    
                    }
                    
                    bss_part = section_part_new (bss_section, of);
                    section_append_section_part (bss_section, bss_part);
                    
                    bss_part->content_size = symbol->size - symbol->value;
                    
                    symbol->part = bss_part;
                    symbol->value = 0;
                    symbol->section_number = bss_section_number;
                
                } else {
                
                    if (symbol->value > old_symbol->size) {
                        old_symbol->part->content_size = old_symbol->size = symbol->value;
                    }
                    
                    symbol->value = 0;
                    symbol->part = 0;
                
                }
            
            } else {
                symbol->part = 0;
            }
        
        } else if (section_no > 0 && section_no <= no_sections) {
            symbol->part = part_p_array[section_no];
        } else if (section_no == IMAGE_SYM_ABSOLUTE || section_no == IMAGE_SYM_DEBUG) {
        
            symbol->section_number = section_no;
            symbol->part = 0;
        
        } else if (section_no > no_sections) {
        
            report_at (program_name, 0, REPORT_ERROR, "%s: invalid symbol SectionNumber: %hi", filename, section_no);
            symbol->part = 0;
        
        } else {
        
            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++not yet supported symbol SectionNumber: %hi", section_no);
            exit (EXIT_FAILURE);
        
        }
        
        if (coff_symbol->StorageClass[0] == IMAGE_SYM_CLASS_STATIC) {
            symbol->n_type = 2;
        }
        
        if (coff_symbol->StorageClass[0] == IMAGE_SYM_CLASS_EXTERNAL || section_no == IMAGE_SYM_UNDEFINED) {
            symbol_record_external_symbol (symbol);
        }
        
        if (coff_symbol->NumberOfAuxSymbols[0]) {
        
            unsigned long j;
            
            for (j = 0; j < coff_symbol->NumberOfAuxSymbols[0]; j++) {
            
                symbol = of->symbol_arr + i + 1 + j;
                
                memset (symbol, 0, sizeof (*symbol));
                symbol->auxiliary = 1;
            
            }
            
            i += coff_symbol->NumberOfAuxSymbols[1];
        
        }
    
    }
    
    free (part_p_array);

}


struct exclude_symbol {

    char *name;
    struct exclude_symbol *next;

};

static struct exclude_symbol *exclude_symbols = 0;

static int generate_reloc_section = 1;
static int can_be_relocated = 0;

static int check_reloc_section_needed_section_part (struct section_part *part) {

    struct reloc_howto *reloc_howto;
    unsigned long i;
    
    for (i = 0; i < part->reloc_cnt; i++) {
    
        reloc_howto = part->reloc_arr[i].howto;
        
        if (reloc_howto == &reloc_howtos[RELOC_TYPE_16] || reloc_howto == &reloc_howtos[RELOC_TYPE_32]) {
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

static void exclude_symbols_free (void) {

    struct exclude_symbol *exclude_symbol;
    
    for (exclude_symbol = exclude_symbols; exclude_symbol; exclude_symbol = exclude_symbols) {
    
        exclude_symbols = exclude_symbol->next;
        
        free (exclude_symbol->name);
        free (exclude_symbol);
    
    }

}

static void generate_base_relocation_block (struct section *section, struct coff_relocation_entry *ibr_hdr_p, unsigned long num_relocs, struct section *saved_section, struct section_part *saved_part, unsigned long saved_i) {

    struct section_part *reloc_part;
    struct reloc_entry *relocs;
    
    unsigned char *write_pos;
    unsigned long i;
    
    struct section_part *part;
    
    reloc_part = section_part_new (section, object_file_make (FAKE_LD_FILENAME, 0));
    reloc_part->content_size = num_relocs * sizeof (*ibr_hdr_p);
    
    reloc_part->content = xmalloc (reloc_part->content_size);
    write_pos = reloc_part->content;
    
    for (part = ((section = saved_section) ? saved_part : section->first_part); part; part = part->next) {
    
        relocs = part->reloc_arr;
        
        for (i = ((part == saved_part) ? saved_i : 0); i < part->reloc_cnt; i++) {
        
            integer_to_array (part->rva + relocs[i].offset, ibr_hdr_p->VirtualAddress, 4, 0);
            
            if (relocs[i].howto == &reloc_howtos[RELOC_TYPE_16]) {
                integer_to_array (IMAGE_REL_I386_DIR16, ibr_hdr_p->Type, 2, 0);
            } else if (relocs[i].howto == &reloc_howtos[RELOC_TYPE_32]) {
                integer_to_array (IMAGE_REL_I386_DIR32, ibr_hdr_p->Type, 2, 0);
            } else {
                continue;
            }
            
            memcpy (write_pos, ibr_hdr_p, sizeof (*ibr_hdr_p));
            write_pos += sizeof (*ibr_hdr_p);
            
            if (!--num_relocs) {
                goto _finish;
            }
        
        }
    
    }
    
    report_at (program_name, 0, REPORT_INTERNAL_ERROR, "num_relocs mismatch while generating .reloc section");
    
_finish:
    
    section_append_section_part (section, reloc_part);

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
    
    struct coff_section_table_entry *hdr;
    struct section *section;
    
    for (section = all_sections; section; section = section->next) {
    
        if (!(hdr = (struct coff_section_table_entry *) section->object_dependent_data)) {
            section->object_dependent_data = (hdr = xmalloc (sizeof (*hdr)));
        }
        
        memset (hdr->Name, 0, sizeof (hdr->Name));
        memcpy (hdr->Name, section->name, (strlen (section->name) >= sizeof (hdr->Name)) ? sizeof (hdr->Name) : strlen (section->name));
        
        write741_to_byte_array (hdr->VirtualSize, section->total_size);
        write741_to_byte_array (hdr->VirtualAddress, section->rva);
        
        if (!section->is_bss) {
        
            write741_to_byte_array (hdr->SizeOfRawData, section->total_size);
            write741_to_byte_array (hdr->PointerToRawData, pos - data);
            
            if (array_to_integer (hdr->NumberOfRelocations, 2, 0) > 0) {
                write741_to_byte_array (hdr->PointerToRelocations, (pos - data) + section->total_size);
            }
            
            section_write (section, pos);
            pos += (section->total_size + (array_to_integer (hdr->NumberOfRelocations, 2, 0) * sizeof (struct coff_relocation_entry)));
        
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

void coff_after_link (void) {

    unsigned long num_relocs = 0, saved_i = 0, i;
    
    struct section *saved_section = 0, *section;
    struct section_part *saved_part = 0, *part;
    
    struct coff_relocation_entry ibr_hdr;
    struct reloc_entry *relocs;
    
    struct coff_section_table_entry *hdr;
    
    if (!generate_reloc_section) {
        return;
    }
    
    memset (&ibr_hdr, 0, sizeof (ibr_hdr));
    
    for (section = all_sections; section; section = section->next) {
    
        section->object_dependent_data = (hdr = xmalloc (sizeof (*hdr)));
        
        for (part = section->first_part; part; part = part->next) {
        
            relocs = part->reloc_arr;
            
            for (i = 0; i < part->reloc_cnt; i++) {
            
                if (relocs[i].howto != &reloc_howtos[RELOC_TYPE_16] && relocs[i].howto != &reloc_howtos[RELOC_TYPE_32]) {
                    continue;
                }
                
                if (num_relocs && part->rva + relocs[i].offset < array_to_integer (ibr_hdr.VirtualAddress, 4, 0)) {
                
                    generate_base_relocation_block (section, &ibr_hdr, num_relocs, saved_section, saved_part, saved_i);
                    num_relocs = 0;
                
                }
                
                if (num_relocs == 0) {
                
                    integer_to_array (part->rva + relocs[i].offset, ibr_hdr.VirtualAddress, 4, 0);
                    
                    saved_section = section;
                    saved_part = part;
                    
                    saved_i = i;
                
                }
                
                num_relocs++;
            
            }
        
        }
        
        if (num_relocs) {
            generate_base_relocation_block (section, &ibr_hdr, num_relocs, saved_section, saved_part, saved_i);
        }
        
        integer_to_array (num_relocs, hdr->NumberOfRelocations, 2, 0);
    
    }

}

void coff_before_link (void) {

    exclude_symbols_free ();
    
    if (!check_reloc_section_needed ()) {
    
        can_be_relocated = 1;
        generate_reloc_section = 0;
    
    }
    
    if (generate_reloc_section) {
        can_be_relocated = 1;
    }
    
    state->size_of_headers = sizeof (struct coff_header) + sizeof (struct coff_optional_header);
    state->size_of_headers += sizeof (struct coff_section_table_entry) * section_count ();

}

void coff_write (const char *filename) {

    FILE *fp;
    
    unsigned long data_size = 0;
    unsigned char *data, *pos;
    
    struct coff_header *coffhdr;
    struct coff_optional_header *opthdr;
    
    struct section *section;
    struct coff_section_table_entry *sec_ent;
    
    if (!(fp = fopen (filename, "wb"))) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to open '%s' for writing", filename);
        return;
    
    }
    
    for (section = all_sections; section; section = section->next) {
    
        if (!section->is_bss) {
        
            data_size += section->total_size;
            
            if ((sec_ent = section->object_dependent_data)) {
                data_size += (array_to_integer (sec_ent->NumberOfRelocations, 2, 0) * sizeof (struct coff_relocation_entry));
            }
        
        }
    
    }
    
    data_size += state->size_of_headers;
    
    data = xmalloc (data_size);
    write_sections (data);
    
    coffhdr = (struct coff_header *) data;
    opthdr = (struct coff_optional_header *) ((char *) coffhdr + sizeof (*coffhdr));
    
    pos = (unsigned char *) opthdr + sizeof (*opthdr);
    
    write721_to_byte_array (coffhdr->Machine, IMAGE_FILE_MACHINE_I386);
    write721_to_byte_array (coffhdr->NumberOfSections, section_count ());
    write741_to_byte_array (coffhdr->TimeDateStamp, time (0));
    write721_to_byte_array (coffhdr->SizeOfOptionalHeader, sizeof (*opthdr));
    
    {
    
        unsigned short characteristics = 0;
        
        characteristics |= IMAGE_FILE_EXECUTABLE_IMAGE;
        /*characteristics |= IMAGE_FILE_LINE_NUMS_STRIPPED;*/
        characteristics |= IMAGE_FILE_LOCAL_SYMS_STRIPPED;
        characteristics |= IMAGE_FILE_LITTLE_ENDIAN;
        
        if (!can_be_relocated) {
            characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
        }
        
        write721_to_byte_array (coffhdr->Characteristics, characteristics);
    
    }
    
    write721_to_byte_array (opthdr->Magic, IMAGE_FILE_MAGIC_I386);
    
    opthdr->MajorLinkerVersion = 0;
    opthdr->MinorLinkerVersion = 10;
    
    write741_to_byte_array (opthdr->SizeOfCode, size_of_code);
    write741_to_byte_array (opthdr->SizeOfInitializedData, size_of_initialized_data);
    write741_to_byte_array (opthdr->SizeOfUninitializedData, size_of_uninitialized_data);
    
    write741_to_byte_array (opthdr->AddressOfEntryPoint, state->entry_point);
    
    write741_to_byte_array (opthdr->BaseOfCode, base_of_code);
    write741_to_byte_array (opthdr->BaseOfData, base_of_data);
    
    for (section = all_sections; section; section = section->next) {
    
        struct coff_section_table_entry *hdr = section->object_dependent_data;
        
        memcpy (pos, hdr, sizeof (*hdr));
        pos += sizeof (*hdr);
        
        free (hdr);
    
    }
    
    if (fwrite (data, data_size, 1, fp) != 1) {
        report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", filename);
    }
    
    free (data);
    fclose (fp);

}
