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
#include    "report.h"
#include    "section.h"
#include    "write7x.h"

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
        
            integer_to_array (part->rva + relocs[i].offset, ibr_hdr_p->VirtualAddress, 4);
            
            if (relocs[i].howto == &reloc_howtos[RELOC_TYPE_16]) {
                integer_to_array (IMAGE_REL_I386_DIR16, ibr_hdr_p->Type, 2);
            } else if (relocs[i].howto == &reloc_howtos[RELOC_TYPE_32]) {
                integer_to_array (IMAGE_REL_I386_DIR32, ibr_hdr_p->Type, 2);
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
            
            if (array_to_integer (hdr->NumberOfRelocations, 2) > 0) {
                write741_to_byte_array (hdr->PointerToRelocations, (pos - data) + section->total_size);
            }
            
            section_write (section, pos);
            pos += (section->total_size + (array_to_integer (hdr->NumberOfRelocations, 2) * sizeof (struct coff_relocation_entry)));
        
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
                
                if (num_relocs && part->rva + relocs[i].offset < array_to_integer (ibr_hdr.VirtualAddress, 4)) {
                
                    generate_base_relocation_block (section, &ibr_hdr, num_relocs, saved_section, saved_part, saved_i);
                    num_relocs = 0;
                
                }
                
                if (num_relocs == 0) {
                
                    integer_to_array (part->rva + relocs[i].offset, ibr_hdr.VirtualAddress, 4);
                    
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
        
        integer_to_array (num_relocs, hdr->NumberOfRelocations, 2);
    
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
                data_size += (array_to_integer (sec_ent->NumberOfRelocations, 2) * sizeof (struct coff_relocation_entry));
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
