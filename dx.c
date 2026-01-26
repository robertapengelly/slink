/******************************************************************************
 * @file            dx.c
 *****************************************************************************/
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "dx.h"
#include    "ld.h"
#include    "lib.h"
#include    "reloc.h"
#include    "report.h"
#include    "section.h"
#include    "symbol.h"

static unsigned long section_alignment = DEFAULT_SECTION_ALIGNMENT;

static unsigned long section_get_num_relocs (struct section *section) {

    unsigned long num_relocs = 0, i;
    
    struct section_part *part;
    struct reloc_howto *howto;
    
    for (part = section->first_part; part; part = part->next) {
    
        for (i = 0; i < part->reloc_cnt; i++) {
        
            howto = part->reloc_arr[i].howto;
            
            if (howto == &reloc_howtos[RELOC_TYPE_64] || howto == &reloc_howtos[RELOC_TYPE_32] || howto == &reloc_howtos[RELOC_TYPE_16] || howto == &reloc_howtos[RELOC_TYPE_8]) {
                num_relocs++;
            }
        
        }
    
    }
    
    return num_relocs;

}

static unsigned char *write_relocs_for_section (unsigned char *pos, struct section *section) {

    struct section_part *part;
    struct dx_relocation_info rel;
    
    struct symbol *symbol;
    unsigned long size_log2, i, r_symbolnum;
    
    for (part = section->first_part; part; part = part->next) {
    
        for (i = 0; i < part->reloc_cnt; i++) {
        
            memset (&rel, 0, sizeof (rel));
            
            if (part->reloc_arr[i].howto == &reloc_howtos[RELOC_TYPE_64]) {
                size_log2 = 3;
            } else if (part->reloc_arr[i].howto == &reloc_howtos[RELOC_TYPE_32]) {
                size_log2 = 2;
            } else if (part->reloc_arr[i].howto == &reloc_howtos[RELOC_TYPE_16]) {
                size_log2 = 1;
            } else if (part->reloc_arr[i].howto == &reloc_howtos[RELOC_TYPE_8]) {
                size_log2 = 0;
            } else {
                continue;
            }
            
            symbol = part->reloc_arr[i].symbol;
            
            if (symbol_is_undefined (symbol)) {
                symbol = symbol_find (symbol->name);
            }
            
            integer_to_array (part->rva - part->section->rva + part->reloc_arr[i].offset, rel.r_address, 4, 0);
            
            if (!symbol->part || strcmp (symbol->part->section->name, ".text") == 0) {
                r_symbolnum = N_TEXT;
            } else if (strcmp (symbol->part->section->name, ".data") == 0) {
                r_symbolnum = N_DATA;
            } else if (strcmp (symbol->part->section->name, ".bss") == 0) {
                r_symbolnum = N_BSS;
            } else {
                r_symbolnum = N_TEXT;
            }
            
            if ((part->reloc_arr[i].r_symbolnum >> 27) & 1) {
                r_symbolnum |= (1LU << 27);
            }
            
            integer_to_array (r_symbolnum | (size_log2 << 25), rel.r_symbolnum, 4, 0);
            
            memcpy (pos, &rel, sizeof (rel));
            pos += sizeof (rel);
        
        }
    
    }
    
    return pos;

}

void dx_write (const char *filename) {

    FILE *fp;
    
    unsigned char *data, *pos;
    unsigned long image_size;
    
    struct section *text_section, *data_section, *bss_section;
    unsigned long text_size = 0, data_size = 0, bss_size = 0;
    
    struct dx_exec exec;
    memset (&exec, 0, sizeof (exec));
    
    if (!(fp = fopen (filename, "wb"))) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to open '%s' for writing", filename);
        return;
    
    }
    
    text_section = section_find (".text");
    data_section = section_find (".data");
    bss_section  = section_find (".bss");
    
    integer_to_array (DX_MAGIC, exec.a_magic, 4, 0);
    
    exec.a_cpu = (state->format == LD_FORMAT_I386_DX) ? 0x10 : 0x04;
    exec.a_hdrlen = sizeof (exec);
    
    if (text_section) {
    
        if (state->impure) {
            text_size = text_section->total_size;
        } else {
            text_size = ALIGN (text_section->total_size, section_alignment);
        }
    
    }
    
    if (data_section) {
    
        if (state->impure) {
            data_size = data_section->total_size;
        } else {
            data_size = ALIGN (data_section->total_size, section_alignment);
        }
    
    }
    
    if (bss_section) {
    
        if (state->impure) {
            bss_size = bss_section->total_size;
        } else {
            bss_size = ALIGN (bss_section->total_size, section_alignment);
        }
    
    }
    
    integer_to_array (text_size, exec.a_text, 4, 0);
    integer_to_array (data_size, exec.a_data, 4, 0);
    
    integer_to_array (bss_size, exec.a_bss, 4, 0);
    integer_to_array (state->entry_point, exec.a_entry, 4, 0);
    
    integer_to_array (array_to_integer (exec.a_text, 4, 0) + array_to_integer (exec.a_data, 4, 0), exec.a_total, 4, 0);
    
    if (text_section) {
        integer_to_array (section_get_num_relocs (text_section) * sizeof (struct dx_relocation_info), exec.a_trsize, 4, 0);
    }
    
    if (data_section) {
        integer_to_array (section_get_num_relocs (data_section) * sizeof (struct dx_relocation_info), exec.a_drsize, 4, 0);
    }
    
    image_size = sizeof (exec);
    
    image_size += (array_to_integer (exec.a_text, 4, 0) + array_to_integer (exec.a_data, 4, 0));
    image_size += (array_to_integer (exec.a_trsize, 4, 0) + array_to_integer (exec.a_drsize, 4, 0));
    
    image_size += 4;
    
    data = xmalloc (image_size);
    memcpy (data, &exec, sizeof (exec));
    
    pos = data + sizeof (exec);
    
    if (text_section) {
        section_write (text_section, pos);
    }
    
    pos += array_to_integer (exec.a_text, 4, 0);
    
    if (data_section) {
        section_write (data_section, pos);
    }
    
    pos += array_to_integer (exec.a_data, 4, 0);
    
    if (text_section) {
        pos = write_relocs_for_section (pos, text_section);
    }
    
    if (data_section) {
        pos = write_relocs_for_section (pos, data_section);
    }
    
    integer_to_array (4, pos, 4, 0);
    
    if (fwrite (data, image_size, 1, fp) != 1) {
        report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", filename);
    }
    
    free (data);
    fclose (fp);

}


void dx_before_link (void) {

    if (!state->impure) {
    
        struct section *section;
        
        for (section = all_sections; section; section = section->next) {
        
            if (section->section_alignment < section_alignment) {
                section->section_alignment = section_alignment;
            }
        
        }
    
    }

}
