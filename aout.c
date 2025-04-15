/******************************************************************************
 * @file            aout.c
 *****************************************************************************/
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "aout.h"
#include    "ld.h"
#include    "lib.h"
#include    "report.h"
#include    "section.h"
#include    "symbol.h"

static void translate_relocation (struct reloc_entry *reloc, struct aout_relocation_info *input_reloc, struct section_part *part, struct aout_exec *exec_p) {

    unsigned long r_symbolnum = array_to_integer (input_reloc->r_symbolnum, 4);
    
    unsigned long r_address = array_to_integer (input_reloc->r_address, 4);
    long symbolnum = (r_symbolnum & 0xffffff);
    
    if ((r_symbolnum >> 27) & 1) {      /* ext */
    
        reloc->symbol = part->of->symbol_arr + symbolnum;
        
        if (xstrcasecmp (reloc->symbol->name, "DGROUP") == 0) {
            r_symbolnum &= ~(1LU << 27);
        }
        
        symbolnum = (reloc->symbol->n_type & N_TYPE);
    
    } else {
    
        if (symbolnum == N_TEXT) {
            reloc->symbol = part->of->symbol_arr + part->of->symbol_cnt - 3;
        } else if (symbolnum == N_DATA) {
        
            reloc->symbol = part->of->symbol_arr + part->of->symbol_cnt - 2;
            reloc->addend -= array_to_integer (exec_p->a_text, 4);
        
        } else if (symbolnum == N_BSS) {
        
            reloc->symbol = part->of->symbol_arr + part->of->symbol_cnt - 1;
            reloc->addend -= (array_to_integer (exec_p->a_text, 4) + array_to_integer (exec_p->a_data, 4));
        
        } else {
        
            report_at (program_name, 0, REPORT_INTERNAL_ERROR, "local input_reloc->r_symbolnum %#lx is not yet supported", symbolnum);
            return;
        
        }
    
    }
    
    reloc->symbolnum = symbolnum;
    reloc->offset = r_address;
    
    reloc->n_type = ((r_symbolnum >> 24) & 0xff);
    reloc->n_type &= ~(1 << 3);
    
    reloc->n_ext = ((r_symbolnum >> 27) & 1);
    
    switch (1U << ((r_symbolnum >> 25) & 3)) {
    
        case 8:
        
            if ((r_symbolnum >> 24) & 1) {
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_PC64];
                reloc->addend += reloc->offset + 8;
            
            } else {
                reloc->howto = &reloc_howtos[RELOC_TYPE_64];
            }
            
            break;
        
        case 4:
        
            if ((r_symbolnum >> 24) & 1) {
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                reloc->addend += reloc->offset + 4;
            
            } else {
                reloc->howto = &reloc_howtos[RELOC_TYPE_32];
            }
            
            break;
        
        case 2:
        
            if ((r_symbolnum >> 24) & 1) {
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_PC16];
                reloc->addend += reloc->offset + 2;
            
            } else {
                reloc->howto = &reloc_howtos[RELOC_TYPE_16];
            }
            
            break;
        
        case 1:
        
            if ((r_symbolnum >> 24) & 1) {
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_PC8];
                reloc->addend += reloc->offset + 4;
            
            } else {
                reloc->howto = &reloc_howtos[RELOC_TYPE_8];
            }
            
            break;
    
    }

}

void read_aout_object (const char *filename, unsigned char *data, unsigned long data_size) {

    struct aout_exec *aout_exec;
    struct aout_nlist *aout_nlist;
    
    const char *strtab;
    unsigned long strtab_size;
    
    unsigned long num_symbols;
    unsigned long i;
    
    struct section_part *part, *part_p_array[4] = { 0 };
    struct section *section, *bss_section;
    
    struct symbol *symbol, *old_symbol;
    struct section_part *bss_part;
    
    struct aout_relocation_info *reloc_info;
    struct object_file *of;
    
    unsigned char *pos = data;
    
    if ((pos - data + sizeof (*aout_exec) > data_size) || pos < data) {
    
        report_at (program_name, 0, REPORT_FATAL_ERROR, "corrupted input file");
        return;
    
    }
    
    aout_exec = (struct aout_exec *) pos;
    pos += sizeof (*aout_exec);
    
    num_symbols = array_to_integer (aout_exec->a_syms, 4) / sizeof (*aout_nlist);
    of = object_file_make (filename, num_symbols + 4);
    
    section = section_find_or_make (".text");
    section->flags = SECTION_FLAG_ALLOC | SECTION_FLAG_LOAD | SECTION_FLAG_READONLY | SECTION_FLAG_CODE;
    
    part = section_part_new (section, of);
    
    part->content_size = array_to_integer (aout_exec->a_text, 4);
    part->content = xmalloc (part->content_size);
    
    if ((pos - data + part->content_size > data_size) || pos < data) {
    
        report_at (program_name, 0, REPORT_FATAL_ERROR, "corrupted input file");
        return;
    
    }
    
    memcpy (part->content, pos, part->content_size);
    pos += part->content_size;
    
    section_append_section_part (section, part);
    part_p_array[1] = part;
    
    section = section_find_or_make (".data");
    section->flags = SECTION_FLAG_ALLOC | SECTION_FLAG_LOAD | SECTION_FLAG_DATA;
    
    part = section_part_new (section, of);
    
    part->content_size = array_to_integer (aout_exec->a_data, 4);
    part->content = xmalloc (part->content_size);
    
    if ((pos - data + part->content_size > data_size) || pos < data) {
    
        report_at (program_name, 0, REPORT_FATAL_ERROR, "corrupted input file");
        return;
    
    }
    
    memcpy (part->content, pos, part->content_size);
    pos += part->content_size;
    
    section_append_section_part (section, part);
    part_p_array[2] = part;
    
    bss_section = section = section_find_or_make (".bss");
    
    section->flags = SECTION_FLAG_ALLOC;
    section->is_bss = 1;
    
    part = section_part_new (section, of);
    part->content_size = array_to_integer (aout_exec->a_bss, 4);
    
    section_append_section_part (section, part);
    part_p_array[3] = part;
    
    pos += array_to_integer (aout_exec->a_syms, 4) + array_to_integer (aout_exec->a_trsize, 4) + array_to_integer (aout_exec->a_drsize, 4);
    
    if ((unsigned long) (pos - data + 4) > data_size || pos < data) {
    
        report_at (program_name, 0, REPORT_FATAL_ERROR, "corrupted input file");
        return;
    
    }
    
    strtab_size = array_to_integer (pos, 4);
    
    if (strtab_size < 4) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: invalid string table size %lu", filename, strtab_size);
        return;
    
    } else {
    
        if ((pos - data + strtab_size > data_size) || pos < data) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "corrupted input file");
            return;
        
        }
        
        strtab = (char *) pos;
    
    }
    
    pos -= array_to_integer (aout_exec->a_syms, 4);
    
    for (i = 0; i < num_symbols; i++) {
    
        aout_nlist = (struct aout_nlist *) (pos + (i * sizeof (*aout_nlist)));
        symbol = of->symbol_arr + i;
        
        if (array_to_integer (aout_nlist->n_strx, 4) < strtab_size) {
            symbol->name = xstrdup (strtab + array_to_integer (aout_nlist->n_strx, 4));
        } else {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid offset into string table", filename);
            return;
        
        }
        
        symbol->value = array_to_integer (aout_nlist->n_value, 4);
        symbol->size = 0;
        symbol->n_type = aout_nlist->n_type;
        
        if ((aout_nlist->n_type & N_TYPE) == N_UNDF || (aout_nlist->n_type & N_TYPE) == N_COMM) {
        
            if (symbol->value) {
            
                old_symbol = symbol_find (symbol->name);
                
                if (!old_symbol || symbol_is_undefined (old_symbol)) {
                
                    bss_part = section_part_new (bss_section, of);
                    section_append_section_part (bss_section, bss_part);
                    
                    bss_part->content_size = symbol->size = symbol->value;
                    
                    symbol->part = bss_part;
                    symbol->value = 0;
                    symbol->section_number = 3;
                
                } else {
                
                    if (symbol->value > old_symbol->size) {
                        old_symbol->part->content_size = old_symbol->size = symbol->value;
                    }
                    
                    symbol->part = 0;
                    symbol->value = 0;
                    symbol->section_number = UNDEFINED_SECTION_NUMBER;
                
                }
            
            } else {
            
                symbol->section_number = UNDEFINED_SECTION_NUMBER;
                symbol->part = 0;
            
            }
        
        } else if ((aout_nlist->n_type & N_TYPE) == N_ABS) {
        
            symbol->section_number = ABSOLUTE_SECTION_NUMBER;
            symbol->part = 0;
        
        } else if ((aout_nlist->n_type & N_TYPE) == N_TEXT) {
        
            symbol->section_number = 1;
            symbol->part = part_p_array[1];
        
        } else if ((aout_nlist->n_type & N_TYPE) == N_DATA) {
        
            symbol->section_number = 2;
            symbol->part = part_p_array[2];
            symbol->value -= array_to_integer (aout_exec->a_text, 4);
        
        } else if ((aout_nlist->n_type & N_TYPE) == N_BSS) {
        
            symbol->section_number = 3;
            symbol->part = part_p_array[3];
            symbol->value -= (array_to_integer (aout_exec->a_text, 4) + array_to_integer (aout_exec->a_data, 4));
        
        } else {
        
            report_at (program_name, 0, REPORT_INTERNAL_ERROR, "unsupported nlist.n_type: %#x", aout_nlist->n_type);
            return;
        
        }
        
        if ((aout_nlist->n_type & N_EXT) || (aout_nlist->n_type & N_TYPE) == N_UNDF || (aout_nlist->n_type & N_TYPE) == N_COMM) {
            symbol_record_external_symbol (symbol);
        }
    
    }
    
    for (i = 1; i < 4; i++) {
    
        symbol = of->symbol_arr + num_symbols + i;
        part = part_p_array[i];
        
        symbol->name = xstrdup (part->section->name);
        symbol->value = 0;
        symbol->size = 0;
        symbol->part = part;
        symbol->section_number = i;
    
    }
    
    pos -= (array_to_integer (aout_exec->a_trsize, 4) + array_to_integer (aout_exec->a_drsize, 4));
    part = part_p_array[1];
    
    part->reloc_cnt = array_to_integer (aout_exec->a_trsize, 4) / sizeof (*reloc_info);
    part->reloc_arr = xmalloc (sizeof (*part->reloc_arr) * part->reloc_cnt);
    
    for (i = 0; i < part->reloc_cnt; i++) {
    
        reloc_info = (struct aout_relocation_info *) (pos + (sizeof (*reloc_info) * i));
        translate_relocation (part->reloc_arr + i, reloc_info, part, aout_exec);
    
    }
    
    pos += array_to_integer (aout_exec->a_trsize, 4);
    part = part_p_array[2];
    
    part->reloc_cnt = array_to_integer (aout_exec->a_drsize, 4) / sizeof (*reloc_info);
    part->reloc_arr = xmalloc (sizeof (*part->reloc_arr) * part->reloc_cnt);
    
    for (i = 0; i < part->reloc_cnt; i++) {
    
        reloc_info = (struct aout_relocation_info *) (pos + (sizeof (*reloc_info) * i));
        translate_relocation (part->reloc_arr + i, reloc_info, part, aout_exec);
    
    }

}


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
    struct aout_relocation_info rel;
    
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
            
            integer_to_array (part->rva - part->section->rva + part->reloc_arr[i].offset, rel.r_address, 4);
            
            if (!symbol->part || strcmp (symbol->part->section->name, ".text") == 0) {
                r_symbolnum = N_TEXT;
            } else if (strcmp (symbol->part->section->name, ".data") == 0) {
                r_symbolnum = N_DATA;
            } else if (strcmp (symbol->part->section->name, ".bss") == 0) {
                r_symbolnum = N_BSS;
            } else {
                r_symbolnum = N_TEXT;
            }
            
            if ((part->reloc_arr[i].symbolnum >> 27) & 1) {
            
                /*report_at (part->of->filename, 0, REPORT_INTERNAL_ERROR, "symbolnum: %lx", part->reloc_arr[i].symbolnum);*/
                r_symbolnum |= (1LU << 27);
            
            }
            
            integer_to_array (r_symbolnum | (size_log2 << 25), rel.r_symbolnum, 4);
            
            memcpy (pos, &rel, sizeof (rel));
            pos += sizeof (rel);
        
        }
    
    }
    
    return pos;

}

void aout_write (const char *filename) {

    FILE *fp;
    
    unsigned char *data, *pos;
    unsigned long data_size;
    
    struct section *text_section, *data_section, *bss_section;
    
    struct aout_exec exec;
    memset (&exec, 0, sizeof (exec));
    
    if (!(fp = fopen (filename, "wb"))) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to open '%s' for writing", filename);
        return;
    
    }
    
    text_section = section_find (".text");
    data_section = section_find (".data");
    bss_section  = section_find (".bss");
    
    integer_to_array (OMAGIC, exec.a_info, 4);
    
    if (data_section) {
    
        integer_to_array (data_section->rva, exec.a_text, 4);
        
        if (bss_section) {
            integer_to_array (bss_section->rva - data_section->rva, exec.a_data, 4);
        } else {
            integer_to_array (data_section->total_size, exec.a_data, 4);
        }
    
    } else {
    
        integer_to_array (0, exec.a_data, 4);
        
        if (bss_section) {
            integer_to_array (bss_section->rva, exec.a_text, 4);
        } else {
            integer_to_array (text_section ? text_section->total_size : 0, exec.a_text, 4);
        }
    
    }
    
    integer_to_array (bss_section ? bss_section->total_size : 0, exec.a_bss, 4);
    integer_to_array (state->entry_point, exec.a_entry, 4);
    
    if (text_section) {
        integer_to_array (section_get_num_relocs (text_section) * sizeof (struct aout_relocation_info), exec.a_trsize, 4);
    }
    
    if (data_section) {
        integer_to_array (section_get_num_relocs (data_section) * sizeof (struct aout_relocation_info), exec.a_drsize, 4);
    }
    
    data_size = sizeof (exec);
    
    data_size += (array_to_integer (exec.a_text, 4) + array_to_integer (exec.a_data, 4));
    data_size += (array_to_integer (exec.a_trsize, 4) + array_to_integer (exec.a_drsize, 4));
    
    data_size += 4;
    
    data = xmalloc (data_size);
    memcpy (data, &exec, sizeof (exec));
    
    pos = data + sizeof (exec);
    
    if (text_section) {
        section_write (text_section, pos);
    }
    
    pos += array_to_integer (exec.a_text, 4);
    
    if (data_section) {
        section_write (data_section, pos);
    }
    
    pos += array_to_integer (exec.a_data, 4);
    
    if (text_section) {
        pos = write_relocs_for_section (pos, text_section);
    }
    
    if (data_section) {
        pos = write_relocs_for_section (pos, data_section);
    }
    
    integer_to_array (4, pos, 4);
    
    if (fwrite (data, data_size, 1, fp) != 1) {
        report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", filename);
    }
    
    free (data);
    fclose (fp);

}
