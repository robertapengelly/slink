/******************************************************************************
 * @file            elks.c
 *****************************************************************************/
#include    <string.h>

#include    "elks.h"
#include    "ld.h"
#include    "lib.h"
#include    "reloc.h"
#include    "report.h"
#include    "section.h"
#include    "symbol.h"

static void translate_relocation (const char *filename, struct reloc_entry *reloc, struct elks_relocation_info *input_reloc, struct section_part *part, struct elks_exec *exec_p) {

    unsigned long r_symbolnum = array_to_integer (input_reloc->r_symbolnum, 4);
    
    unsigned long r_address = array_to_integer (input_reloc->r_address, 4);
    long symbolnum = (r_symbolnum & 0x7ffffff);
    
    if ((r_symbolnum >> 31) & 1) {      /* ext */
        reloc->symbol = part->of->symbol_arr + symbolnum;
    } else {
    
        if (state->format == LD_FORMAT_BIN || state->format == LD_FORMAT_COM) {
        
            if ((((r_symbolnum & (3 << 29)) >> 28) & 0xff) != N_ABS) {
                report_at (program_name, 0, REPORT_ERROR, "%s: segment relocation at %04x:%04x", filename, r_address / 0xffff, r_address % 0xffff);
            }
        
        }
        
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
    
    reloc->offset = r_address;
    
    switch (1U << ((r_symbolnum >> 29) & 3)) {
    
        case 8:
        
            if ((r_symbolnum >> 28) & 1) {
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_PC64];
                reloc->addend += reloc->offset + 8;
            
            } else {
                reloc->howto = &reloc_howtos[RELOC_TYPE_64];
            }
            
            break;
        
        case 4:
        
            if ((r_symbolnum >> 28) & 1) {
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                reloc->addend += reloc->offset + 4;
            
            } else {
                reloc->howto = &reloc_howtos[RELOC_TYPE_32];
            }
            
            break;
        
        case 2:
        
            if ((r_symbolnum >> 28) & 1) {
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_PC16];
                reloc->addend += reloc->offset + 2;
            
            } else {
                reloc->howto = &reloc_howtos[RELOC_TYPE_16];
            }
            
            break;
        
        case 1:
        
            if ((r_symbolnum >> 28) & 1) {
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_PC8];
                reloc->addend += reloc->offset + 4;
            
            } else {
                reloc->howto = &reloc_howtos[RELOC_TYPE_8];
            }
            
            break;
    
    }

}

void read_elks_object (const char *filename, unsigned char *data, unsigned long data_size) {

    struct elks_exec *elks_exec;
    struct elks_nlist *elks_nlist;
    
    const char *strtab;
    unsigned long strtab_size;
    
    unsigned long num_symbols;
    unsigned long i;
    
    struct section_part *part, *part_p_array[4] = { 0 };
    struct section *section, *bss_section;
    
    struct symbol *symbol, *old_symbol;
    struct section_part *bss_part;
    
    struct elks_relocation_info *reloc_info;
    struct object_file *of;
    
    unsigned char *pos = data;
    
    if ((pos - data + sizeof (*elks_exec) > data_size) || pos < data) {
    
        report_at (program_name, 0, REPORT_FATAL_ERROR, "corrupted input file");
        return;
    
    }
    
    elks_exec = (struct elks_exec *) pos;
    pos += sizeof (*elks_exec);
    
    num_symbols = array_to_integer (elks_exec->a_syms, 4) / sizeof (*elks_nlist);
    of = object_file_make (filename, num_symbols + 4);
    
    section = section_find_or_make (".text");
    section->flags = SECTION_FLAG_ALLOC | SECTION_FLAG_LOAD | SECTION_FLAG_READONLY | SECTION_FLAG_CODE;
    
    part = section_part_new (section, of);
    
    part->content_size = array_to_integer (elks_exec->a_text, 4);
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
    
    part->content_size = array_to_integer (elks_exec->a_data, 4);
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
    part->content_size = array_to_integer (elks_exec->a_bss, 4);
    
    section_append_section_part (section, part);
    part_p_array[3] = part;
    
    pos += array_to_integer (elks_exec->a_syms, 4) + array_to_integer (elks_exec->a_trsize, 4) + array_to_integer (elks_exec->a_drsize, 4);
    
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
    
    pos -= array_to_integer (elks_exec->a_syms, 4);
    
    for (i = 0; i < num_symbols; i++) {
    
        elks_nlist = (struct elks_nlist *) (pos + (i * sizeof (*elks_nlist)));
        symbol = of->symbol_arr + i;
        
        if (array_to_integer (elks_nlist->n_strx, 4) < strtab_size) {
            symbol->name = xstrdup (strtab + array_to_integer (elks_nlist->n_strx, 4));
        } else {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid offset into string table", filename);
            return;
        
        }
        
        symbol->value = array_to_integer (elks_nlist->n_value, 4);
        symbol->size = 0;
        
        if ((elks_nlist->n_type & N_TYPE) == N_UNDF || (elks_nlist->n_type & N_TYPE) == N_COMM) {
        
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
        
        } else if ((elks_nlist->n_type & N_TYPE) == N_ABS) {
        
            symbol->section_number = ABSOLUTE_SECTION_NUMBER;
            symbol->part = 0;
        
        } else if ((elks_nlist->n_type & N_TYPE) == N_TEXT) {
        
            symbol->section_number = 1;
            symbol->part = part_p_array[1];
        
        } else if ((elks_nlist->n_type & N_TYPE) == N_DATA) {
        
            symbol->section_number = 2;
            symbol->part = part_p_array[2];
            symbol->value -= array_to_integer (elks_exec->a_text, 4);
        
        } else if ((elks_nlist->n_type & N_TYPE) == N_BSS) {
        
            symbol->section_number = 3;
            symbol->part = part_p_array[3];
            symbol->value -= (array_to_integer (elks_exec->a_text, 4) + array_to_integer (elks_exec->a_data, 4));
        
        } else {
        
            report_at (program_name, 0, REPORT_INTERNAL_ERROR, "unsupported nlist.n_type: %#x", elks_nlist->n_type);
            return;
        
        }
        
        if ((elks_nlist->n_type & N_EXT) || (elks_nlist->n_type & N_TYPE) == N_UNDF || (elks_nlist->n_type & N_TYPE) == N_COMM) {
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
    
    pos -= (array_to_integer (elks_exec->a_trsize, 4) + array_to_integer (elks_exec->a_drsize, 4));
    part = part_p_array[1];
    
    part->reloc_cnt = array_to_integer (elks_exec->a_trsize, 4) / sizeof (*reloc_info);
    part->reloc_arr = xmalloc (sizeof (*part->reloc_arr) * part->reloc_cnt);
    
    for (i = 0; i < part->reloc_cnt; i++) {
    
        reloc_info = (struct elks_relocation_info *) (pos + (sizeof (*reloc_info) * i));
        translate_relocation (filename, part->reloc_arr + i, reloc_info, part, elks_exec);
    
    }
    
    pos += array_to_integer (elks_exec->a_trsize, 4);
    part = part_p_array[2];
    
    part->reloc_cnt = array_to_integer (elks_exec->a_drsize, 4) / sizeof (*reloc_info);
    part->reloc_arr = xmalloc (sizeof (*part->reloc_arr) * part->reloc_cnt);
    
    for (i = 0; i < part->reloc_cnt; i++) {
    
        reloc_info = (struct elks_relocation_info *) (pos + (sizeof (*reloc_info) * i));
        translate_relocation (filename, part->reloc_arr + i, reloc_info, part, elks_exec);
    
    }

}
