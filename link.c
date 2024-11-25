/******************************************************************************
 * @file            link.c
 *****************************************************************************/
#include    <limits.h>
#include    <string.h>

#include    "ld.h"
#include    "lib.h"
#include    "pe.h"
#include    "reloc.h"
#include    "report.h"
#include    "section.h"
#include    "symbol.h"

struct reloc_howto reloc_howtos[RELOC_TYPE_END] = {

    {   0,  0,  0,  0,  0,  "RELOC_TYPE_IGNORED",   0,  0   },
    
    {   8,  0,  0,  0,  0,  "RELOC_TYPE_64",        0,  0   },
    {   8,  1,  0,  0,  0,  "RELOC_TYPE_PC64",      0,  0   },
    
    {   4,  0,  0,  0,  0,  "RELOC_TYPE_32",        0,  0   },
    {   4,  1,  0,  0,  0,  "RELOC_TYPE_PC32",      0,  0   },
    
    {   2,  0,  0,  0,  0,  "RELOC_TYPE_16",        0,  0   },
    {   2,  1,  0,  0,  0,  "RELOC_TYPE_PC16",      0,  0   },
    
    {   1,  0,  0,  0,  0,  "RELOC_TYPE_8",         0,  0   },
    {   1,  1,  0,  0,  0,  "RELOC_TYPE_PC8",       0,  0   }

};

static void check_unresolved (void) {

    struct object_file *of;
    struct symbol *symbol;
    
    unsigned long i;
    unsigned long unresolved = 0;
    
    for (of = all_object_files; of; of = of->next) {
    
        for (i = 0; i < of->symbol_cnt; i++) {
        
            symbol = of->symbol_arr + i;
            
            if (symbol->auxiliary || !symbol_is_undefined (symbol) || (symbol->flags & SYMBOL_FLAG_SECTION_SYMBOL) || !symbol->name) {
                continue;
            }
            
            if (!(symbol = symbol_find (symbol->name))) {
            
                symbol = of->symbol_arr + i;
                report_at (program_name, 0, REPORT_INTERNAL_ERROR, "external symbol '%s' not found in hashtab", symbol->name);
            
            }
            
            if (symbol_is_undefined (symbol)) {
            
                report_at (program_name, 0, REPORT_ERROR, "%s: unresolved external symbol '%s'", of->filename, symbol->name);
                unresolved++;
            
            }
        
        }
    
    }
    
    if (unresolved) {
        report_at (program_name, 0, REPORT_FATAL_ERROR, "%lu unresolved external%s", unresolved, (unresolved > 1 ? "s" : ""));
    }

}

static void collapse_subsections (void) {

    struct section *section;
    struct subsection *subsection;
    
    for (section = all_sections; section; section = section->next) {
    
        for (subsection = section->all_subsections; subsection; subsection = subsection->next) {
        
            if (subsection->first_part) {
            
                *section->last_part_p = subsection->first_part;
                section->last_part_p = subsection->last_part_p;
            
            }
        
        }
    
    }

}

static void calculate_section_sizes_and_rvas (void) {

    struct section *section;
    struct section_part *part;
    
    unsigned long rva = 0;
    
    if (state->format == LD_FORMAT_I386_PE) {
        rva = pe_get_first_section_rva ();
    }
    
    for (section = all_sections; section; section = section->next) {
    
        rva = ALIGN (rva, section->section_alignment);
        
        section->rva = rva;
        section->total_size = 0;
        
        for (part = section->first_part; part; part = part->next) {
        
            if (part->next && part->next->alignment > 1) {
            
                unsigned long new_rva = ALIGN (rva + part->content_size, part->next->alignment);
                
                if (new_rva != rva + part->content_size) {
                
                    part->content = xrealloc (part->content, new_rva - rva);
                    memset (part->content + part->content_size, 0, new_rva - rva - part->content_size);
                    
                    part->content_size = new_rva - rva;
                
                }
            
            }
            
            part->rva = rva;
            
            section->total_size += part->content_size;
            rva += part->content_size;
        
        }
    
    }

}

static void reloc_generic (struct section_part *part, struct reloc_entry *rel, struct symbol *symbol) {

    unsigned long result = 0;
    
    switch (rel->howto->size) {
    
        case 8: {
        
            result = array_to_integer (part->content + rel->offset, 8);
            break;
        
        }
        
        case 4: {
        
            result = array_to_integer (part->content + rel->offset, 4);
            break;
        
        }
        
        case 3: {
        
            result = array_to_integer (part->content + rel->offset, 3);
            break;
        
        }
        
        case 2: {
        
            result = array_to_integer (part->content + rel->offset, 2);
            break;
        
        }
        
        case 1: {
        
            result = array_to_integer (part->content + rel->offset, 1);
            break;
        
        }
        
        default: {
        
            report_at (program_name, 0, REPORT_INTERNAL_ERROR, "invalid relocation size");
            break;
        
        }
    
    }
    
    result += rel->addend;
    
    if (rel->howto->pc_rel || rel->howto->no_base) {
    
        result += symbol_get_value_no_base (symbol);
        
        if (rel->howto->pc_rel) {
        
            result -= (part->rva + rel->offset);
            result -= rel->howto->size;
        
        }
    
    } else {
        result += symbol_get_value_with_base (symbol);
    }
    
    if ((unsigned long) rel->howto->size < sizeof (result)) {
    
        unsigned long mask = (((unsigned long) 1) << (CHAR_BIT * rel->howto->size)) - 1;
        result &= mask;
    
    }
    
    result >>= rel->howto->final_right_shift;
    
    switch (rel->howto->size) {
    
        case 8: {
        
            integer_to_array (result, part->content + rel->offset, 8);
            break;
        
        }
        
        case 4: {
        
            integer_to_array (result, part->content + rel->offset, 4);
            break;
        
        }
        
        case 3: {
        
            integer_to_array (result, part->content + rel->offset, 3);
            break;
        
        }
        
        case 2: {
        
            integer_to_array (result, part->content + rel->offset, 2);
            break;
        
        }
        
        case 1: {
        
            integer_to_array (result, part->content + rel->offset, 1);
            break;
        
        }
        
        default: {
        
            report_at (program_name, 0, REPORT_INTERNAL_ERROR, "invalid relocation size");
            break;
        
        }
    
    }

}

static void relocate_part (struct section_part *part) {

    struct reloc_entry *relocs = part->reloc_arr;
    
    struct symbol *symbol;
    unsigned long i;
    
    for (i = 0; i < part->reloc_cnt; i++) {
    
        if (relocs[i].howto->size == 0) {
            continue;
        }
        
        symbol = relocs[i].symbol;
        
        if (symbol_is_undefined (symbol)) {
        
            if (!(symbol = symbol_find (symbol->name))) {
            
                symbol = relocs[i].symbol;
                report_at (program_name, 0, REPORT_INTERNAL_ERROR, "external symbol '%s' not found in hashtab", symbol->name);
            
            }
            
            if (symbol_is_undefined (symbol)) {
            
                report_at (program_name, 0, REPORT_ERROR, "%s:(%s+%#lu): undefined reference to '%s'", part->of->filename, part->section->name, relocs[i].offset, symbol->name);
                continue;
            
            }
        
        }
        
        if (relocs[i].howto->special_function) {
        
            (*relocs[i].howto->special_function) (part, &relocs[i], symbol);
            continue;
        
        }
        
        reloc_generic (part, &relocs[i], symbol);
    
    }

}

static void relocate_sections (void) {

    struct section *section;
    struct section_part *part;
    
    for (section = all_sections; section; section = section->next) {
    
        for (part = section->first_part; part; part = part->next) {
            relocate_part (part);
        }
    
    }

}

static void calculate_entry_point (void) {

    struct symbol *symbol;
    struct section *section;
    
    if (state->entry_symbol_name) {
    
        if (state->entry_symbol_name[0] == '\0') {
        
            state->entry_point -= state->base_address;
            return;
        
        }
        
        if ((symbol = symbol_find (state->entry_symbol_name)) && !symbol_is_undefined (symbol)) {
        
            state->entry_point = symbol_get_value_no_base (symbol);
            return;
        
        }
    
    }
    
    if (!state->entry_symbol_name) {
    
        if (state->format == LD_FORMAT_I386_AOUT || state->format == LD_FORMAT_I386_ELKS || state->format == LD_FORMAT_IA16_ELKS) {
        
            state->entry_symbol_name = xstrdup ("_start");
            
            if ((symbol = symbol_find (state->entry_symbol_name))) {
            
                state->entry_point = symbol_get_value_no_base (symbol);
                return;
            
            }
        
        } else if (state->format == LD_FORMAT_I386_PE) {
        
            state->entry_symbol_name = xstrdup ("_mainCRTStartup");
            
            if ((symbol = symbol_find (state->entry_symbol_name))) {
            
                state->entry_point = symbol_get_value_no_base (symbol);
                return;
            
            }
        
        }
    
    }
    
    if ((section = section_find (".text"))) {
        state->entry_point = section->rva;
    }
    
    if (state->entry_symbol_name) {
        report_at (program_name, 0, REPORT_WARNING, "cannot find entry symbol '%s'; defaulting to 0x%08lx", state->entry_symbol_name, state->base_address + state->entry_point);
    }

}

void link (void) {

    struct section *section;
    unsigned long value = 0;
    
    struct object_file *of;
    struct symbol *symbol;
    
    collapse_subsections ();
    calculate_section_sizes_and_rvas ();
    
    if (!(symbol = symbol_find ("__edata")) || symbol_is_undefined (symbol)) {
    
        if ((section = section_find (".text"))) {
        
            value += (/*section->rva + */section->total_size);
            /*value -= state->size_of_headers;*/
        
        }
        
        of = object_file_make (FAKE_LD_FILENAME, 1);
        
        symbol = of->symbol_arr;
        symbol->name = xstrdup ("__edata");
        
        symbol->section_number = ABSOLUTE_SECTION_NUMBER;
        symbol->value = value / 16;
        
        symbol_record_external_symbol (symbol);
        value %= 16;
    
    }
    
    if (!(symbol = symbol_find ("__end")) || symbol_is_undefined (symbol)) {
    
        if ((section = section_find (".data"))) {
            value += section->total_size;
        }
        
        if ((section = section_find (".bss"))) {
            value += section->total_size;
        }
        
        of = object_file_make (FAKE_LD_FILENAME, 1);
        
        symbol = of->symbol_arr;
        symbol->name = xstrdup ("__end");
        
        symbol->section_number = ABSOLUTE_SECTION_NUMBER;
        symbol->value = value % 16;
        
        symbol_record_external_symbol (symbol);
    
    }
    
    check_unresolved ();
    
    relocate_sections ();
    calculate_entry_point ();

}
