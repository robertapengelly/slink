/******************************************************************************
 * @file            link.c
 *****************************************************************************/
#include    <limits.h>
#include    <stdio.h>
#include    <stdint.h>
#include    <stdlib.h>
#include    <string.h>

#include    "elf.h"
#include    "ld.h"
#include    "lib.h"
#include    "macho.h"
#include    "pe.h"
#include    "reloc.h"
#include    "report.h"
#include    "section.h"
#include    "symbol.h"

static uint64_t generic_read (struct section_part *part, struct reloc_entry *rel) {

    uint64_t result;
    int endianess = 0;
    
    switch (rel->howto->size) {
    
        case 8:
        
            result = array_to_integer (part->content + rel->offset, 8, endianess);
            break;
        
        case 4:
        
            result = array_to_integer (part->content + rel->offset, 4, endianess);
            break;
        
        case 3:
        
            result = array_to_integer (part->content + rel->offset, 3, endianess);
            break;
        
        case 2:
        
            result = array_to_integer (part->content + rel->offset, 2, endianess);
            break;
        
        case 1:
        
            result = array_to_integer (part->content + rel->offset, 1, endianess);
            break;
        
        default:
        
            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "invalid relocation size");
            exit (EXIT_FAILURE);
    
    }
    
    return result;

}

static void generic_write (struct section_part *part, struct reloc_entry *rel, uint64_t result) {

    int endianess = 0;
    
    switch (rel->howto->size) {
    
        case 8:
        
            integer_to_array (result, part->content + rel->offset, 8, endianess);
            break;
        
        case 4:
        
            integer_to_array (result, part->content + rel->offset, 4, endianess);
            break;
        
        case 3:
        
            integer_to_array (result, part->content + rel->offset, 3, endianess);
            break;
        
        case 2:
        
            integer_to_array (result, part->content + rel->offset, 2, endianess);
            break;
        
        case 1:
        
            integer_to_array (result, part->content + rel->offset, 1, endianess);
            break;
        
        default:
        
            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "invalid relocation size");
            exit (EXIT_FAILURE);
    
    }

}

static void reloc_generic_add (struct section_part *part, struct reloc_entry *rel, struct symbol *symbol) {

    uint64_t result, saved;
    
    saved = generic_read (part, rel);
    result = rel->addend;
    
    if (rel->howto->pc_rel || rel->howto->no_base) {
        result += symbol_get_value_no_base (symbol);
    } else {
        result += symbol_get_value_with_base (symbol);
    }
    
    if (rel->howto->pc_rel) {
    
        result -= part->rva + rel->offset;
        result -= rel->howto->size;
    
    }
    
    if (rel->howto->size < (int) sizeof (result)) {
    
        uint64_t mask = (((uint64_t) 1) << (CHAR_BIT * rel->howto->size)) - 1;
        result &= mask;
    
    }
    
    if (rel->howto->final_right_shift) {
    
        /* If the result was negative, it should remain negative even after the final right shift. */
        uint64_t sign_bit = result & (((uint64_t) 1) << (rel->howto->size * 8 - 1));
        
        result >>= rel->howto->final_right_shift;
        result |= sign_bit;
    
    }
    
    generic_write (part, rel, saved + result);

}

static void reloc_generic_subtract (struct section_part *part, struct reloc_entry *rel, struct symbol *symbol) {

    uint64_t result, saved;
    
    saved = generic_read (part, rel);
    result = rel->addend;
    
    if (rel->howto->pc_rel || rel->howto->no_base) {
        result += symbol_get_value_no_base (symbol);
    } else {
        result += symbol_get_value_with_base (symbol);
    }
    
    if (rel->howto->pc_rel) {
    
        result -= part->rva + rel->offset;
        result -= rel->howto->size;
    
    }
    
    if (rel->howto->size < (int) sizeof (result)) {
    
        uint64_t mask = (((uint64_t) 1) << (CHAR_BIT * rel->howto->size)) - 1;
        result &= mask;
    
    }
    
    if (rel->howto->final_right_shift) {
    
        /* If the result was negative, it should remain negative even after the final right shift. */
        uint64_t sign_bit = result & (((uint64_t) 1) << (rel->howto->size * 8 - 1));
        
        result >>= rel->howto->final_right_shift;
        result |= sign_bit;
    
    }
    
    generic_write (part, rel, saved - result);

}

static void reloc_aarch64_hi21_page_pcrel (struct section_part *part, struct reloc_entry *rel, struct symbol *symbol) {

    uint64_t bottom_2_bits = 0, result;
    unsigned long field;
    
    result = (symbol_get_value_with_base (symbol) + rel->addend) & ~(uint64_t) 0xfff;
    result -= (state->base_address + part->rva + rel->offset) & ~(uint64_t) 0xfff;
    
    if ((bottom_2_bits = result & 0x3000)) {
    
        result &= ~bottom_2_bits;
        bottom_2_bits >>= 12;
    
    }
    
    result >>= 9;
    
    /**
     * If the result is negative, those 2 bits are already set,
     * so they must be cleared before putting the real bottom 2 bits there.
     */
    result &= ~(((uint64_t) 0x03) << 29);
    result |= bottom_2_bits << 29;
    
    field = array_to_integer (part->content + rel->offset, 4, 0);
    field = ((field & ~(uint64_t) rel->howto->dst_mask) | (((field & rel->howto->dst_mask) + result) & rel->howto->dst_mask));
    
    integer_to_array (field, part->content + rel->offset, 4, 0);

}

static void reloc_aarch64_generic (struct section_part *part, struct reloc_entry *rel, struct symbol *symbol) {

    uint64_t result = rel->addend, field;
    result += symbol_get_value_with_base (symbol);
    
    if (rel->howto->pc_rel) {
        result -= state->base_address + part->rva + rel->offset;
    }
    
    result >>= rel->howto->final_right_shift;
    result <<= rel->howto->final_left_shift;
    
    switch (rel->howto->size) {
    
        case 8:
        
            field = array_to_integer (part->content + rel->offset, 8, 0);
            break;
        
        case 4:
        
            field = array_to_integer (part->content + rel->offset, 4, 0);
            break;
        
        case 2:
        
            field = array_to_integer (part->content + rel->offset, 2, 0);
            break;
        
        default:
        
            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "invalid relocation size");
            exit (EXIT_FAILURE);
    
    }

    field = ((field & ~(uint64_t) rel->howto->dst_mask) | (((field & rel->howto->dst_mask) + result) & rel->howto->dst_mask));
    
    switch (rel->howto->size) {
    
        case 8:
        
            integer_to_array (field, part->content + rel->offset, 8, 0);
            break;
        
        case 4:
        
            integer_to_array (field, part->content + rel->offset, 4, 0);
            break;
        
        case 2:
        
            integer_to_array (field, part->content + rel->offset, 2, 0);
            break;
        
        default:
        
            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "invalid relocation size");
            exit (EXIT_FAILURE);
    
    }

}

struct reloc_howto reloc_howtos[RELOC_TYPE_END] = {

    {   0,  0,  0,  0,  0,  "RELOC_TYPE_IGNORED",       0,  0   },
    
    {   8,  0,  0,  0,  0,  "RELOC_TYPE_64",            0,  0   },
    {   4,  0,  0,  0,  0,  "RELOC_TYPE_32",            0,  0   },
    {   2,  0,  0,  0,  0,  "RELOC_TYPE_16",            0,  0   },
    {   1,  0,  0,  0,  0,  "RELOC_TYPE_8",             0,  0   },
    
    {   8,  1,  0,  0,  0,  "RELOC_TYPE_PC64",          0,  0   },
    {   4,  1,  0,  0,  0,  "RELOC_TYPE_PC32",          0,  0   },
    {   2,  1,  0,  0,  0,  "RELOC_TYPE_PC16",          0,  0   },
    {   1,  1,  0,  0,  0,  "RELOC_TYPE_PC8",           0,  0   },
    
    {   4,  0,  1,  0,  0,  "RELOC_TYPE_32_NO_BASE",    0,  0   },
    
    {   8,  0,  0,  0,  &reloc_generic_add,     "RELOC_TYPE_64_ADD",    0,  0   },
    {   4,  0,  0,  0,  &reloc_generic_add,     "RELOC_TYPE_32_ADD",    0,  0   },
    {   3,  0,  0,  0,  &reloc_generic_add,     "RELOC_TYPE_24_ADD",    0,  0   },
    {   2,  0,  0,  0,  &reloc_generic_add,     "RELOC_TYPE_16_ADD",    0,  0   },
    {   1,  0,  0,  0,  &reloc_generic_add,     "RELOC_TYPE_8_ADD",     0,  0   },

    {   8,  0,  0,  0,  &reloc_generic_subtract,    "RELOC_TYPE_64_SUB",    0,  0   },
    {   4,  0,  0,  0,  &reloc_generic_subtract,    "RELOC_TYPE_32_SUB",    0,  0   },
    {   3,  0,  0,  0,  &reloc_generic_subtract,    "RELOC_TYPE_24_SUB",    0,  0   },
    {   2,  0,  0,  0,  &reloc_generic_subtract,    "RELOC_TYPE_16_SUB",    0,  0   },
    {   1,  0,  0,  0,  &reloc_generic_subtract,    "RELOC_TYPE_8_SUB",     0,  0   },
    
    {   4,  1,  0,  9,  &reloc_aarch64_hi21_page_pcrel,     "RELOC_TYPE_AARCH64_ADR_PREL_PG_HI21",      0x60ffffe0,     0   },
    {   4,  0,  0,  0,  &reloc_aarch64_generic,             "RELOC_TYPE_AARCH64_ADD_ABS_LO12_NC",       0x3ffc00,       10  },
    {   4,  0,  0,  0,  &reloc_aarch64_generic,             "RELOC_TYPE_AARCH64_LDST8_ABS_LO12_NC",     0x3ffc00,       10  },
    {   4,  0,  0,  1,  &reloc_aarch64_generic,             "RELOC_TYPE_AARCH64_LDST16_ABS_LO12_NC",    0x1ffc00,       10  },
    {   4,  0,  0,  2,  &reloc_aarch64_generic,             "RELOC_TYPE_AARCH64_LDST32_ABS_LO12_NC",    0xffc00,        10  },
    {   4,  0,  0,  3,  &reloc_aarch64_generic,             "RELOC_TYPE_AARCH64_LDST64_ABS_LO12_NC",    0x7fc00,        10  },
    {   4,  0,  0,  4,  &reloc_aarch64_generic,             "RELOC_TYPE_AARCH64_LDST128_ABS_LO12_NC",   0x3fc00,        10  },
    {   4,  1,  0,  2,  &reloc_aarch64_generic,             "RELOC_TYPE_AARCH64_JUMP26",                0x3ffffff,      0   },
    {   4,  1,  0,  2,  &reloc_aarch64_generic,             "RELOC_TYPE_AARCH64_CALL26",                0x3ffffff,      0   }

};

static unsigned long dgroup_start = 0;
static int has_dgroup = 0;

static unsigned long align_section_if_needed (unsigned long value) {

    if (state->format == LD_FORMAT_I386_PE || state->format == LD_FORMAT_AMD64_PE) {
        return pe_align_to_file_alignment (value);
    }
    
    return value;

}

static void output_symbols (void) {

    struct section *section = section_find_or_make (".data");
    
    struct object_file *of;
    struct symbol *symbol;
    
    struct section_part *part = section_part_new (section, 0);
    unsigned long pos = 0, i;
    
    for (of = all_object_files; of; of = of->next) {
    
        for (i = 0; i < of->symbol_cnt; i++) {
        
            symbol = of->symbol_arr + i;
            
            if (symbol->auxiliary || symbol_is_undefined (symbol) || (symbol->flags & SYMBOL_FLAG_SECTION_SYMBOL) || !symbol->name) {
                continue;
            }
            
            if (!(symbol = symbol_find (symbol->name))) {
                continue;
            }
            
            part->content_size += (strlen (symbol->name) + 1);
        
        }
    
    }
    
    if (!part->content_size) {
    
        free (part);
        return;
    
    }
    
    part->content = xmalloc (part->content_size);
    
    for (of = all_object_files; of; of = of->next) {
    
        for (i = 0; i < of->symbol_cnt; i++) {
        
            symbol = of->symbol_arr + i;
            
            if (symbol->auxiliary || symbol_is_undefined (symbol) || (symbol->flags & SYMBOL_FLAG_SECTION_SYMBOL) || !symbol->name) {
                continue;
            }
            
            if (!(symbol = symbol_find (symbol->name))) {
                continue;
            }
            
            pos += (sprintf ((char *) part->content + pos, "%s", symbol->name) + 1);
        
        }
    
    }
    
    section_append_section_part (section, part);

}

static unsigned long generate_symbols_table (unsigned long offset) {

    struct section *section = section_find_or_make (".data");
    
    struct object_file *of;
    struct symbol *symbol;
    
    struct section_part *part = section_part_new (section, 0);
    unsigned long pos = 0, i;
    
    for (of = all_object_files; of; of = of->next) {
    
        for (i = 0; i < of->symbol_cnt; i++) {
        
            symbol = of->symbol_arr + i;
            
            if (symbol->auxiliary || symbol_is_undefined (symbol) || (symbol->flags & SYMBOL_FLAG_SECTION_SYMBOL) || !symbol->name) {
                continue;
            }
            
            if (!(symbol = symbol_find (symbol->name))) {
                continue;
            }
            
            part->content_size += 8;
        
        }
    
    }
    
    if (!part->content_size) {

        free (part);
        return 0;

    }
    
    part->content = xmalloc (part->content_size);
    
    for (of = all_object_files; of; of = of->next) {
    
        for (i = 0; i < of->symbol_cnt; i++) {
        
            symbol = of->symbol_arr + i;
            
            if (symbol->auxiliary || symbol_is_undefined (symbol) || (symbol->flags & SYMBOL_FLAG_SECTION_SYMBOL) || !symbol->name) {
                continue;
            }
            
            if (!(symbol = symbol_find (symbol->name))) {
                continue;
            }
            
            integer_to_array (symbol_get_value_no_base (symbol), part->content + pos, 4, 0);
            pos += 4;
            
            integer_to_array (offset, part->content + pos, 4, 0);
            pos += 4;
            
            offset += strlen (symbol->name) + 1;
        
        }
    
    }
    
    section_append_section_part (section, part);
    return part->content_size;

}

static void check_unresolved (void) {

    struct object_file *of;
    struct symbol *symbol;
    
    unsigned long unresolved = 0;
    unsigned long i;
    
    for (of = all_object_files; of; of = of->next) {
    
        for (i = 0; i < of->symbol_cnt; i++) {
        
            symbol = of->symbol_arr + i;
            
            if (symbol->auxiliary || !symbol_is_undefined (symbol) || (symbol->flags & SYMBOL_FLAG_SECTION_SYMBOL) || !symbol->name) {
                continue;
            }
            
            if (!(symbol = symbol_find (symbol->name))) {
            
                symbol = of->symbol_arr + i;
                
                report_at (program_name, 0, REPORT_INTERNAL_ERROR, "external symbol '%s' not found in hashtab", symbol->name);
                exit (EXIT_FAILURE);
            
            }
            
            if (symbol_is_undefined (symbol)) {
            
                report_at (program_name, 0, REPORT_ERROR, "%s: unresolved external symbol '%s'", of->filename, symbol->name);
                unresolved++;
            
            }
        
        }
    
    }
    
    if (unresolved) {
    
        report_at (program_name, 0, REPORT_FATAL_ERROR, "%lu unresolved external%s", unresolved, (unresolved > 1 ? "s" : ""));
        exit (EXIT_FAILURE);
    
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
    
    uint64_t rva = 0;
    
    if (state->format == LD_FORMAT_AMD64_PE || state->format == LD_FORMAT_I386_PE) {
        rva = pe_get_first_section_rva ();
    } else if (state->format == LD_FORMAT_AMD64_MACHO || state->format == LD_FORMAT_AARCH64_MACHO) {
        rva = macho_get_first_section_rva ();
    } else if (state->format == LD_FORMAT_AMD64_ELF || state->format == LD_FORMAT_I386_ELF) {
        rva = elf_get_first_section_rva ();
    }
    
    for (section = all_sections; section; section = section->next) {
    
        rva = ALIGN (rva, section->section_alignment);
        
        section->rva = rva;
        section->total_size = 0;
        
        for (part = section->first_part; part; part = part->next) {
        
            if (part->next && part->next->alignment > 1) {
            
                uint64_t new_rva = ALIGN (rva + part->content_size, part->next->alignment);
                
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

    unsigned char opcode = (part->content + rel->offset - 1)[0];
    uint64_t result = 0, offset = rel->offset;
    
    switch (rel->howto->size) {
    
        case 8: {
        
            result = array_to_integer (part->content + offset, 8, 0);
            break;
        
        }
        
        case 4: {
        
            result = array_to_integer (part->content + offset, 4, 0);
            break;
        
        }
        
        case 3: {
        
            result = array_to_integer (part->content + offset, 3, 0);
            break;
        
        }
        
        case 2: {
        
            result = array_to_integer (part->content + offset, 2, 0);
            break;
        
        }
        
        case 1: {
        
            result = array_to_integer (part->content + offset, 1, 0);
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
        
            result -= (part->rva + offset);
            result -= rel->howto->size;
        
        }
    
    } else {
    
        result += symbol_get_value_with_base (symbol);
        
        if (state->format == LD_FORMAT_BIN || state->format == LD_FORMAT_COM) {
        
            if (symbol->section_number != ABSOLUTE_SECTION_NUMBER && !rel->n_ext) {
            
                if (rel->n_type != 2 && symbol->n_type != 2) {
                    report_at (program_name, 0, REPORT_ERROR, "%s:(%s+%#lu): segment relocation", part->of->filename, part->section->name, offset);
                }
            
            }
        
        } else if (state->format == LD_FORMAT_MZ) {
        
            if (xstrcasecmp (symbol->name, "DGROUP")) {
            
                int is_section = (xstrcasecmp (symbol->name, ".text") == 0) || (xstrcasecmp (symbol->name, ".data") == 0) || (xstrcasecmp (symbol->name, ".bss") == 0);
                
                if (is_section || (rel->n_type != 4 && rel->n_type != 6 && rel->n_type != 8) || rel->symbolnum == 0 || rel->symbolnum == 4 || rel->symbolnum == 8) {
                
                    if (rel->howto == &reloc_howtos[RELOC_TYPE_64]) {
                        rel->howto = &reloc_howtos[RELOC_TYPE_PC64];
                    } else if (rel->howto == &reloc_howtos[RELOC_TYPE_32]) {
                        rel->howto = &reloc_howtos[RELOC_TYPE_PC32];
                    } else if (rel->howto == &reloc_howtos[RELOC_TYPE_16]) {
                        rel->howto = &reloc_howtos[RELOC_TYPE_PC16];
                    } else if (rel->howto == &reloc_howtos[RELOC_TYPE_8]) {
                        rel->howto = &reloc_howtos[RELOC_TYPE_PC8];
                    }
                
                }
            
            }
        
        }
        
        if (xstrcasecmp (symbol->name, "DGROUP__edata") == 0 || xstrcasecmp (symbol->name, "DGROUP__end") == 0 || xstrcasecmp (symbol->name, "__etext") == 0 || xstrcasecmp (symbol->name, "__edata") == 0 || xstrcasecmp (symbol->name, "__end") == 0) {
        
            if (rel->howto == &reloc_howtos[RELOC_TYPE_64]) {
                rel->howto = &reloc_howtos[RELOC_TYPE_PC64];
            } else if (rel->howto == &reloc_howtos[RELOC_TYPE_32]) {
                rel->howto = &reloc_howtos[RELOC_TYPE_PC32];
            } else if (rel->howto == &reloc_howtos[RELOC_TYPE_16]) {
                rel->howto = &reloc_howtos[RELOC_TYPE_PC16];
            } else if (rel->howto == &reloc_howtos[RELOC_TYPE_8]) {
                rel->howto = &reloc_howtos[RELOC_TYPE_PC8];
            }
        
        }
    
    }
    
    if ((unsigned long) rel->howto->size < sizeof (result)) {
    
        unsigned long mask = (((uint64_t) 1) << (CHAR_BIT * rel->howto->size)) - 1;
        result &= mask;
    
    }
    
    if (rel->howto->final_right_shift) {
    
        uint64_t sign_bit = result & (((uint64_t) 1) << (rel->howto->size * 8 - 1));
        result >>= rel->howto->final_right_shift;
        
        result |= sign_bit;
    
    }
    
    if (state->emulation == LD_EMULATION_IA16_DX || state->emulation == LD_EMULATION_IA16_MZ) {
    
        if (opcode == 0x9A || opcode == 0xFF || rel->n_type == 4) {
        
            unsigned char *p = part->content + offset;
            /*printf ("relocating: %s: %s: %lx, %lx, %d\n", part->of->filename, symbol->name, part->rva + offset + 0x40, rel->symbolnum, rel->n_type);*/
            
            if ((opcode != 0x9A && opcode != 0xFF) || result >= 65535) {
            
                if (opcode == 0xFF) { *(p - 1) = 0x9A; }
                
                if (rel->howto == &reloc_howtos[RELOC_TYPE_PC64]) {
                    rel->howto = &reloc_howtos[RELOC_TYPE_64];
                } else if (rel->howto == &reloc_howtos[RELOC_TYPE_PC32]) {
                    rel->howto = &reloc_howtos[RELOC_TYPE_32];
                } else if (rel->howto == &reloc_howtos[RELOC_TYPE_PC16]) {
                    rel->howto = &reloc_howtos[RELOC_TYPE_16];
                } else if (rel->howto == &reloc_howtos[RELOC_TYPE_PC8]) {
                    rel->howto = &reloc_howtos[RELOC_TYPE_8];
                }
                
                while (rel->howto->size > 2) {
                    rel->howto->size--;
                }
                
                rel->offset += 2;
                
                if (result >= dgroup_start) {
                
                    unsigned long temp = result - (dgroup_start & 0xfffffff0);
                    result = (((unsigned long) dgroup_start / 16) << 16) | (unsigned long) temp;
                
                } else {
                    /*result = (((unsigned long) result / 16) << 16) | (unsigned long) result % 16;*/
                    result = (((unsigned long) result / 65536) << 16) | (unsigned long) result % 65536;
                }
                
                /*printf ("relocating: %s: %lx, %lx, %lx\n", rel->symbol->name, part->rva + offset + 0x60, result, size);*/
                rel->howto->size = 4;
            
            } else if (opcode == 0x9A || opcode == 0xFF) {
            
                if (rel->howto == &reloc_howtos[RELOC_TYPE_64]) {
                    rel->howto = &reloc_howtos[RELOC_TYPE_PC64];
                } else if (rel->howto == &reloc_howtos[RELOC_TYPE_32]) {
                    rel->howto = &reloc_howtos[RELOC_TYPE_PC32];
                } else if (rel->howto == &reloc_howtos[RELOC_TYPE_16]) {
                    rel->howto = &reloc_howtos[RELOC_TYPE_PC16];
                } else if (rel->howto == &reloc_howtos[RELOC_TYPE_8]) {
                    rel->howto = &reloc_howtos[RELOC_TYPE_PC8];
                }
                
                if (opcode == 0x9A) {
                
                    *(p - 1) = 0x0E;
                    *(p + 0) = 0xE8;
                    *(p + 3) = 0x90;
                    
                    result -= part->rva + offset;
                    result -= 4;
                    
                    while (rel->howto->size > 2) {
                        rel->howto->size--;
                    }
                    
                    offset++;
                    result++;
                
                } else {
                
                    *(p - 1) = 0x0E;
                    *(p + 0) = 0x3E;
                    *(p + 1) = 0xE8;
                    
                    result -= part->rva + offset;
                    result -= 4;
                    
                    while (rel->howto->size > 2) {
                        rel->howto->size--;
                    }
                    
                    offset += 2;
                
                }
            
            }
        
        } else if (opcode != 0xE8 && has_dgroup && result >= dgroup_start) {
        
            /*printf ("relocating: %s: %s: %lx, %lx, %d\n", part->of->filename, symbol->name, part->rva + offset + 0x40, rel->symbolnum, rel->n_type);*/
            
            if (xstrcasecmp (symbol->name, "DGROUP__edata") != 0 && xstrcasecmp (symbol->name, "DGROUP__end") != 0 && xstrcasecmp (symbol->name, "__etext") != 0 && xstrcasecmp (symbol->name, "__edata") != 0 && xstrcasecmp (symbol->name, "__end") != 0) {
            
                if (result >= dgroup_start) {
                    result -= (dgroup_start & 0xfffffff0);
                }
            
            }
        
        }
    
    }
    
    switch (rel->howto->size) {
    
        case 8: {
        
            integer_to_array (result, part->content + offset, 8, 0);
            break;
        
        }
        
        case 4: {
        
            integer_to_array (result, part->content + offset, 4, 0);
            break;
        
        }
        
        case 3: {
        
            integer_to_array (result, part->content + offset, 3, 0);
            break;
        
        }
        
        case 2: {
        
            integer_to_array (result, part->content + offset, 2, 0);
            break;
        
        }
        
        case 1: {
        
            integer_to_array (result, part->content + offset, 1, 0);
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
    unsigned long undef = 0, i;
    
    for (i = 0; i < part->reloc_cnt; i++) {
    
        if (relocs[i].howto->size == 0) {
            continue;
        }
        
        symbol = relocs[i].symbol;
        
        if (symbol_is_undefined (symbol)) {
        
            if (!(symbol = symbol_find (symbol->name))) {
            
                symbol = relocs[i].symbol;
                
                report_at (program_name, 0, REPORT_INTERNAL_ERROR, "external symbol '%s' not found in hashtab", symbol->name);
                exit (EXIT_FAILURE);
            
            }
            
            if (symbol_is_undefined (symbol)) {
            
                report_at (program_name, 0, REPORT_ERROR, "%s:(%s+%#lu): undefined reference to '%s'", part->of->filename, part->section->name, relocs[i].offset, symbol->name);
                undef++;
                
                continue;
            
            }
        
        }
        
        if (relocs[i].howto->special_function) {
        
            (*relocs[i].howto->special_function) (part, &relocs[i], symbol);
            continue;
        
        }
        
        reloc_generic (part, &relocs[i], symbol);
    
    }
    
    if (undef) { exit (EXIT_FAILURE); }

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
    
        if (state->format == LD_FORMAT_IA16_ELKS || state->format == LD_FORMAT_I386_AOUT || state->format == LD_FORMAT_I386_AXE || state->format == LD_FORMAT_I386_ELF || state->format == LD_FORMAT_I386_ELKS) {
        
            state->entry_symbol_name = xstrdup ("_start");
            
            if ((symbol = symbol_find (state->entry_symbol_name))) {
            
                state->entry_point = symbol_get_value_no_base (symbol);
                return;
            
            }
        
        } else if (state->format == LD_FORMAT_AMD64_AXE || state->format == LD_FORMAT_AMD64_ELF) {
        
            state->entry_symbol_name = xstrdup ("_start");
            
            if ((symbol = symbol_find (state->entry_symbol_name))) {
            
                state->entry_point = symbol_get_value_no_base (symbol);
                return;
            
            }
        
        } else if (state->format == LD_FORMAT_AARCH64_MACHO || state->format == LD_FORMAT_AMD64_MACHO) {
        
            state->entry_symbol_name = xstrdup ("_start");
            
            if ((symbol = symbol_find (state->entry_symbol_name))) {
            
                state->entry_point = symbol_get_value_no_base (symbol);
                return;
            
            }
        
        } else if (state->format == LD_FORMAT_AMD64_PE) {
        
            state->entry_symbol_name = xstrdup ("mainCRTStartup");
            
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
    
    if (!state->create_shared_library && state->entry_symbol_name) {
        report_at (program_name, 0, REPORT_WARNING, "cannot find entry symbol '%s'; defaulting to 0x%08lx", state->entry_symbol_name, state->base_address + state->entry_point);
    }

}

void link (void) {

    unsigned long value = 0, offset = 0;
    
    struct section *section;
    struct section_part *part;
    
    struct object_file *of;
    struct symbol *symbol;
    
    collapse_subsections ();
    
    if (state->generate_symbols_table) {
        output_symbols ();
    }
    
    calculate_section_sizes_and_rvas ();
    
    if (state->generate_symbols_table) {
    
        if ((section = section_find (".data"))) {
        
            offset += (section->rva % 16);
            value += (section->rva % 16);
            
            for (part = section->first_part; part; part = part->next) {
            
                if (part->next) {
                    offset += part->content_size;
                }
                
                value += part->content_size;
            
            }
            
            if ((symbol = symbol_find ("__symbol_table_start")) && symbol_is_undefined (symbol)) {
            
                of = object_file_make (FAKE_LD_FILENAME, 1);
                
                symbol = of->symbol_arr;
                symbol->name = xstrdup ("__symbol_table_start");
                
                symbol->section_number = ABSOLUTE_SECTION_NUMBER;
                symbol->value = value;
                
                symbol_record_external_symbol (symbol);
            
            }
            
            value += generate_symbols_table (offset);
            calculate_section_sizes_and_rvas ();
            
            if ((symbol = symbol_find ("__symbol_table_end")) && symbol_is_undefined (symbol)) {
            
                of = object_file_make (FAKE_LD_FILENAME, 1);
                
                symbol = of->symbol_arr;
                symbol->name = xstrdup ("__symbol_table_end");
                
                symbol->section_number = ABSOLUTE_SECTION_NUMBER;
                symbol->value = value;
                
                symbol_record_external_symbol (symbol);
            
            }
        
        }
    
    }
    
    if (state->emulation == LD_EMULATION_IA16_DX || state->emulation == LD_EMULATION_IA16_MZ) {
    
        value = 0;
        
        if ((symbol = symbol_find ("DGROUP")) && symbol_is_undefined (symbol)) {
        
            if ((section = section_find (".data"))) {
                value += align_section_if_needed (section->rva);
            } else if ((section = section_find (".bss"))) {
                value += align_section_if_needed (section->rva);
            }
            
            dgroup_start = value;
            has_dgroup = 1;
            
            of = object_file_make (FAKE_LD_FILENAME, 1);
            
            symbol = of->symbol_arr;
            symbol->name = xstrdup ("DGROUP");
            
            symbol->section_number = ABSOLUTE_SECTION_NUMBER;
            symbol->value = value / 16;
            
            symbol_record_external_symbol (symbol);
        
        }
        
        value = 0;
        
        if ((symbol = symbol_find ("DGROUP__edata")) && symbol_is_undefined (symbol)) {
        
            if ((section = section_find (".data"))) {
                value += align_section_if_needed (section->rva + section->total_size);
            }
            
            of = object_file_make (FAKE_LD_FILENAME, 1);
            value -= (dgroup_start & 0xfffffff0);
            
            symbol = of->symbol_arr;
            symbol->name = xstrdup ("DGROUP__edata");
            
            symbol->section_number = ABSOLUTE_SECTION_NUMBER;
            symbol->value = value;
            
            symbol_record_external_symbol (symbol);
        
        }
        
        value = 0;
        
        if ((symbol = symbol_find ("DGROUP__end")) && symbol_is_undefined (symbol)) {
        
            if ((section = section_find (".bss"))) {
                value += align_section_if_needed (section->rva + section->total_size);
            } else if ((section = section_find (".data"))) {
                value += align_section_if_needed (section->rva + section->total_size);
            }
            
            of = object_file_make (FAKE_LD_FILENAME, 1);
            value -= (dgroup_start & 0xfffffff0);
            
            symbol = of->symbol_arr;
            symbol->name = xstrdup ("DGROUP__end");
            
            symbol->section_number = ABSOLUTE_SECTION_NUMBER;
            symbol->value = value;
            
            symbol_record_external_symbol (symbol);
        
        }
    
    }
    
    value = 0;
    
    if ((symbol = symbol_find ("__etext")) && symbol_is_undefined (symbol)) {
    
        if ((section = section_find (".text"))) {
            value += align_section_if_needed (section->total_size);
        }
        
        of = object_file_make (FAKE_LD_FILENAME, 1);
        
        symbol = of->symbol_arr;
        symbol->name = xstrdup ("__etext");
        
        symbol->section_number = ABSOLUTE_SECTION_NUMBER;
        symbol->value = value;
        
        symbol_record_external_symbol (symbol);
    
    }
    
    value = 0;
    
    if ((symbol = symbol_find ("__edata")) && symbol_is_undefined (symbol)) {
    
        if ((section = section_find (".data"))) {
            value += align_section_if_needed (section->total_size);
        }
        
        of = object_file_make (FAKE_LD_FILENAME, 1);
        
        symbol = of->symbol_arr;
        symbol->name = xstrdup ("__edata");
        
        symbol->section_number = ABSOLUTE_SECTION_NUMBER;
        symbol->value = value;
        
        symbol_record_external_symbol (symbol);
    
    }
    
    value = 0;
    
    if ((symbol = symbol_find ("__end")) && symbol_is_undefined (symbol)) {
    
        if ((section = section_find (".bss"))) {
            value += align_section_if_needed (section->total_size);
        }
        
        of = object_file_make (FAKE_LD_FILENAME, 1);
        
        symbol = of->symbol_arr;
        symbol->name = xstrdup ("__end");
        
        symbol->section_number = ABSOLUTE_SECTION_NUMBER;
        symbol->value = value;
        
        symbol_record_external_symbol (symbol);
    
    }
    
    check_unresolved ();
    
    relocate_sections ();
    calculate_entry_point ();

}
