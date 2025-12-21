/******************************************************************************
 * @file            macho.c
 *****************************************************************************/
#include    <limits.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "ld.h"
#include    "lib.h"
#include    "macho.h"
#include    "report.h"
#include    "section.h"

unsigned long _static = 0;
#define     LD_OPTION_STATIC                                1

static struct ld_option opts[] = {

    {   "-static",          LD_OPTION_TYPE_LONG,        LD_OPTION_STATIC,       LD_OPTION_NO_ARG    },
    {   0,                  0,                          0,                      0                   }

};

int macho_check_option (const char *cmd_arg, int argc, char **argv, int *optind, const char **optarg) {

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

void macho_use_option (const char *cmd_arg, int idx, const char *optarg) {

    (void) optarg;
    
    switch (idx) {
    
        case LD_OPTION_STATIC: {
        
            _static = 1;
            break;
        
        }
        
        default: {
        
            report_at (program_name, 0, REPORT_ERROR, "unsupported option '%s'", cmd_arg);
            exit (EXIT_FAILURE);
        
        }
    
    }

}

void macho_print_help (void) {

    fprintf (stderr, "macho:\n\n");
    fprintf (stderr, "    -static                       Produces a Mach-O file that does not use the dyld.\n");

}


#define     PAGE_SIZE                   0x4000

struct part_reloc {

    struct section_part *part;
    struct reloc_entry *reloc_entry;

};

static struct part_reloc addend_part_reloc = { 0 };

static void apply_addend_reloc (struct reloc_entry *reloc, struct section_part *part) {

    if (!addend_part_reloc.reloc_entry) return;
    
    if (part != addend_part_reloc.part) {
        report_at (program_name, 0, REPORT_WARNING, "%s: ARM64_RELOC_ADDEND is in different" " section than relocation it applies to", addend_part_reloc.part->of->filename);
    }
    
    if (reloc->offset != addend_part_reloc.reloc_entry->offset) {
        report_at (program_name, 0, REPORT_WARNING, "%s: ARM64_RELOC_ADDEND has different offset than relocation it applies to", addend_part_reloc.part->of->filename);
    }
    
    reloc->addend = addend_part_reloc.reloc_entry->addend;
    addend_part_reloc.reloc_entry = 0;

}

#define     CHECK_READ(memory_position, size_to_read)                           \
    do                                                                          \
        if (((memory_position) - data + (size_to_read) > data_size) ||          \
             (memory_position) < data) {                                        \
            report_at (program_name, 0, REPORT_FATAL_ERROR,                     \
                "%s: corrupt input file", filename);                            \
            exit (EXIT_FAILURE);                                                \
        }                                                                       \
    while (0)

static void translate_relocation (struct reloc_entry *reloc, struct macho_relocation_info *input_reloc, struct section_part *part) {

    unsigned long r_symbolnum = array_to_integer (input_reloc->r_symbolnum, 4, 0);
    
    unsigned long field;
    unsigned int size, pcrel, type;
    
    if ((r_symbolnum >> 27) & 1) {
        reloc->symbol = part->of->symbol_arr + (r_symbolnum & 0xffffff);
    } else {
    
        if (r_symbolnum == 0) {
        
            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "local input_reloc->r_symbolnum %#lx is not yet supported", r_symbolnum & 0xffffff);
            exit (EXIT_FAILURE);
        
        }
        
        reloc->symbol = part->of->symbol_arr + part->of->symbol_cnt - (r_symbolnum & 0xffffff);
    
    }
    
    reloc->offset = array_to_integer (input_reloc->r_address, 4, 0);
    reloc->r_symbolnum = r_symbolnum;
    
    size = 1U << ((r_symbolnum >> 25) & 3);
    
    pcrel = (r_symbolnum >> 24) & 1;
    type = r_symbolnum >> 28;
    
    if ((state->format & LD_TARGET_MACHINE_AMD64)) {
    
        switch (size) {
        
            case 8:
            
                if (!pcrel && type == AMD64_RELOC_UNSIGNED) {
                    reloc->howto = &reloc_howtos[RELOC_TYPE_64];
                } else {
                    goto unsupported;
                }
                
                break;
            
            case 4:
            
                if (pcrel) {
                
                    if (type == AMD64_RELOC_SIGNED) {
                    
                        reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                        
                        if (reloc->symbol->flags & SYMBOL_FLAG_SECTION_SYMBOL) {
                        
                            field = array_to_integer (part->content + reloc->offset, 4, 0);
                            
                            field -= reloc->symbol->part->rva - reloc->offset - 4;
                            integer_to_array (field, part->content + reloc->offset, 4, 0);
                        
                        }
                    
                    } else if (type == AMD64_RELOC_BRANCH) {
                        reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                    } else if (type == AMD64_RELOC_GOT_LOAD) {
                    
                        reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                        
                        if (part->content[reloc->offset - 2] != 0x8b) {
                        
                            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: not yet supported x64 GOT instruction", part->of->filename);
                            exit (EXIT_FAILURE);
                        
                        }
                        
                        part->content[reloc->offset - 2] = 0x8d;
                    
                    } else if (type == AMD64_RELOC_GOT) {
                    
                        uint64_t addend, helper_offset;
                        
                        if (part->content[reloc->offset - 1] != 0x05 || part->content[reloc->offset - 2] != 0x03 || part->content[reloc->offset - 3] != 0x48) {
                        
                            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: not yet supported x64 GOT instruction", part->of->filename);
                            exit (EXIT_FAILURE);
                        
                        }
                        
                        part->content[reloc->offset - 3] = 0x90;
                        part->content[reloc->offset - 2] = 0x90;
                        part->content[reloc->offset - 1] = 0xe8;
                        
                        field = array_to_integer (part->content + reloc->offset, 4, 0);
                        addend = field;
                        
                        field = part->content_size - reloc->offset - 4;
                        integer_to_array (field, part->content + reloc->offset, 4, 0);
                        
                        helper_offset = part->content_size;
                        part->content_size += 13;
                        
                        part->content = xrealloc (part->content, part->content_size);
                        memcpy (part->content + helper_offset,
                            "\x51"
                            "\x48\x8D\x0D\x00\x00\x00\x00"
                            "\x48\x01\xC8"
                            "\x59"
                            "\xC3",
                        13);
                        
                        reloc->offset = helper_offset + 4;
                        integer_to_array (addend, part->content + reloc->offset, 4, 0);
                        
                        reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                    
                    } else if (type == AMD64_RELOC_SIGNED_1 || type == AMD64_RELOC_SIGNED_2 || type == AMD64_RELOC_SIGNED_4) {
                        reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                    } else {
                        goto unsupported;
                    }
                
                } else {
                
                    if (type == AMD64_RELOC_UNSIGNED) {
                        reloc->howto = &reloc_howtos[RELOC_TYPE_32];
                    } else if (type == AMD64_RELOC_SUBTRACTOR) {
                        reloc->howto = &reloc_howtos[RELOC_TYPE_32_SUB];
                    } else {
                        goto unsupported;
                    }
                
                }
                
                break;
            
            default:
            
                goto unsupported;
        
        }
    
    } else if ((state->format & LD_TARGET_MACHINE_AARCH64)) {
    
        switch (size) {
        
            case 8:
            
                if (!pcrel && type == ARM64_RELOC_UNSIGNED) {
                    reloc->howto = &reloc_howtos[RELOC_TYPE_64];
                } else {
                    goto unsupported;
                }
                
                break;
            
            case 4:
            
                if (pcrel) {
                
                    if (type == ARM64_RELOC_BRANCH26) {
                    
                        reloc->howto = &reloc_howtos[RELOC_TYPE_AARCH64_CALL26];
                        apply_addend_reloc (reloc, part);
                    
                    } else if (type == ARM64_RELOC_PAGE21) {
                    
                        reloc->howto = &reloc_howtos[RELOC_TYPE_AARCH64_ADR_PREL_PG_HI21];
                        apply_addend_reloc (reloc, part);
                    
                    } else if (type == ARM64_RELOC_GOT_LOAD_PAGE21) {
                        reloc->howto = &reloc_howtos[RELOC_TYPE_AARCH64_ADR_PREL_PG_HI21];
                    } else {
                        goto unsupported;
                    }
                } else {
                
                    if (type == ARM64_RELOC_PAGEOFF12) {
                    
                        if (part->content[reloc->offset + 3] == 0x39) {
                            reloc->howto = &reloc_howtos[RELOC_TYPE_AARCH64_LDST8_ABS_LO12_NC];
                        } else if (part->content[reloc->offset + 3] == 0x79) {
                            reloc->howto = &reloc_howtos[RELOC_TYPE_AARCH64_LDST16_ABS_LO12_NC]; /*strh*/
                        } else if (part->content[reloc->offset + 3] == 0xB9) {
                            reloc->howto = &reloc_howtos[RELOC_TYPE_AARCH64_LDST32_ABS_LO12_NC];
                        } else if (part->content[reloc->offset + 3] == 0xF9 || part->content[reloc->offset + 3] == 0xFD) {
                            reloc->howto = &reloc_howtos[RELOC_TYPE_AARCH64_LDST64_ABS_LO12_NC];
                        } else if (part->content[reloc->offset + 3] == 0x3D) {
                            reloc->howto = &reloc_howtos[RELOC_TYPE_AARCH64_LDST128_ABS_LO12_NC];
                        } else {
                            reloc->howto = &reloc_howtos[RELOC_TYPE_AARCH64_ADD_ABS_LO12_NC];
                        }
                        
                        apply_addend_reloc (reloc, part);
                    
                    } else if (type == ARM64_RELOC_GOT_LOAD_PAGEOFF12) {
                    
                        field  = array_to_integer (part->content + reloc->offset, 4, 0);
                        field &= ~0x68400000;
                        
                        integer_to_array (field, part->content + reloc->offset, 4, 0);
                        reloc->howto = &reloc_howtos[RELOC_TYPE_AARCH64_ADD_ABS_LO12_NC];
                    
                    } else if (type == ARM64_RELOC_ADDEND) {
                    
                        reloc->symbol = NULL;
                        reloc->addend = r_symbolnum & 0xffffff;
                        reloc->howto = &reloc_howtos[RELOC_TYPE_IGNORED];
                        
                        addend_part_reloc.reloc_entry = reloc;
                        addend_part_reloc.part = part;
                    
                    } else {
                        goto unsupported;
                    }
                
                }
                
                break;
            
            default:
            
                goto unsupported;
        
        }
    
    } else {
    unsupported:
    
        report_at (program_name, 0, REPORT_WARNING, "%s: ignoring not yet supported relocation with size %u, pcrel %u and type %#x", part->of->filename, size, pcrel, type);
        reloc->howto = &reloc_howtos[RELOC_TYPE_IGNORED];
    
    }

}

#define     UNNAMED_SYMBOL_NAME         "(unnamed)"

void read_macho_object (const char *filename, unsigned char *data, unsigned long data_size) {

    unsigned char *pos = (unsigned char *) data;
    
    struct section_part **part_p_array = 0, *bss_part;
    struct object_file *of = 0;
    
    struct segment_command_64 *segment_cmd;
    struct section_64 *section_64;
    struct symtab_command *symtab_cmd;
    
    struct section_part *part;
    struct section *section;
    
    struct section *bss_section = 0;
    long bss_section_number = 0;
    
    char *section_name, *segment_name, *string_table;
    uint64_t num_symbols = 0, num_sections = 0;
    
    struct load_command *load_command;
    uint64_t sizeof_cmds, cmd_size, i, j, k;
    
    unsigned long num_cmds, num_sects, num_syms, n_strx, cpu_type;
    unsigned char *sym_pos;
    
    struct nlist_64 *nlist_64;
    struct symbol *old_symbol, *symbol;
    
    struct macho_relocation_info *reloc_info;
    unsigned char *rel_pos;
    
    struct macho_header_64 *header;
    CHECK_READ (pos, sizeof (*header));
    
    header = (struct macho_header_64 *) pos;
    pos += sizeof (*header);
    
    cpu_type = array_to_integer (header->cpu_type, 4, 0);
    
    if (cpu_type != MH_CPU_TYPE_AMD64 && cpu_type != MH_CPU_TYPE_ARM64) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: unrecognized cputype %#lx", filename, cpu_type);
        return;
    
    }
    
    sizeof_cmds = array_to_integer (header->sizeof_cmds, 4, 0);
    
    if (array_to_integer (header->file_type, 4, 0) != MH_OBJECT) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: file type is not MH_OBJECT", filename);
        return;
    
    }
    
    num_cmds = array_to_integer (header->num_cmds, 4, 0);
    CHECK_READ (pos, num_cmds);
    
    for (i = 0; i < num_cmds; i++) {
    
        load_command = (struct load_command *) pos;
        
        if ((pos - data) + sizeof (*load_command) > sizeof (*header) + sizeof_cmds) {
        
            report_at (program_name, 0, REPORT_ERROR, "%s: invalid header size of commands / number of commands", filename);
            return;
        
        }
        
        cmd_size = array_to_integer (load_command->command_size, 4, 0);
        
        if ((pos - data) + cmd_size > sizeof (*header) + sizeof_cmds) {
        
            report_at (program_name, 0, REPORT_ERROR, "%s: invalid load command command size", filename);
            return;
        
        }
        
        if (array_to_integer (load_command->command, 4, 0) == LC_SYMTAB) {
        
            symtab_cmd = (struct symtab_command *) pos;
            
            if (sizeof (*symtab_cmd) > array_to_integer (symtab_cmd->command_size, 4, 0)) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: symtab command command size too small", filename);
                exit (EXIT_FAILURE);
            
            }
            
            if (num_symbols && array_to_integer (symtab_cmd->num_symbols, 4, 0)) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: more than 1 non-empty symbol table per object file", filename);
                exit (EXIT_FAILURE);
            
            }
            
            num_symbols = array_to_integer (symtab_cmd->num_symbols, 4, 0);
        
        } else if (array_to_integer (load_command->command, 4, 0) == LC_SEGMENT_64) {
        
            segment_cmd = (struct segment_command_64 *) pos;
            
            if (num_sections && array_to_integer (segment_cmd->num_sects, 4, 0)) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: more than 1 non-empty segment command per object file", filename);
                exit (EXIT_FAILURE);
            
            }
            
            num_sections = array_to_integer (segment_cmd->num_sects, 4, 0);
        
        }
        
        pos += cmd_size;
    
    }
    
    of = object_file_make (filename, num_symbols + num_sections);
    pos = (unsigned char *) (data + sizeof (*header));
    
    for (i = 0; i < num_cmds; i++) {
    
        load_command = (struct load_command *) pos;
        
        if (array_to_integer (load_command->command, 4, 0) == LC_SEGMENT_64) {
        
            segment_cmd = (struct segment_command_64 *) pos;
            
            if (!(num_sects = array_to_integer (segment_cmd->num_sects, 4, 0))) {
            
                pos += array_to_integer (load_command->command_size, 4, 0);
                continue;
            
            }
            
            part_p_array = xmalloc ((num_sects + 1) * sizeof (*part_p_array));
            
            if (sizeof (*segment_cmd) + num_sects * sizeof (*section_64) > array_to_integer (segment_cmd->command_size, 4, 0)) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: segment command command size and number of sections mismatch", filename);
                exit (EXIT_FAILURE);
            
            }
            
            for (j = 0; j < num_sects; j++) {
            
                section_64 = (struct section_64 *) (pos + sizeof (*segment_cmd) + j * sizeof (*section_64));
                
                section_name = xstrndup (section_64->sect_name, sizeof (section_64->sect_name));
                segment_name = xstrndup (section_64->seg_name, sizeof (section_64->seg_name));
                
                section = section_find_or_make (section_name);
                free (section_name);
                
                if (1LU << array_to_integer (section_64->align, 4, 0) > section->section_alignment) {
                    section->section_alignment = 1LU << array_to_integer (section_64->align, 4, 0);
                }
                
                if (strcmp (segment_name, "__TEXT") == 0) {
                
                    unsigned long flags = array_to_integer (section_64->flags, 4, 0);
                    section->flags = SECTION_FLAG_ALLOC | SECTION_FLAG_LOAD | SECTION_FLAG_READONLY;
                    
                    if ((flags & S_REGULAR)) {
                        section->flags |= SECTION_FLAG_CODE;
                    }
                
                } else if (strcmp (segment_name, "__DATA") == 0) {
                
                    unsigned long flags = array_to_integer (section_64->flags, 4, 0);
                    
                    if (strcmp (section->name, "__const") == 0) {
                        section->flags = SECTION_FLAG_ALLOC | SECTION_FLAG_LOAD | SECTION_FLAG_READONLY;
                    } else if ((flags & 0xff) == S_ZEROFILL) {
                    
                        section->flags = SECTION_FLAG_ALLOC;
                        section->is_bss = 1;
                        
                        bss_section_number = j + 1;
                        bss_section = section;
                    
                    } else {
                        section->flags = SECTION_FLAG_ALLOC | SECTION_FLAG_LOAD | SECTION_FLAG_DATA;
                    }
                
                } else {
                    section->flags = SECTION_FLAG_ALLOC | SECTION_FLAG_LOAD | SECTION_FLAG_READONLY;
                }
                
                free (segment_name);
                
                part = section_part_new (section, of);
                part->rva = array_to_integer (section_64->addr, 8, 0);
                
                part->content_size = array_to_integer (section_64->size, 8, 0);
                part->alignment = 1LU << array_to_integer (section_64->align, 4, 0);
                
                if (!section->is_bss) {
                
                    unsigned char *content_pos = (unsigned char *) data + array_to_integer (section_64->offset, 4, 0);
                    
                    part->content = xmalloc (part->content_size);
                    memcpy (part->content, content_pos, part->content_size);
                
                }
                
                section_append_section_part (section, part);
                part_p_array[j + 1] = part;
            
            }
        
        }
        
        pos += array_to_integer (load_command->command_size, 4, 0);
    
    }
    
    pos = (unsigned char *) (data + sizeof (*header));
    
    for (i = 0; i < num_cmds; i++) {
    
        load_command = (struct load_command *) pos;
        
        if (array_to_integer (load_command->command, 4, 0) == LC_SYMTAB) {
        
            symtab_cmd = (struct symtab_command *) pos;
            
            if (!(num_syms = array_to_integer (symtab_cmd->num_symbols, 4, 0))) {
            
                pos += array_to_integer (load_command->command_size, 4, 0);
                continue;
            
            }
            
            string_table = (char *) data + array_to_integer (symtab_cmd->string_offset, 4, 0);
            CHECK_READ (data + array_to_integer (symtab_cmd->string_offset, 4, 0), array_to_integer (symtab_cmd->string_size, 4, 0));
            
            sym_pos = (unsigned char *) data + array_to_integer (symtab_cmd->symbol_offset, 4, 0);
            CHECK_READ (sym_pos, sizeof (*nlist_64) * num_syms);
            
            for (j = 0; j < num_syms; j++) {
            
                nlist_64 = (struct nlist_64 *) (sym_pos + j * sizeof (*nlist_64));
                symbol = of->symbol_arr + j;
                
                if ((n_strx = array_to_integer (nlist_64->n_strx, 4, 0)) < array_to_integer (symtab_cmd->string_size, 4, 0)) {
                
                    if (string_table[n_strx] == '\0') {
                        symbol->name = xstrdup (UNNAMED_SYMBOL_NAME);
                    } else {
                        symbol->name = xstrdup (string_table + n_strx);
                    }
                
                } else {
                
                    report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid index into string table", filename);
                    exit (EXIT_FAILURE);
                
                }
                
                symbol->value = array_to_integer (nlist_64->n_value, 8, 0);
                
                if ((nlist_64->n_type[0] & MACHO_N_STAB) || (nlist_64->n_type[0] & MACHO_N_PEXT)) {
                
                    report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++%s: not yet supported symbol n_type: %#x", filename, nlist_64->n_type[0]);
                    exit (EXIT_FAILURE);
                
                }
                
                if ((nlist_64->n_type[0] & MACHO_N_TYPE) == MACHO_N_UNDF) {
                
                    if (symbol->value) {
                    
                        old_symbol = symbol_find (symbol->name);
                        
                        if (!old_symbol || symbol_is_undefined (old_symbol)) {
                        
                            if (!bss_section) {
                            
                                bss_section = section_find_or_make ("__bss");
                                
                                bss_section->flags = SECTION_FLAG_ALLOC;
                                bss_section->is_bss = 1;
                                
                                bss_section_number = num_sections ? num_sections : 1;
                            
                            }
                            
                            bss_part = section_part_new (bss_section, of);
                            section_append_section_part (bss_section, bss_part);
                            
                            bss_part->content_size = symbol->size = symbol->value;
                            
#if     0
                            if (bss_part->content_size > PAGE_SIZE) {
                                bss_part->alignment = PAGE_SIZE;
                            } else {
                                bss_part->alignment = bss_part->content_size;
                            }
#else
                            /* Assume everything needed at most 16-byte alignment. */
                            bss_part->alignment = 16;
#endif
                            
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
                    
                        symbol->section_number = UNDEFINED_SECTION_NUMBER;
                        symbol->part = 0;
                    
                    }
                
                } else if ((nlist_64->n_type[0] & MACHO_N_TYPE) == MACHO_N_SECT) {
                
                    if (nlist_64->n_sect[0] > num_sections) {
                    
                        report_at (__FILE__, __LINE__, REPORT_ERROR, "%s: invalid symbol n_sect: %u", filename, nlist_64->n_sect[0]);
                        symbol->part = 0;
                    
                    } else {
                        symbol->value -= part_p_array[nlist_64->n_sect[0]]->rva;
                    }
                    
                    symbol->section_number = nlist_64->n_sect[0];
                    symbol->part = part_p_array[nlist_64->n_sect[0]];
                
                } else {
                
                    report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++%s: not yet supported symbol n_type: %#x", filename, nlist_64->n_type[0]);
                    exit (EXIT_FAILURE);
                
                }
                
                if (nlist_64->n_type[0] & MACHO_N_EXT) {
                    symbol_record_external_symbol (symbol);
                }
            
            }
            
            break;
        
        }
        
        pos += array_to_integer (load_command->command_size, 4, 0);
    
    }
    
    for (i = 1; i < num_sections + 1; i++) {
    
        symbol = of->symbol_arr + of->symbol_cnt - i;
        
        part = part_p_array[i];
        symbol->name = xstrdup (part->section->name);
        
        symbol->flags |= SYMBOL_FLAG_SECTION_SYMBOL;
        symbol->value = 0;
        symbol->size = 0;
        symbol->part = part;
        symbol->section_number = i;
    
    }
    
    pos = (unsigned char *) (data + sizeof (*header));
    
    for (i = 0; i < num_cmds; i++) {
    
        load_command = (struct load_command *) pos;
        
        if (array_to_integer (load_command->command, 4, 0) == LC_SEGMENT_64) {
        
            segment_cmd = (struct segment_command_64 *) pos;
            
            if (!(num_sects = array_to_integer (segment_cmd->num_sects, 4, 0))) {
            
                pos += array_to_integer (load_command->command_size, 4, 0);
                continue;
            
            }
            
            for (j = 0; j < num_sects; j++) {
            
                section_64 = (struct section_64 *) (pos + sizeof (*segment_cmd) + j * sizeof (*section_64));
                
                {
                
                    part = part_p_array[j + 1];
                    
                    if ((part->reloc_cnt = array_to_integer (section_64->num_reloc, 4, 0))) {
                    
                        rel_pos = data + array_to_integer (section_64->rel_off, 4, 0);
                        CHECK_READ (rel_pos, part->reloc_cnt * sizeof (*reloc_info));
                        
                        part->reloc_arr = xmalloc (part->reloc_cnt * sizeof (*part->reloc_arr));
                        
                        for (k = 0; k < part->reloc_cnt; k++) {
                        
                            reloc_info = (struct macho_relocation_info *) (rel_pos + sizeof (*reloc_info) * k);
                            translate_relocation (part->reloc_arr + k, reloc_info, part);
                        
                        }
                    
                    }
                
                }
            
            }
        
        }
        
        pos += array_to_integer (load_command->command_size, 4, 0);
    
    }
    
    free (part_p_array);
    
    if (addend_part_reloc.reloc_entry) {
        report_at (program_name, 0, REPORT_WARNING, "%s: ARM64_RELOC_ADDEND without following relocation", filename);
    }

}

#define     section_in_text_seg(section)                    \
    ((section)->flags & SECTION_FLAG_CODE)

#define     section_in_data_seg(section)                    \
    (!((section)->flags & SECTION_FLAG_CODE))

static struct section *first_data_section = 0;
static uint64_t first_data_section_alignment = 0;

void macho_before_link (void) {

    struct section *section, *next_section;
    
    struct section *text_sections = 0;
    struct section **last_text_section_p = &text_sections;
    
    struct section *data_sections = 0;
    struct section **last_data_section_p = &data_sections;
    
    struct section *bss_sections = 0;
    struct section **last_bss_section_p = &bss_sections;
    
    for (section = all_sections; section; section = next_section) {
    
        next_section = section->next;
        section->next = 0;
        
        if (section_in_text_seg (section)) {
        
            *last_text_section_p = section;
            last_text_section_p = &section->next;
        
        } else if (!section->is_bss) {
        
            *last_data_section_p = section;
            last_data_section_p = &section->next;
        
        } else {
        
            *last_bss_section_p = section;
            last_bss_section_p = &section->next;
        
        }
    
    }
    
    *last_text_section_p = data_sections;
    
    if (data_sections) {
        *last_data_section_p = bss_sections;
    } else {
        *last_text_section_p = bss_sections;
    }
    
    all_sections = text_sections;
    
    if ((first_data_section = *last_text_section_p)) {
    
        first_data_section_alignment = first_data_section->section_alignment;
        first_data_section->section_alignment = PAGE_SIZE;
    
    }

}

uint64_t macho_get_first_section_rva (void) {
    return PAGE_SIZE;
}

#define     FLOOR_TO(to_floor, floor)                       \
    ((to_floor) / (floor) * (floor))

static int part_reloc_compare (const void *a, const void *b) {

    const struct part_reloc *apr, *bpr;
    uint64_t arva, brva;
    
    apr = a;
    bpr = b;
    
    arva = apr->part->rva + apr->reloc_entry->offset;
    brva = bpr->part->rva + bpr->reloc_entry->offset;
    
    if (arva < brva) {
        return -1;
    }
    
    if (arva > brva) {
        return 1;
    }
    
    return 0;

}

#define     NUM_SEGS                    4

struct chained_fixup_starts {

    unsigned short *page_starts;
    unsigned short page_count;

};

unsigned long minos_version = 0x000B0000LU;                 /* "11.0.0" */

static void calculate_chained_fixups (struct chained_fixup_starts *cfs, int doing_data) {

    struct section *section;
    struct section_part *part;
    
    struct part_reloc *part_rels = 0, *p;
    unsigned long num_relocs = 0, i;
    
    uint64_t seg_rva = 0;
    
    if (doing_data) {
    
        for (section = all_sections; section; section = section->next) {
        
            if (section_in_data_seg (section)) {
            
                seg_rva = section->rva;
                break;
            
            }
        
        }
    
    }
    
    for (section = all_sections; section; section = section->next) {
    
        if ((doing_data && !section_in_data_seg (section)) || (!doing_data && !section_in_text_seg (section))) {
            continue;
        }
        
        for (part = section->first_part; part; part = part->next) {
        
            struct reloc_entry *relocs = part->reloc_arr;
            
            for (i = 0; i < part->reloc_cnt; i++) {
            
                if (relocs[i].howto != &reloc_howtos[RELOC_TYPE_64]) {
                    continue;
                }
                
                num_relocs++;
            
            }
        
        }
    
    }
    
    if (!num_relocs) {
        return;
    }
    
    p = part_rels = xmalloc (sizeof (*part_rels) * num_relocs);
    
    for (section = all_sections; section; section = section->next) {
    
        if ((doing_data && !section_in_data_seg (section)) || (!doing_data && !section_in_text_seg (section))) {
            continue;
        }
        
        for (part = section->first_part; part; part = part->next) {
        
            struct reloc_entry *relocs = part->reloc_arr;
            
            for (i = 0; i < part->reloc_cnt; i++) {
            
                if (relocs[i].howto != &reloc_howtos[RELOC_TYPE_64]) {
                    continue;
                }
                
                p->reloc_entry = &relocs[i];
                p->part = part;
                
                p++;
            
            }
        
        }
    
    }
    
    qsort (part_rels, num_relocs, sizeof (*part_rels), &part_reloc_compare);
    
    {
        uint64_t max_rva = part_rels[num_relocs - 1].part->rva + part_rels[num_relocs - 1].reloc_entry->offset;
        
        max_rva = ALIGN (max_rva, PAGE_SIZE);
        cfs->page_count = (max_rva - seg_rva) / PAGE_SIZE;
    }
    
    cfs->page_starts = xmalloc (sizeof *(cfs->page_starts) * cfs->page_count);
    
    for (i = 0, p = part_rels; (i < cfs->page_count) && (p < part_rels + num_relocs); i++) {
    
        uint64_t p_rva = p->part->rva + p->reloc_entry->offset;
        
        if (seg_rva + (i + 1) * PAGE_SIZE <= p_rva) {
        
            cfs->page_starts[i] = DYLD_CHAINED_PTR_START_NONE;
            continue;
        
        }
        
        cfs->page_starts[i] = p_rva & (PAGE_SIZE - 1);
        
        for (; p < part_rels + num_relocs; p++) {
        
            uint64_t result = array_to_integer (p->part->content + p->reloc_entry->offset, 8, 0);
            result -= state->base_address;
            
#if     !defined (NO_LONG_LONG) || ULONG_MAX > 4294967295UL

            result &= 0xfffffffff;
            
            if (p + 1 != part_rels + num_relocs) {
            
                uint64_t rva1, rva2;
                
                rva1 = p->part->rva + p->reloc_entry->offset;
                rva2 = p[1].part->rva + p[1].reloc_entry->offset;
                
                if (FLOOR_TO (rva1, PAGE_SIZE) != FLOOR_TO (rva2, PAGE_SIZE)) {
                
                    integer_to_array (result, p->part->content + p->reloc_entry->offset, 8, 0);
                    
                    p++;
                    break;
                
                }
                
                result |= (((rva2 - rva1) / 4) & 0xfff) << 51;
            
            }

#endif
            
            integer_to_array (result, p->part->content + p->reloc_entry->offset, 8, 0);
        
        }
    
    }
    
    free (part_rels);

}

static unsigned long num_function_starts_symbols = 0;
static uint64_t *function_starts_addresses_p = 0;

static void function_starts_symbol_callback (struct symbol *symbol) {

    if (!symbol->part || !(symbol->part->section->flags & SECTION_FLAG_CODE)) {
        return;
    }
    
    num_function_starts_symbols++;

}

static void function_starts_symbol_callback2 (struct symbol *symbol) {

    if (!symbol->part || !(symbol->part->section->flags & SECTION_FLAG_CODE)) {
        return;
    }
    
    *function_starts_addresses_p = symbol_get_value_no_base (symbol);
    function_starts_addresses_p++;

}

static int function_starts_address_compare (const void *a, const void *b) {

    if (*(const uint64_t *) a < *(const uint64_t *) b) {
        return -1;
    }
    
    if (*(const uint64_t *) a > *(const uint64_t *) b) {
        return 1;
    }
    
    return 0;

}

#define     PROT_READ                   0x01
#define     PROT_WRITE                  0x02
#define     PROT_EXECUTE                0x04

static int log_base2 (uint64_t val) {

    int ret = 0;
    
    if (!val) {
        return ret;
    }
    
    for (val >>= 1; val; val >>= 1) {
        ret++;
    }
    
    return ret;

}

#define     SDK_VERSION                 0x000D0300LU        /* "13.3.0" */

void macho_write (const char *filename) {

    struct chained_fixup_starts chained_fixups[NUM_SEGS] = { { 0 } };
    
    struct macho_header_64 header = { 0 };
    FILE *fp;
    
    unsigned long data_size = 0, content_offset = 0, sizeof_commands = 0, num_commands = 0, file_offset = 0;
    unsigned char *saved_pos, *content, *data, *pos;
    
    struct segment_command_64 segment_cmd = { 0 };
    struct section *section;
    struct section_64 section_64 = { 0 };
    struct symtab_command symtab_cmd = { 0 };
    
    struct function_starts function_starts_command = { 0 };
    struct nlist_64 nlist_64 = { 0 };
    struct main_command main_command = { 0 };
    struct dylib_command dylib_command = { 0 };
    
    struct version_min version_min = { 0 };
    struct data_in_code data_in_code = { 0 };
    struct source_version source_version = { 0 };
    
    struct dysymtab_command dysymtab = { 0 };
    struct dylinker_command dylinker = { 0 };
    
    struct dyld_exports_trie dyld_exports_trie = { 0 };
    struct dyld_chained_fixups_header dyld_chained_fixups_header = { 0 };
    struct dyld_chained_fixups_command dyld_chained_fixups_command = { 0 };
    struct dyld_chained_starts_in_image dyld_chained_starts_in_image = { 0 };
    struct dyld_chained_starts_in_segment dyld_chained_starts_in_segment = { 0 };
    
    unsigned long function_starts_size = 0, command_size, num_sects, vm_addr, vm_size;
    unsigned char *function_starts = 0;
    
    struct unixthread_command unixthread = { 0 };
    struct amd64_thread_state64 thread_state64 = { 0 };
    
    uint64_t data_segment_offset = 0, symbol_offset = 0;
    
    if (!(fp = fopen (filename, "wb"))) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to open '%s' for writing", filename);
        return;
    
    }
    
    data_size += sizeof (header);
    
    if (first_data_section) {
        first_data_section->section_alignment = first_data_section_alignment;
    }
    
    integer_to_array (MH_MAGIC_64, header.magic, 4, 0);
    integer_to_array (MH_EXECUTE, header.file_type, 4, 0);
    
    if (state->format == LD_FORMAT_AMD64_MACHO) {
    
        integer_to_array (MH_CPU_TYPE_AMD64, header.cpu_type, 4, 0);
        integer_to_array (MH_CPU_SUBTYPE_I386_ALL, header.cpu_subtype, 4, 0);
    
    } else if (state->format == LD_FORMAT_AARCH64_MACHO) {
        integer_to_array (MH_CPU_TYPE_ARM64, header.cpu_type, 4, 0);
    }
    
    if (!_static) {
        integer_to_array (MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE, header.flags, 4, 0);
    } else {
        integer_to_array (MH_NOUNDEFS, header.flags, 4, 0);
    }
    
    sizeof_commands += sizeof (segment_cmd);
    num_commands++;
    
    sizeof_commands += sizeof (segment_cmd);
    num_commands++;
    
    for (section = all_sections; section; section = section->next) {
    
        if (section_in_text_seg (section)) {
            sizeof_commands += sizeof (section_64);
        }
    
    }
    
    sizeof_commands += sizeof (segment_cmd);
    num_commands++;
    
    for (section = all_sections; section; section = section->next) {
    
        if (section_in_data_seg (section)) {
            sizeof_commands += sizeof (section_64);
        }
    
    }
    
    sizeof_commands += sizeof (segment_cmd);
    num_commands++;
    
    if (!_static) {
    
        sizeof_commands += sizeof (dyld_chained_fixups_command);
        num_commands++;
        
        sizeof_commands += sizeof (dyld_exports_trie);
        num_commands++;
        
        sizeof_commands += sizeof (dysymtab);
        num_commands++;
        
#define     DYLINKER_STRING             "/usr/lib/dyld"
        
        sizeof_commands += ALIGN (sizeof (dylinker) + sizeof (DYLINKER_STRING), 8);
        num_commands++;
        
        sizeof_commands += sizeof (function_starts_command);
        num_commands++;
        
        sizeof_commands += sizeof (symtab_cmd);
        num_commands++;
        
#define     DYLIB_STRING                "/usr/lib/libSystem.B.dylib"
        
        sizeof_commands += ALIGN (sizeof (dylib_command) + sizeof (DYLIB_STRING), 8);
        num_commands++;
        
        sizeof_commands += sizeof (version_min);
        num_commands++;
        
        sizeof_commands += sizeof (source_version);
        num_commands++;
        
        sizeof_commands += sizeof (data_in_code);
        num_commands++;
        
        sizeof_commands += sizeof (main_command);
        num_commands++;
    
    } else {
    
        sizeof_commands += sizeof (symtab_cmd);
        num_commands++;
        
        sizeof_commands += sizeof (unixthread) + sizeof (thread_state64);
        num_commands++;
    
    }
    
    integer_to_array (num_commands, header.num_cmds, 4, 0);
    integer_to_array (sizeof_commands, header.sizeof_cmds, 4, 0);
    
    data_size = all_sections ? all_sections->rva : PAGE_SIZE;
    content_offset = data_size;
    
    for (section = all_sections; section; section = section->next) {
    
        if (section_in_text_seg (section)) {
        
            if (!section->is_bss) {
            
                data_size  = ALIGN (data_size, section->section_alignment);
                data_size += section->total_size;
                
            }
            
        }
        
    }
    
    data_size = ALIGN (data_size, PAGE_SIZE);
    
    for (section = all_sections; section; section = section->next) {
        
        if (section_in_data_seg (section)) {
            
            if (!section->is_bss) {
            
                data_size  = ALIGN (data_size, section->section_alignment);
                data_size += section->total_size;
            
            }
        
        }
    
    }
    
    data_size = ALIGN (data_size, PAGE_SIZE);
    
    if (!_static) {
    
        data_size += sizeof (dyld_chained_fixups_header);
        data_size += sizeof (dyld_chained_starts_in_image) + (NUM_SEGS - 1) * 4 + 4;
        
        calculate_chained_fixups (&chained_fixups[2], 1);
        
        if (chained_fixups[2].page_count) {
        
            data_size += sizeof (dyld_chained_starts_in_segment);
            data_size += chained_fixups[2].page_count * 2 - 2;
            
            data_size = ALIGN (data_size, 4);
        
        }
        
        data_size += sizeof (dyld_chained_starts_in_image);
        data_size += 0x980;
        
        num_function_starts_symbols = 0;
        symbols_for_each_global (&function_starts_symbol_callback);
        
        {
        
            unsigned char *p;
            
            uint64_t *addresses, prev_rva;
            unsigned long i;
            
            addresses = xmalloc (sizeof (*addresses) * num_function_starts_symbols);
            
            function_starts_addresses_p = addresses;
            symbols_for_each_global (&function_starts_symbol_callback2);
            
            qsort (addresses, num_function_starts_symbols, sizeof (*addresses), &function_starts_address_compare);
            function_starts = xmalloc (num_function_starts_symbols * (sizeof (uint64_t) * CHAR_BIT / 7 + 1) + 7);
            
            prev_rva = 0;
            p = function_starts;
            
            for (i = 0; i < num_function_starts_symbols; i++) {
            
                uint64_t diff = addresses[i] - prev_rva;
                
                while (diff) {
                
                    *p = diff & 0x7f;
                
                    if ((diff >>= 7)) {
                        *p |= 0x80;
                    }
                    
                    p++;
                
                }
                
                prev_rva = addresses[i];
            
            }
            
            memset (p, 0, 7);
            
            p = function_starts + ALIGN (p - function_starts, 8);
            data_size += function_starts_size = p - function_starts;
            
            free (addresses);
        
        }
        
#define     MH_HEADER_SYMBOL_NAME       "__mh_execute_header"
        
        data_size += sizeof (nlist_64);
        data_size += 4 + sizeof (MH_HEADER_SYMBOL_NAME);
    
    }
    
    pos = (data = xmalloc (data_size));
    content = pos + content_offset;
    
    memcpy (pos, &header, sizeof (header));
    pos += sizeof (header);
    
    memset (&segment_cmd, 0, sizeof (segment_cmd));
    
    integer_to_array (LC_SEGMENT_64, segment_cmd.command, 4, 0);
    integer_to_array (sizeof (segment_cmd), segment_cmd.command_size, 4, 0);
    
    strcpy (segment_cmd.seg_name, "__PAGEZERO");
    integer_to_array (state->base_address, segment_cmd.vm_size, 8, 0);
    
    memcpy (pos, &segment_cmd, sizeof (segment_cmd));
    pos += sizeof (segment_cmd);
    
    vm_addr = 0;
    vm_size = 0;
    
    memset (&segment_cmd, 0, sizeof (segment_cmd));
    integer_to_array (LC_SEGMENT_64, segment_cmd.command, 4, 0);
    
    command_size = sizeof (segment_cmd);
    num_sects = 0;
    
    strcpy (segment_cmd.seg_name, "__TEXT");
    integer_to_array (state->base_address, segment_cmd.vm_addr, 8, 0);
    
    integer_to_array (PROT_READ | PROT_EXECUTE, segment_cmd.max_prot, 4, 0);
    integer_to_array (PROT_READ | PROT_EXECUTE, segment_cmd.init_prot, 4, 0);
    
    saved_pos = pos;
    pos += sizeof (segment_cmd);
    
    for (section = all_sections; section; section = section->next) {
    
        memset (&section_64, 0, sizeof (section_64));
        
        if (section_in_text_seg (section)) {
        
            command_size += sizeof (section_64);
            num_sects++;
            
            memcpy (section_64.sect_name, section->name, 
                (strlen (section->name) >= sizeof (section_64.sect_name)) ?
                    sizeof (section_64.seg_name) : strlen (section->name));
            
            if (section_64.sect_name[0] == '.') {
            
                memmove (section_64.sect_name + 2, section_64.sect_name + 1, sizeof (section_64.sect_name) - 2);
                section_64.sect_name[0] = section_64.sect_name[1] = '_';
            
            }
            
            strcpy (section_64.seg_name, "__TEXT");
            
            integer_to_array (state->base_address + section->rva, section_64.addr, 8, 0);
            integer_to_array (section->total_size, section_64.size, 8, 0);
            integer_to_array (log_base2 (section->section_alignment), section_64.align, 4, 0);
            
            if (section->flags & SECTION_FLAG_CODE) {
                integer_to_array ((0x80000000 | S_REGULAR), section_64.flags, 4, 0);
            } else if (strcmp (section->name, "__cstring") == 0) {
                integer_to_array (S_CSTRING_LITERALS, section_64.flags, 4, 0);
            }
            
            vm_addr = array_to_integer (segment_cmd.vm_addr, 8, 0);
            vm_size = state->base_address + section->rva + section->total_size - vm_addr;
            
            if (!section->is_bss) {
            
                content = data + ALIGN (content - data, section->section_alignment);
                integer_to_array (content - data, section_64.offset, 4, 0);
                
                section_write (section, content);
                content += section->total_size;
            
            }
            
            memcpy (pos, &section_64, sizeof (section_64));
            pos += sizeof (section_64);
        
        }
    
    }
    
    integer_to_array (command_size, segment_cmd.command_size, 4, 0);
    integer_to_array (num_sects, segment_cmd.num_sects, 4, 0);
    integer_to_array (ALIGN (vm_size, PAGE_SIZE), segment_cmd.vm_size, 8, 0);
    
    content = data + ALIGN (content - data, PAGE_SIZE);
    
    file_offset = array_to_integer (segment_cmd.file_off, 8, 0);
    integer_to_array (content - data - file_offset, segment_cmd.file_size, 8, 0);
    
    memcpy (saved_pos, &segment_cmd, sizeof (segment_cmd));
    
    vm_addr = 0;
    vm_size = 0;
    
    memset (&segment_cmd, 0, sizeof (segment_cmd));
    integer_to_array (LC_SEGMENT_64, segment_cmd.command, 4, 0);
    
    command_size = sizeof (segment_cmd);
    num_sects = 0;
    
    strcpy (segment_cmd.seg_name, "__DATA");
    integer_to_array (content - data, segment_cmd.file_off, 8, 0);
    
    integer_to_array (PROT_READ | PROT_WRITE, segment_cmd.max_prot, 4, 0);
    integer_to_array (PROT_READ | PROT_WRITE, segment_cmd.init_prot, 4, 0);
    
    saved_pos = pos;
    pos += sizeof (segment_cmd);
    
    for (section = all_sections; section; section = section->next) {
    
        memset (&section_64, 0, sizeof (section_64));
        
        if (section_in_data_seg (section)) {
        
            if (!(vm_addr = array_to_integer (segment_cmd.vm_addr, 8, 0))) {
            
                vm_addr = state->base_address + section->rva;
                integer_to_array (vm_addr, segment_cmd.vm_addr, 8, 0);
            
            }
            
            command_size += sizeof (section_64);
            num_sects++;
            
            memcpy (section_64.sect_name, section->name, 
                (strlen (section->name) >= sizeof (section_64.sect_name)) ?
                    sizeof (section_64.seg_name) : strlen (section->name));
            
            if (section_64.sect_name[0] == '.') {
            
                memmove (section_64.sect_name + 2, section_64.sect_name + 1, sizeof (section_64.sect_name) - 2);
                section_64.sect_name[0] = section_64.sect_name[1] = '_';
            
            }
            
            strcpy (section_64.seg_name, "__DATA");
            
            integer_to_array (state->base_address + section->rva, section_64.addr, 8, 0);
            integer_to_array (section->total_size, section_64.size, 8, 0);
            integer_to_array (log_base2 (section->section_alignment), section_64.align, 4, 0);
            
            if (!(section->flags & SECTION_FLAG_LOAD)) {
                integer_to_array (S_ZEROFILL, section_64.flags, 4, 0);
            }
            
            vm_size = state->base_address + section->rva + section->total_size - vm_addr;
            
            if (!section->is_bss) {
            
                content = data + ALIGN (content - data, section->section_alignment);
                integer_to_array (content - data, section_64.offset, 4, 0);
                
                section_write (section, content);
                content += section->total_size;
            
            }
            
            memcpy (pos, &section_64, sizeof (section_64));
            pos += sizeof (section_64);
        
        }
    
    }
    
    integer_to_array (command_size, segment_cmd.command_size, 4, 0);
    integer_to_array (num_sects, segment_cmd.num_sects, 4, 0);
    integer_to_array (ALIGN (vm_size, PAGE_SIZE), segment_cmd.vm_size, 8, 0);
    
    content = data + ALIGN (content - data, PAGE_SIZE);
    
    file_offset = array_to_integer (segment_cmd.file_off, 8, 0);
    integer_to_array (content - data - file_offset, segment_cmd.file_size, 8, 0);
    
    memcpy (saved_pos, &segment_cmd, sizeof (segment_cmd));
    data_segment_offset = array_to_integer (segment_cmd.file_off, 8, 0);
    
    vm_addr = array_to_integer (segment_cmd.vm_addr, 8, 0);
    vm_size = array_to_integer (segment_cmd.vm_size, 8, 0);
    
    memset (&segment_cmd, 0, sizeof (segment_cmd));
    
    integer_to_array (LC_SEGMENT_64, segment_cmd.command, 4, 0);
    integer_to_array (sizeof (segment_cmd), segment_cmd.command_size, 4, 0);
    
    strcpy (segment_cmd.seg_name, "__LINKEDIT");
    
    vm_addr += vm_size;
    integer_to_array (vm_addr, segment_cmd.vm_addr, 8, 0);
    
    vm_size = data_size - (content - data);
    integer_to_array (ALIGN (vm_size, PAGE_SIZE), segment_cmd.vm_size, 8, 0);
    
    integer_to_array (PROT_READ, segment_cmd.max_prot, 4, 0);
    integer_to_array (PROT_READ, segment_cmd.init_prot, 4, 0);
    
    file_offset = content - data;
    
    integer_to_array (file_offset, segment_cmd.file_off, 8, 0);
    integer_to_array (data_size - file_offset, segment_cmd.file_size, 8, 0);
        
    memcpy (pos, &segment_cmd, sizeof (segment_cmd));
    pos += sizeof (segment_cmd);
    
    if (!_static) {
    
        integer_to_array (LC_DYLD_CHAINED_FIXUPS, dyld_chained_fixups_command.command, 4, 0);
        integer_to_array (sizeof (dyld_chained_fixups_command), dyld_chained_fixups_command.command_size, 4, 0);
        integer_to_array (content - data, dyld_chained_fixups_command.data_offset, 4, 0);
        
        {
        
            unsigned char *saved = content, *starts;
            
            memset (&dyld_chained_fixups_header, 0, sizeof (dyld_chained_fixups_header));
            integer_to_array (DYLD_CHAINED_IMPORT, dyld_chained_fixups_header.imports_format, 4, 0);
            
            content += sizeof (dyld_chained_fixups_header);
            integer_to_array (content - saved, dyld_chained_fixups_header.starts_offset, 4, 0);
            
            starts = content;
            
            integer_to_array (NUM_SEGS, content, 4, 0);
            integer_to_array (0, content + 4, 4, 0);
            integer_to_array (0, content + 8, 4, 0);
            integer_to_array (0, content + 12, 4, 0);
            integer_to_array (0, content + 16, 4, 0);
            integer_to_array (0, content + 20, 4, 0);
            
            content += 24;
            
            if (chained_fixups[2].page_count) {
            
                struct chained_fixup_starts *cfs = &chained_fixups[2];
                
                unsigned long count, size;
                int i;
                
                integer_to_array (content - starts, starts + 12, 4, 0);
                
                integer_to_array (sizeof (dyld_chained_starts_in_segment), dyld_chained_starts_in_segment.size, 4, 0);
                integer_to_array (PAGE_SIZE, dyld_chained_starts_in_segment.page_size, 2, 0);
                integer_to_array (6, dyld_chained_starts_in_segment.pointer_format, 2, 0);
                integer_to_array (data_segment_offset, dyld_chained_starts_in_segment.segment_offset, 8, 0);
                integer_to_array (0, dyld_chained_starts_in_segment.max_valid_pointer, 4, 0);
                integer_to_array (cfs->page_count, dyld_chained_starts_in_segment.page_count, 2, 0);
                integer_to_array (cfs->page_starts[0], dyld_chained_starts_in_segment.page_start, 2, 0);
                
                count = array_to_integer (dyld_chained_starts_in_segment.page_count, 2, 0);
                
                size  = array_to_integer (dyld_chained_starts_in_segment.size, 2, 0);
                size += count * 2 - 2;
                
                integer_to_array (ALIGN (size, 4), dyld_chained_starts_in_segment.size, 4, 0);
                
                memcpy (content, &dyld_chained_starts_in_segment, sizeof (dyld_chained_starts_in_segment));
                content += sizeof (dyld_chained_starts_in_segment);
                
                for (i = 1; i < cfs->page_count; i++) {
                
                    integer_to_array (cfs->page_starts[i], content, 2, 0);
                    content += 2;
                
                }
                
                content = data + ALIGN (content - data, 4);
                free (cfs->page_starts);
            
            }
            
            integer_to_array (content - saved, dyld_chained_fixups_header.imports_offset, 4, 0);
            integer_to_array (content - saved, dyld_chained_fixups_header.symbols_offset, 4, 0);
            
            integer_to_array (0, content, 4, 0);
            content += 4;
            
            integer_to_array (0, content, 4, 0);
            content += 4;
            
            memcpy (saved, &dyld_chained_fixups_header, sizeof (dyld_chained_fixups_header));
        
        }
        
        integer_to_array (content - data - array_to_integer (dyld_chained_fixups_command.data_offset, 4, 0), dyld_chained_fixups_command.data_size, 4, 0);
        
        memcpy (pos, &dyld_chained_fixups_command, sizeof (dyld_chained_fixups_command));
        pos += array_to_integer (dyld_chained_fixups_command.command_size, 4, 0);
        
        integer_to_array (LC_DYLD_EXPORTS_TRIE, dyld_exports_trie.command, 4, 0);
        integer_to_array (sizeof (dyld_exports_trie), dyld_exports_trie.command_size, 4, 0);
        integer_to_array (content - data, dyld_exports_trie.data_offset, 4, 0);
        
        {
        
            unsigned char *saved = content;
            
            content[0] = 0;
            content[1] = 1;
            content += 2;
            
            strcpy ((char *) content, MH_HEADER_SYMBOL_NAME);
            content += sizeof (MH_HEADER_SYMBOL_NAME);
            
            content[0] = content - saved + 1;
            content[1] = 2;
            
            content = saved + 0x980;
        
        }
        
        integer_to_array (content - data - array_to_integer (dyld_exports_trie.data_offset, 4, 0), dyld_exports_trie.data_size, 4, 0);
        
        memcpy (pos, &dyld_exports_trie, sizeof (dyld_exports_trie));
        pos += array_to_integer (dyld_exports_trie.command_size, 4, 0);
        
        integer_to_array (LC_LOAD_DYLINKER, dylinker.command, 4, 0);
        integer_to_array (ALIGN (sizeof (dylinker) + sizeof (DYLINKER_STRING), 8), dylinker.command_size, 4, 0);
        integer_to_array (sizeof (dylinker), dylinker.name_offset, 4, 0);
        
        memcpy (pos, &dylinker, sizeof (dylinker));
        
        strcpy ((char *) pos + sizeof (dylinker), DYLINKER_STRING);
        pos += array_to_integer (dylinker.command_size, 4, 0);
        
        integer_to_array (LC_FUNCTION_STARTS, function_starts_command.command, 4, 0);
        integer_to_array (sizeof (function_starts_command), function_starts_command.command_size, 4, 0);
        integer_to_array (content - data, function_starts_command.data_offset, 4, 0);
        
        memcpy (content, function_starts, function_starts_size);
        
        content += function_starts_size;
        free (function_starts);
        
        integer_to_array (content - data - array_to_integer (function_starts_command.data_offset, 4, 0), function_starts_command.data_size, 4, 0);
        
        memcpy (pos, &function_starts_command, sizeof (function_starts_command));
        pos += array_to_integer (function_starts_command.command_size, 4, 0);
        
        integer_to_array (LC_SYMTAB, symtab_cmd.command, 4, 0);
        integer_to_array (sizeof (symtab_cmd), symtab_cmd.command_size, 4, 0);
        
        symbol_offset = content - data;
        
        integer_to_array (symbol_offset, symtab_cmd.symbol_offset, 4, 0);
        integer_to_array (0, symtab_cmd.num_symbols, 4, 0);
        
        integer_to_array (4, nlist_64.n_strx, 4, 0);
        
        nlist_64.n_type[0] = MACHO_N_SECT | MACHO_N_EXT;
        nlist_64.n_sect[0] = 1;
        
        integer_to_array (0x10, nlist_64.n_desc, 2, 0);
        integer_to_array (state->base_address, nlist_64.n_value, 8, 0);
        
        memcpy (content, &nlist_64, sizeof (nlist_64));
        content += sizeof (nlist_64);
        
        integer_to_array (array_to_integer (symtab_cmd.num_symbols, 4, 0) + 1, symtab_cmd.num_symbols, 4, 0);
        integer_to_array (content - data, symtab_cmd.string_offset, 4, 0);
        
        memset (content, '\0', 4);
        content += 4;
        
        strcpy ((char *) content, MH_HEADER_SYMBOL_NAME);
        content += sizeof (MH_HEADER_SYMBOL_NAME);
        
        integer_to_array (content - data - array_to_integer (symtab_cmd.string_offset, 4, 0), symtab_cmd.string_size, 4, 0);
        
        memcpy (pos, &symtab_cmd, sizeof (symtab_cmd));
        pos += array_to_integer (symtab_cmd.command_size, 4, 0);
        
        integer_to_array (LC_DYSYMTAB, dysymtab.cmd, 4, 0);
        integer_to_array (sizeof (dysymtab), dysymtab.cmdsize, 4, 0);
        integer_to_array (1, dysymtab.nextdefsym, 4, 0);
        integer_to_array (1, dysymtab.iundefsym, 4, 0);
        
        memcpy (pos, &dysymtab, sizeof (dysymtab));
        pos += array_to_integer (dysymtab.cmdsize, 4, 0);
        
        integer_to_array (LC_VERSION_MIN, version_min.command, 4, 0);
        integer_to_array (sizeof (version_min), version_min.command_size, 4, 0);
        integer_to_array (minos_version, version_min.version, 4, 0);
        integer_to_array (SDK_VERSION, version_min.sdk, 4, 0);
        
        memcpy (pos, &version_min, sizeof (version_min));
        pos += array_to_integer (version_min.command_size, 4, 0);
        
        integer_to_array (LC_LOAD_DYLIB, dylib_command.command, 4, 0);
        integer_to_array (ALIGN (sizeof (dylib_command) + sizeof (DYLIB_STRING), 8), dylib_command.command_size, 4, 0);
        integer_to_array (sizeof (dylib_command), dylib_command.name_offset, 4, 0);
        integer_to_array (2, dylib_command.timestamp, 4, 0);
        integer_to_array (0x05276403, dylib_command.current_version, 4, 0);
        integer_to_array (0x00010000, dylib_command.compatibility_version, 4, 0);
        
        memcpy (pos, &dylib_command, sizeof (dylib_command));
        strcpy ((char *) pos + sizeof (dylib_command), DYLIB_STRING);
        
        pos += array_to_integer (dylib_command.command_size, 4, 0);
        
        integer_to_array (LC_SOURCE_VERSION, source_version.command, 4, 0);
        integer_to_array (sizeof (source_version), source_version.command_size, 4, 0);
        integer_to_array (0, source_version.version, 8, 0);
        
        memcpy (pos, &source_version, sizeof (source_version));
        pos += array_to_integer (source_version.command_size, 4, 0);
        
        integer_to_array (LC_DATA_IN_CODE, data_in_code.command, 4, 0);
        integer_to_array (sizeof (data_in_code), data_in_code.command_size, 4, 0);
        integer_to_array (symbol_offset, data_in_code.data_offset, 4, 0);
        integer_to_array (0, data_in_code.data_size, 4, 0);
        
        memcpy (pos, &data_in_code, sizeof (data_in_code));
        pos += array_to_integer (data_in_code.command_size, 4, 0);
        
        integer_to_array (LC_MAIN, main_command.command, 4, 0);
        integer_to_array (sizeof (main_command), main_command.command_size, 4, 0);
        integer_to_array (state->entry_point, main_command.entry_offset, 8, 0);
        integer_to_array (0, main_command.stack_size, 8, 0);
        
        memcpy (pos, &main_command, sizeof (main_command));
        pos += array_to_integer (main_command.command_size, 4, 0);
    
    } else {
    
        integer_to_array (LC_SYMTAB, symtab_cmd.command, 4, 0);
        integer_to_array (sizeof (symtab_cmd), symtab_cmd.command_size, 4, 0);
        
        memcpy (pos, &symtab_cmd, sizeof (symtab_cmd));
        pos += array_to_integer (symtab_cmd.command_size, 4, 0);
        
        integer_to_array (LC_UNIXTHREAD, unixthread.command, 4, 0);
        integer_to_array (sizeof (unixthread) + sizeof (thread_state64), unixthread.command_size, 4, 0);
        integer_to_array (0x04, unixthread.flavor, 4, 0);
        integer_to_array (0x2A, unixthread.count, 4, 0);
        
        memcpy (pos, &unixthread, sizeof (unixthread));
        
        integer_to_array (state->base_address + state->entry_point, thread_state64.rip, 8, 0);
        memcpy (pos + sizeof (unixthread), &thread_state64, sizeof (thread_state64));
        
        pos += array_to_integer (unixthread.command_size, 4, 0);
    
    }
    
    if (fwrite (data, data_size, 1, fp) != 1) {
        report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", filename);
    }
    
    free (data);
    fclose (fp);

}
