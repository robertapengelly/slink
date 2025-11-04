/******************************************************************************
 * @file            elf.c
 *****************************************************************************/
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "ld.h"
#include    "lib.h"
#include    "elf.h"
#include    "report.h"
#include    "section.h"
#include    "stdint.h"
#include    "symbol.h"

#define     UNNAMED_SYMBOL_NAME         "(unnamed)"

#define     SHT_RELA                    4
#define     SHT_REL                     9

#define     ELF32_R_SYM(i)              ((i) >> 8)
#define     ELF32_R_TYPE(i)             ((unsigned char) (i))

static void translate_relocation (const char *filename, struct reloc_entry *reloc, struct elf32_rel *input_rel, struct section_part *part, int endianess) {

    uint32_t r_info = array_to_integer (input_rel->r_info, 4, endianess);
    uint32_t r_offset = array_to_integer (input_rel->r_offset, 4, endianess);
    
    uint32_t symbol_index = ELF32_R_SYM (r_info), rel_type = ELF32_R_TYPE (r_info);
    
    if (symbol_index >= part->of->symbol_cnt) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: relocation has invalid symbol index", filename);
        goto bad;
    
    }
    
    if (r_offset >= part->content_size || r_offset + 4 > part->content_size) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: relocation has invalid r_offset", filename);
        goto bad;
    
    }
    
    reloc->symbol = part->of->symbol_arr + symbol_index;
    reloc->offset = r_offset;
    
    if ((state->format & LD_TARGET_MACHINE_I386)) {
    
        switch (rel_type) {
        
            case R_386_NONE:
            
                goto bad;
            
            case R_386_32:
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_32];
                break;
            
            case R_386_PC32:
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                reloc->addend += 4;
                
                break;
            
            default:
            
                report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++relocation type 0x%02x not supported yet", rel_type);
                exit (EXIT_FAILURE);
        
        }
    
    } else {
    bad:
    
        reloc->symbol = 0;
        reloc->offset = 0;
        
        reloc->howto = &reloc_howtos[RELOC_TYPE_IGNORED];
    
    }

}

#define     ELF64_R_SYM(i)              ((i) >> 32)
#define     ELF64_R_TYPE(i)             ((i) & 0xffffffff)

static void translate_relocation64_addend (const char *filename, struct reloc_entry *reloc, struct elf64_rela *input_reloc, struct section_part *part, int endianess) {

    uint64_t r_info = array_to_integer (input_reloc->r_info, 8, endianess);
    uint64_t r_offset = array_to_integer (input_reloc->r_offset, 8, endianess);
    
    uint32_t symbol_index = ELF64_R_SYM (r_info), rel_type = ELF64_R_TYPE (r_info);
    
    if (symbol_index >= part->of->symbol_cnt) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: relocation has invalid symbol index", filename);
        goto bad;
    
    }
    
    if (r_offset >= part->content_size) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: relocation has invalid r_offset", filename);
        goto bad;
    
    }
    
    reloc->symbol = part->of->symbol_arr + symbol_index;
    reloc->offset = r_offset;
    reloc->addend = array_to_integer (input_reloc->r_addend, 8, endianess);
    
    if ((state->format & LD_TARGET_MACHINE_AMD64)) {
    
        switch (rel_type) {
        
            case R_AMD64_NONE:
            
                goto bad;
            
            case R_AMD64_64:
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_64];
                break;
            
            case R_AMD64_PC32:
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                break;
            
            case R_AMD64_PLT32:
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                break;
            
            case R_AMD64_RELATIVE:
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_64];
                break;
            
            case R_AMD64_32:
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_32];
                break;
            
            case R_AMD64_32S:
            
                reloc->howto = &reloc_howtos[RELOC_TYPE_32];
                break;
            
            default:
            
                report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++relocation type 0x%02x not supported yet", rel_type);
                exit (EXIT_FAILURE);
        
        }
        
        if (reloc->howto->pc_rel && !reloc->howto->special_function) {
            reloc->addend += reloc->howto->size;
        }
    
    } else {
    bad:
    
        reloc->symbol = 0;
        reloc->offset = 0;
        reloc->addend = 0;
        
        reloc->howto = &reloc_howtos[RELOC_TYPE_IGNORED];
    
    }

}

#define     ELF32_ST_BIND(i)            ((i) >> 4)
# define        STB_LOCAL               0
# define        STB_GLOBAL              1

#define     ELF32_ST_TYPE(i)            ((i) & 0x0F)
# define        STT_SECTION             3

static uint64_t translate_sh_flags_to_section_flags (uint64_t sh_flags) {

    uint64_t flags = 0;
    
    if (!(sh_flags & SHF_WRITE)) {
        flags |= SECTION_FLAG_READONLY;
    }
    
    if (sh_flags & SHF_ALLOC) {
        flags |= SECTION_FLAG_ALLOC;
    }
    
    if (sh_flags & SHF_EXEC_INSTR) {
        flags |= SECTION_FLAG_CODE;
    }
    
    return flags;

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

void read_elf32_object (const char *filename, unsigned char *data, unsigned long data_size, int endianess) {

    unsigned char *pos = (unsigned char *) data;
    
    uint32_t e_shoff, sh_type, sh_link, sh_offset, sh_size, sh_entsize, sh_info;
    uint16_t e_shentsize, e_shstrndx, e_shnum;
    
    struct elf32_exec *header;
    struct elf32_shdr *shdr, *strtab_hdr;
    
    struct elf32_sym *elf_symbol;
    struct symbol *symbol, *old_symbol;
    
    char *section_name_string_table = 0, *sym_strtab, *section_name, *p;
    uint32_t section_name_string_table_size = 0, sym_strtab_size, st_name, i, j;
    
    struct section_part **part_p_array, *bss_part;
    struct object_file *of = 0;
    
    struct section_part *part;
    struct section *section;
    struct subsection *subsection;
    
    struct section *bss_section = 0;
    uint64_t bss_section_number = 0;
    
    struct elf32_rela *rela;
    struct elf32_rel rel;
    
    CHECK_READ (pos, sizeof (*header));
    
    header = (struct elf32_exec *) pos;
    pos += sizeof (*header);
    
    if (header->e_ident[EI_VERSION] != EV_CURRENT) {
        
        report_at (program_name, 0, REPORT_ERROR, "%s: unsupported ELF version", filename);
        return;
    
    }
    
    if (array_to_integer (header->e_type, 2, endianess) != ET_REL) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: e_type is no ET_REL", filename);
        return;
    
    }
    
    if (array_to_integer (header->e_version, 4, endianess) != EV_CURRENT) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: unsupported ELF version", filename);
        return;
    
    }
    
    if (array_to_integer (header->e_ehsize, 2, endianess) < sizeof (*header)) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: e_ehsize is too small", filename);
        return;
    
    }
    
    e_shnum = array_to_integer (header->e_shnum, 2, endianess);
    e_shoff = array_to_integer (header->e_shoff, 4, endianess);
    
    e_shentsize = array_to_integer (header->e_shentsize, 2, endianess);
    
    if (e_shoff == 0 || e_shentsize == 0 || e_shnum == 0) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: missing section header table", filename);
        return;
    
    }
    
    if (e_shentsize < sizeof (*shdr)) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: e_shentsize is too small", filename);
        return;
    
    }
    
    e_shstrndx = array_to_integer (header->e_shstrndx, 2, endianess);
    
    if (e_shstrndx == 0 || e_shstrndx >= e_shnum) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: missing section header table", filename);
        return;
    
    }
    
    pos = data + e_shoff;
    
    CHECK_READ (pos, (unsigned long) (e_shentsize * e_shnum));
    pos += e_shentsize * e_shstrndx;
    
    shdr = (struct elf32_shdr *) pos;
    
    if (array_to_integer (shdr->sh_type, 4, endianess) != SHT_STRTAB) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: section name string table does no have SHT_STRTAB type", filename);
        return;
    
    }
    
    section_name_string_table_size = array_to_integer (shdr->sh_size, 4, endianess);
    
    pos = data + array_to_integer (shdr->sh_offset, 4, endianess);
    CHECK_READ (pos, (unsigned long) section_name_string_table_size);
    
    section_name_string_table = (char *) pos;
    part_p_array = xmalloc (sizeof (*part_p_array) * (e_shnum + 1));
    
    for (i = 1; i < e_shnum; i++) {
    
        shdr = (struct elf32_shdr *) (pos = data + e_shoff + i * e_shentsize);
        
        if (array_to_integer (shdr->sh_type, 4, endianess) != SHT_SYMTAB) {
            continue;
        }
        
        if (of) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: more than 1 symbol table per object file", filename);
            exit (EXIT_FAILURE);
        
        }
        
        of = object_file_make (filename, array_to_integer (shdr->sh_size, 4, endianess) / array_to_integer (shdr->sh_entsize, 4, endianess));
    
    }
    
    for (i = 1; i < e_shnum; i++) {
    
        shdr = (struct elf32_shdr *) (pos = data + e_shoff + i * e_shentsize);
        
        if (array_to_integer (shdr->sh_name, 4, endianess) < section_name_string_table_size) {
            section_name = xstrdup (section_name_string_table + array_to_integer (shdr->sh_name, 4, endianess));
        } else {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid offset into string table", filename);
            exit (EXIT_FAILURE);
        
        }
        
        sh_type = array_to_integer (shdr->sh_type, 4, endianess);
        
        if (sh_type != SHT_PROGBITS && sh_type != SHT_NOBITS) {
        
            part_p_array[i] = 0;
            
            free (section_name);
            continue;
        
        }
        
        if ((p = strrchr (section_name, '.'))) {
        
            if (p != section_name) {
                *p++ = '\0';
            }
        
        }
        
        section = section_find_or_make (section_name);
        
        if (array_to_integer (shdr->sh_addralign, 4, endianess) > section->section_alignment) {
            section->section_alignment = array_to_integer (shdr->sh_addralign, 4, endianess);
        }
        
        section->flags = translate_sh_flags_to_section_flags (array_to_integer (shdr->sh_flags, 4, endianess));
        
        if (sh_type == SHT_NOBITS) {
            section->is_bss = 1;
        } else {
            section->flags |= SECTION_FLAG_LOAD;
        }
        
        if (p) {
            subsection = subsection_find_or_make (section, p);
        } else {
            subsection = 0;
        }
        
        free (section_name);
        
        part = section_part_new (section, of);
        part->alignment = array_to_integer (shdr->sh_addralign, 4, endianess);
        
        part->content_size = array_to_integer (shdr->sh_size, 4, endianess);
        
        if (sh_type != SHT_NOBITS) {
        
            pos = data + array_to_integer (shdr->sh_offset, 4, endianess);
            
            part->content = xmalloc (part->content_size);
            CHECK_READ (pos, part->content_size);
            
            memcpy (part->content, pos, part->content_size);
        
        }
        
        if (section->is_bss) {
        
            bss_section_number = i;
            bss_section = section;
        
        }
        
        if (subsection) {
            subsection_append_section_part (subsection, part);
        } else {
            section_append_section_part (section, part);
        }
        
        part_p_array[i] = part;
    
    }
    
    for (i = 1; i < e_shnum; i++) {
    
        shdr = (struct elf32_shdr *) (pos = data + e_shoff + i * e_shentsize);
        
        if (array_to_integer (shdr->sh_type, 4, endianess) != SHT_SYMTAB) {
            continue;
        }
        
        sh_link = array_to_integer (shdr->sh_link, 4, endianess);
        
        if (sh_link == 0 || sh_link >=  e_shnum) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: symtab has invalid sh_link", filename);
            exit (EXIT_FAILURE);
        
        }
        
        strtab_hdr = (struct elf32_shdr *) (pos = data + e_shoff + sh_link * e_shentsize);
        
        sym_strtab_size = array_to_integer (strtab_hdr->sh_size, 4, endianess);
        
        pos = data + array_to_integer (strtab_hdr->sh_offset, 4, endianess);
        CHECK_READ (pos, (unsigned long) sym_strtab_size);
        
        sym_strtab = (char *) pos;
        
        sh_entsize = array_to_integer (shdr->sh_entsize, 4, endianess);
        sh_offset = array_to_integer (shdr->sh_offset, 4, endianess);
        sh_size = array_to_integer (shdr->sh_size, 4, endianess);
        
        pos = data + sh_offset;
        CHECK_READ (pos, (unsigned long) sh_size);
        
        if (sh_entsize < sizeof (*elf_symbol)) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: symbol table sh_entsize is too small", filename);
            exit (EXIT_FAILURE);
        
        }
        
        for (j = 1; j < sh_size / sh_entsize; j++) {
        
            elf_symbol = (struct elf32_sym *) (data + sh_offset + j * sh_entsize);
            symbol = of->symbol_arr + j;
            
            if ((st_name = array_to_integer (elf_symbol->st_name, 4, endianess)) < sym_strtab_size) {
            
                if (sym_strtab[st_name] == '\0') {
                    symbol->name = xstrdup (UNNAMED_SYMBOL_NAME);
                } else {
                    symbol->name = xstrdup (sym_strtab + st_name);
                }
            
            } else {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid offset into string table", filename);
                exit (EXIT_FAILURE);
            
            }
            
            symbol->value = array_to_integer (elf_symbol->st_value, 4, endianess);
            symbol->size = array_to_integer (elf_symbol->st_size, 4, endianess);
            
            symbol->section_number = array_to_integer (elf_symbol->st_shndx, 2, endianess);
            
            if (symbol->section_number == SHN_UNDEF) {
            
                symbol->section_number = UNDEFINED_SECTION_NUMBER;
                symbol->part = 0;
            
            } else if (symbol->section_number == SHN_ABS) {
            
                symbol->section_number = ABSOLUTE_SECTION_NUMBER;
                symbol->part = 0;
            
            } else if (symbol->section_number == SHN_COMMON) {
            
                if (symbol->size) {
                
                    old_symbol = symbol_find (symbol->name);
                    
                    if (ELF32_ST_BIND (elf_symbol->st_info[0]) != STB_GLOBAL) {
                    
                        report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: non-global common symbol", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    if (!old_symbol || symbol_is_undefined (old_symbol)) {
                    
                        if (!bss_section) {
                        
                            bss_section = section_find_or_make (".bss");
                            
                            if (bss_section->section_alignment < 4) {
                                bss_section->section_alignment = 4;
                            }
                            
                            bss_section->flags = translate_sh_flags_to_section_flags (SHF_WRITE | SHF_ALLOC);
                            bss_section->is_bss = 1;
                            
                            bss_section_number = e_shnum ? e_shnum : 1;
                        
                        }
                        
                        bss_part = section_part_new (bss_section, of);
                        section_append_section_part (bss_section, bss_part);
                        
                        
                        bss_part->content_size = symbol->size;
                        bss_part->alignment = symbol->value;
                        
                        symbol->part = bss_part;
                        symbol->value = 0;
                        
                        symbol->section_number = bss_section_number;
                    
                    } else {
                    
                        if (symbol->size > old_symbol->size) {
                            old_symbol->part->content_size = old_symbol->size = symbol->size;
                        }
                        
                        if (symbol->value > old_symbol->part->alignment) {
                            old_symbol->part->alignment = symbol->value;
                        }
                        
                        symbol->part = 0;
                        symbol->value = 0;
                        
                        symbol->section_number = UNDEFINED_SECTION_NUMBER;
                    
                    }
                
                } else {
                
                    symbol->section_number = UNDEFINED_SECTION_NUMBER;
                    symbol->part = 0;
                
                }
            
            } else if (symbol->section_number >= SHN_LORESERVE && symbol->section_number <= SHN_HIRESERVE) {
            
                report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++not yet supported symbol st_shndx: %hu", symbol->section_number);
                exit (EXIT_FAILURE);
            
            } else if (symbol->section_number >= e_shnum) {
            
                report_at (program_name, 0, REPORT_ERROR, "%s: invalid symbol st_shndx: %hu", filename, symbol->section_number);
                symbol->part = 0;
            
            } else {
                symbol->part = part_p_array[symbol->section_number];
            }
            
            switch (ELF32_ST_BIND (elf_symbol->st_info[0])) {
            
                case STB_LOCAL:
                
                    break;
                
                case STB_GLOBAL:
                
                    symbol_record_external_symbol (symbol);
                    break;
                
                default:
                
                    report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++not yet supported symbol ELF32_ST_BIND: %u", ELF32_ST_BIND (elf_symbol->st_info[0]));
                    exit (EXIT_FAILURE);
            
            }
            
            if (ELF32_ST_TYPE (elf_symbol->st_info[0]) == STT_SECTION) {
                symbol->flags |= SYMBOL_FLAG_SECTION_SYMBOL;
            }
        
        }
    
    }
    
    for (i = 0; i < e_shnum; i++) {
    
        shdr = (struct elf32_shdr *) (pos = data + e_shoff + i * e_shentsize);
        
        sh_type = array_to_integer (shdr->sh_type, 4, endianess);
        sh_size = array_to_integer (shdr->sh_size, 4, endianess);
        
        if ((sh_type != SHT_RELA && sh_type != SHT_REL) || sh_size == 0) {
            continue;
        }
        
        if ((sh_info = array_to_integer (shdr->sh_info, 4, endianess)) >= e_shnum) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: relocation section has invalid sh_info", filename);
            exit (EXIT_FAILURE);
        
        }
        
        if (!(part = part_p_array[sh_info])) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: relocation section has invalid sh_info", filename);
            exit (EXIT_FAILURE);
        
        }
        
        if (part->section->is_bss) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: relocation section sh_info points to BSS section", filename);
            exit (EXIT_FAILURE);
        
        }
        
        sh_entsize = array_to_integer (shdr->sh_entsize, 4, endianess);
        sh_offset = array_to_integer (shdr->sh_offset, 4, endianess);
        
        if ((sh_type == SHT_RELA && sh_entsize != sizeof (*rela)) || (sh_type == SHT_REL && sh_entsize != sizeof (rel))) {
        
            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++relocation shdr.sh_entsize not yet supported");
            exit (EXIT_FAILURE);
        
        }
        
        sh_size = array_to_integer (shdr->sh_size, 4, endianess);
        
        pos = data + sh_offset;
        CHECK_READ (pos, (unsigned long) sh_size);
        
        part->reloc_cnt = sh_size / sh_entsize;
        part->reloc_arr = xmalloc (part->reloc_cnt * sizeof (*part->reloc_arr));
        
        if (sh_type == SHT_RELA) {
        
            for (j = 0; j < part->reloc_cnt; j++) {
            
                rela = (struct elf32_rela *) (pos + sh_entsize * j);
                
                integer_to_array (array_to_integer (rela->r_offset, 4, endianess), rel.r_offset, 4, endianess);
                integer_to_array (array_to_integer (rela->r_info, 4, endianess), rel.r_info, 4, endianess);
                
                part->reloc_arr[j].addend = array_to_integer (rela->r_addend, 4, endianess);
                translate_relocation (filename, part->reloc_arr + j, &rel, part, endianess);
            
            }
        
        } else {
        
            for (j = 0; j < part->reloc_cnt; j++) {
            
                memcpy (&rel, pos + sh_entsize * j, sizeof (rel));
                translate_relocation (filename, part->reloc_arr + j, &rel, part, endianess);
            
            }
        
        }
    
    }
    
    free (part_p_array);

}

void read_elf64_object (const char *filename, unsigned char *data, unsigned long data_size, int endianess) {

    unsigned char *pos = (unsigned char *) data;
    
    uint64_t e_shoff, sh_type, sh_link, sh_offset, sh_size, sh_entsize, sh_info;
    uint16_t e_shentsize, e_shstrndx, e_shnum;
    
    struct elf64_exec *header;
    struct elf64_shdr *shdr, *strtab_hdr;
    
    struct elf64_sym *elf_symbol;
    struct symbol *symbol, *old_symbol;
    
    char *section_name_string_table = 0, *sym_strtab, *section_name, *p;
    uint64_t section_name_string_table_size = 0, sym_strtab_size, st_name, i, j;
    
    struct section_part **part_p_array, *bss_part;
    struct object_file *of = 0;
    
    struct section_part *part;
    struct section *section;
    struct subsection *subsection;
    
    struct section *bss_section = 0;
    uint64_t bss_section_number = 0;
    
    struct elf64_rela *rela;
    CHECK_READ (pos, sizeof (*header));
    
    header = (struct elf64_exec *) pos;
    pos += sizeof (*header);
    
    if (header->e_ident[EI_VERSION] != EV_CURRENT) {
        
        report_at (program_name, 0, REPORT_ERROR, "%s: unsupported ELF version", filename);
        return;
    
    }
    
    if (array_to_integer (header->e_type, 2, endianess) != ET_REL) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: e_type is no ET_REL", filename);
        return;
    
    }
    
    if (array_to_integer (header->e_version, 4, endianess) != EV_CURRENT) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: unsupported ELF version", filename);
        return;
    
    }
    
    if (array_to_integer (header->e_ehsize, 2, endianess) < sizeof (*header)) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: e_ehsize is too small", filename);
        return;
    
    }
    
    e_shnum = array_to_integer (header->e_shnum, 2, endianess);
    e_shoff = array_to_integer (header->e_shoff, 8, endianess);
    
    e_shentsize = array_to_integer (header->e_shentsize, 2, endianess);
    
    if (e_shoff == 0 || e_shentsize == 0 || e_shnum == 0) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: missing section header table", filename);
        return;
    
    }
    
    if (e_shentsize < sizeof (*shdr)) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: e_shentsize is too small", filename);
        return;
    
    }
    
    e_shstrndx = array_to_integer (header->e_shstrndx, 2, endianess);
    
    if (e_shstrndx == 0 || e_shstrndx >= e_shnum) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: missing section header table", filename);
        return;
    
    }
    
    pos = data + e_shoff;
    
    CHECK_READ (pos, (unsigned long) (e_shentsize * e_shnum));
    pos += e_shentsize * e_shstrndx;
    
    shdr = (struct elf64_shdr *) pos;
    
    if (array_to_integer (shdr->sh_type, 4, endianess) != SHT_STRTAB) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: section name string table does no have SHT_STRTAB type", filename);
        return;
    
    }
    
    section_name_string_table_size = array_to_integer (shdr->sh_size, 8, endianess);
    
    pos = data + array_to_integer (shdr->sh_offset, 8, endianess);
    CHECK_READ (pos, (unsigned long) section_name_string_table_size);
    
    section_name_string_table = (char *) pos;
    part_p_array = xmalloc (sizeof (*part_p_array) * (e_shnum + 1));
    
    for (i = 1; i < e_shnum; i++) {
    
        shdr = (struct elf64_shdr *) (pos = data + e_shoff + i * e_shentsize);
        
        if (array_to_integer (shdr->sh_type, 4, endianess) != SHT_SYMTAB) {
            continue;
        }
        
        if (of) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: more than 1 symbol table per object file", filename);
            exit (EXIT_FAILURE);
        
        }
        
        of = object_file_make (filename, array_to_integer (shdr->sh_size, 4, endianess) / array_to_integer (shdr->sh_entsize, 4, endianess));
    
    }
    
    for (i = 1; i < e_shnum; i++) {
    
        shdr = (struct elf64_shdr *) (pos = data + e_shoff + i * e_shentsize);
        
        if (array_to_integer (shdr->sh_name, 4, endianess) < section_name_string_table_size) {
            section_name = xstrdup (section_name_string_table + array_to_integer (shdr->sh_name, 4, endianess));
        } else {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid offset into string table", filename);
            exit (EXIT_FAILURE);
        
        }
        
        sh_type = array_to_integer (shdr->sh_type, 4, endianess);
        
        if (sh_type != SHT_PROGBITS && sh_type != SHT_NOBITS) {
        
            part_p_array[i] = 0;
            
            free (section_name);
            continue;
        
        }
        
        if ((p = strrchr (section_name, '.'))) {
        
            if (p != section_name) {
                *p++ = '\0';
            }
        
        }
        
        section = section_find_or_make (section_name);
        
        if (array_to_integer (shdr->sh_addralign, 8, endianess) > section->section_alignment) {
            section->section_alignment = array_to_integer (shdr->sh_addralign, 8, endianess);
        }
        
        section->flags = translate_sh_flags_to_section_flags (array_to_integer (shdr->sh_flags, 8, endianess));
        
        if (sh_type == SHT_NOBITS) {
            section->is_bss = 1;
        } else {
            section->flags |= SECTION_FLAG_LOAD;
        }
        
        if (p) {
            subsection = subsection_find_or_make (section, p);
        } else {
            subsection = 0;
        }
        
        free (section_name);
        
        part = section_part_new (section, of);
        part->alignment = array_to_integer (shdr->sh_addralign, 8, endianess);
        
        part->content_size = array_to_integer (shdr->sh_size, 8, endianess);
        
        if (sh_type != SHT_NOBITS) {
        
            pos = data + array_to_integer (shdr->sh_offset, 8, endianess);
            
            part->content = xmalloc (part->content_size);
            CHECK_READ (pos, part->content_size);
            
            memcpy (part->content, pos, part->content_size);
        
        }
        
        if (section->is_bss) {
        
            bss_section_number = i;
            bss_section = section;
        
        }
        
        if (subsection) {
            subsection_append_section_part (subsection, part);
        } else {
            section_append_section_part (section, part);
        }
        
        part_p_array[i] = part;
    
    }
    
    for (i = 1; i < e_shnum; i++) {
    
        shdr = (struct elf64_shdr *) (pos = data + e_shoff + i * e_shentsize);
        
        if (array_to_integer (shdr->sh_type, 4, endianess) != SHT_SYMTAB) {
            continue;
        }
        
        sh_link = array_to_integer (shdr->sh_link, 4, endianess);
        
        if (sh_link == 0 || sh_link >=  e_shnum) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: symtab has invalid sh_link", filename);
            exit (EXIT_FAILURE);
        
        }
        
        strtab_hdr = (struct elf64_shdr *) (pos = data + e_shoff + sh_link * e_shentsize);
        
        sym_strtab_size = array_to_integer (strtab_hdr->sh_size, 8, endianess);
        
        pos = data + array_to_integer (strtab_hdr->sh_offset, 8, endianess);
        CHECK_READ (pos, (unsigned long) sym_strtab_size);
        
        sym_strtab = (char *) pos;
        
        sh_entsize = array_to_integer (shdr->sh_entsize, 8, endianess);
        sh_offset = array_to_integer (shdr->sh_offset, 8, endianess);
        sh_size = array_to_integer (shdr->sh_size, 8, endianess);
        
        pos = data + sh_offset;
        CHECK_READ (pos, (unsigned long) sh_size);
        
        if (sh_entsize < sizeof (*elf_symbol)) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: symbol table sh_entsize is too small", filename);
            exit (EXIT_FAILURE);
        
        }
        
        for (j = 1; j < sh_size / sh_entsize; j++) {
        
            elf_symbol = (struct elf64_sym *) (data + sh_offset + j * sh_entsize);
            symbol = of->symbol_arr + j;
            
            if ((st_name = array_to_integer (elf_symbol->st_name, 4, endianess)) < sym_strtab_size) {
            
                if (sym_strtab[st_name] == '\0') {
                    symbol->name = xstrdup (UNNAMED_SYMBOL_NAME);
                } else {
                    symbol->name = xstrdup (sym_strtab + st_name);
                }
            
            } else {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid offset into string table", filename);
                exit (EXIT_FAILURE);
            
            }
            
            symbol->value = array_to_integer (elf_symbol->st_value, 8, endianess);
            symbol->size = array_to_integer (elf_symbol->st_size, 8, endianess);
            
            symbol->section_number = array_to_integer (elf_symbol->st_shndx, 2, endianess);
            
            if (symbol->section_number == SHN_UNDEF) {
            
                symbol->section_number = UNDEFINED_SECTION_NUMBER;
                symbol->part = 0;
            
            } else if (symbol->section_number == SHN_ABS) {
            
                symbol->section_number = ABSOLUTE_SECTION_NUMBER;
                symbol->part = 0;
            
            } else if (symbol->section_number == SHN_COMMON) {
            
                if (symbol->size) {
                
                    old_symbol = symbol_find (symbol->name);
                    
                    if (ELF32_ST_BIND (elf_symbol->st_info[0]) != STB_GLOBAL) {
                    
                        report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: non-global common symbol", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    if (!old_symbol || symbol_is_undefined (old_symbol)) {
                    
                        if (!bss_section) {
                        
                            bss_section = section_find_or_make (".bss");
                            
                            if (bss_section->section_alignment < 4) {
                                bss_section->section_alignment = 4;
                            }
                            
                            bss_section->flags = translate_sh_flags_to_section_flags (SHF_WRITE | SHF_ALLOC);
                            bss_section->is_bss = 1;
                            
                            bss_section_number = e_shnum ? e_shnum : 1;
                        
                        }
                        
                        bss_part = section_part_new (bss_section, of);
                        section_append_section_part (bss_section, bss_part);
                        
                        
                        bss_part->content_size = symbol->size;
                        bss_part->alignment = symbol->value;
                        
                        symbol->part = bss_part;
                        symbol->value = 0;
                        
                        symbol->section_number = bss_section_number;
                    
                    } else {
                    
                        if (symbol->size > old_symbol->size) {
                            old_symbol->part->content_size = old_symbol->size = symbol->size;
                        }
                        
                        if (symbol->value > old_symbol->part->alignment) {
                            old_symbol->part->alignment = symbol->value;
                        }
                        
                        symbol->part = 0;
                        symbol->value = 0;
                        
                        symbol->section_number = UNDEFINED_SECTION_NUMBER;
                    
                    }
                
                } else {
                
                    symbol->section_number = UNDEFINED_SECTION_NUMBER;
                    symbol->part = 0;
                
                }
            
            } else if (symbol->section_number >= SHN_LORESERVE && symbol->section_number <= SHN_HIRESERVE) {
            
                report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++not yet supported symbol st_shndx: %hu", symbol->section_number);
                exit (EXIT_FAILURE);
            
            } else if (symbol->section_number >= e_shnum) {
            
                report_at (program_name, 0, REPORT_ERROR, "%s: invalid symbol st_shndx: %hu", filename, symbol->section_number);
                symbol->part = 0;
            
            } else {
                symbol->part = part_p_array[symbol->section_number];
            }
            
            switch (ELF32_ST_BIND (elf_symbol->st_info[0])) {
            
                case STB_LOCAL:
                
                    break;
                
                case STB_GLOBAL:
                
                    symbol_record_external_symbol (symbol);
                    break;
                
                default:
                
                    report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++not yet supported symbol ELF32_ST_BIND: %u", ELF32_ST_BIND (elf_symbol->st_info[0]));
                    exit (EXIT_FAILURE);
            
            }
            
            if (ELF32_ST_TYPE (elf_symbol->st_info[0]) == STT_SECTION) {
                symbol->flags |= SYMBOL_FLAG_SECTION_SYMBOL;
            }
        
        }
    
    }
    
    for (i = 0; i < e_shnum; i++) {
    
        shdr = (struct elf64_shdr *) (pos = data + e_shoff + i * e_shentsize);
        
        sh_type = array_to_integer (shdr->sh_type, 4, endianess);
        sh_size = array_to_integer (shdr->sh_size, 8, endianess);
        
        if ((sh_type != SHT_RELA && sh_type != SHT_REL) || sh_size == 0) {
            continue;
        }
        
        if ((sh_info = array_to_integer (shdr->sh_info, 4, endianess)) >= e_shnum) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: relocation section has invalid sh_info", filename);
            exit (EXIT_FAILURE);
        
        }
        
        if (!(part = part_p_array[sh_info])) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: relocation section has invalid sh_info", filename);
            exit (EXIT_FAILURE);
        
        }
        
        if (part->section->is_bss) {
        
            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: relocation section sh_info points to BSS section", filename);
            exit (EXIT_FAILURE);
        
        }
        
        sh_entsize = array_to_integer (shdr->sh_entsize, 8, endianess);
        sh_offset = array_to_integer (shdr->sh_offset, 8, endianess);
        
        if ((sh_type == SHT_RELA && sh_entsize != sizeof (*rela)) || (sh_type == SHT_REL && sh_entsize != sizeof (struct elf64_rel))) {
        
            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++relocation shdr.sh_entsize not yet supported");
            exit (EXIT_FAILURE);
        
        }
        
        sh_size = array_to_integer (shdr->sh_size, 8, endianess);
        
        pos = data + sh_offset;
        CHECK_READ (pos, (unsigned long) sh_size);
        
        part->reloc_cnt = sh_size / sh_entsize;
        part->reloc_arr = xmalloc (part->reloc_cnt * sizeof (*part->reloc_arr));
        
        if (sh_type == SHT_RELA) {
        
            for (j = 0; j < part->reloc_cnt; j++) {
            
                rela = (struct elf64_rela *) (pos + sh_entsize * j);
                translate_relocation64_addend (filename, part->reloc_arr + j, rela, part, endianess);
            
            }
        
        } else {
        
            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "+++ELF64 relocations without addend not yet supported");
            exit (EXIT_FAILURE);
        
        }
    
    }
    
    free (part_p_array);

}

#define     PAGE_SIZE                   0x1000

void elf_before_link (void) {

    struct section *section;
    
    for (section = all_sections; section; section = section->next) {
    
        if (section->section_alignment < PAGE_SIZE) {
            section->section_alignment = PAGE_SIZE;
        }
    
    }

}

uint64_t elf_get_first_section_rva (void) {

    uint64_t size_of_headers = 0;
    
    if (state->format == LD_FORMAT_AMD64_ELF) {
        size_of_headers = sizeof (struct elf64_exec);
    } else if (state->format == LD_FORMAT_I386_ELF) {
        size_of_headers = sizeof (struct elf32_exec);
    }
    
    if (all_sections) {
        return ALIGN (size_of_headers, all_sections->section_alignment);
    }
    
    return size_of_headers;

}

#define     PT_LOAD                     1
#define     EM_I386                     3
#define     EM_AMD64                    62

static uint32_t translate_section_flags_to_sh_flags (uint32_t flags) {

    uint32_t sh_flags = 0;
    
    if (!(flags & SECTION_FLAG_READONLY)) {
        sh_flags |= SHF_WRITE;
    }
    
    if (flags & SECTION_FLAG_CODE) {
        sh_flags |= SHF_ALLOC;
    }
    
    if (!(flags & SECTION_FLAG_NOREAD)) {
        sh_flags |= SHF_EXEC_INSTR;
    }
    
    return sh_flags;

}

#define     PF_X                        0x01
#define     PF_W                        0x02
#define     PF_R                        0x04

static uint32_t translate_section_flags_to_p_flags (uint32_t flags) {

    uint32_t p_flags = 0;
    
    if (!(flags & SECTION_FLAG_READONLY)) {
        p_flags |= PF_W;
    }
    
    if (flags & SECTION_FLAG_CODE) {
        p_flags |= PF_X;
    }
    
    if (!(flags & SECTION_FLAG_NOREAD)) {
        p_flags |= PF_R;
    }
    
    return p_flags;

}

static unsigned char *write_sections (unsigned char *data, struct elf32_exec *header, uint64_t shstrtab_i) {

    struct elf32_phdr phdr = { 0 };
    struct elf32_shdr shdr = { 0 };
    
    struct section *section;
    
    unsigned char *pos, *phdr_pos, *shdr_pos;
    uint32_t flags;
    
    phdr_pos = data + array_to_integer (header->e_phoff, 4, 0);
    pos = data + sizeof (header);
    
    /*if (generate_section_headers) */{
    
        shdr_pos = data + array_to_integer (header->e_shoff, 4, 0);
        
        integer_to_array (SHT_NULL, shdr.sh_type, 4, 0);
        integer_to_array (SHN_UNDEF, shdr.sh_link, 4, 0);
        
        memcpy (shdr_pos, &shdr, sizeof (shdr));
        shdr_pos += sizeof (shdr);
    
    }
    
    for (section = all_sections; section; section = section->next) {
    
        integer_to_array (PT_LOAD, phdr.p_type, 4, 0);
        
        integer_to_array (state->base_address + section->rva, phdr.p_paddr, 4, 0);
        integer_to_array (state->base_address + section->rva, phdr.p_vaddr, 4, 0);
        
        integer_to_array (section->total_size, phdr.p_memsz, 4, 0);
        
        if (!section->is_bss) {
        
            integer_to_array (section->total_size, phdr.p_filesz, 4, 0);
            
            pos = data + ALIGN (pos - data, section->section_alignment);
            integer_to_array (pos - data, phdr.p_offset, 4, 0);
            
            section_write (section, pos);
            pos += section->total_size;
        
        } else {
        
            integer_to_array (0, phdr.p_filesz, 4, 0);
            integer_to_array (0, phdr.p_offset, 4, 0);
        
        }
        
        flags = translate_section_flags_to_p_flags (section->flags);
        integer_to_array (flags, phdr.p_flags, 4, 0);
        
        integer_to_array (section->section_alignment, phdr.p_align, 4, 0);
        
        /*if (generate_section_headers) */{
        
            integer_to_array (section->is_bss ? SHT_NOBITS : SHT_PROGBITS, shdr.sh_type, 4, 0);
            
            flags = translate_section_flags_to_sh_flags (section->flags);
            integer_to_array (flags, shdr.sh_flags, 4, 0);
            
            integer_to_array (array_to_integer (phdr.p_vaddr, 4, 0), shdr.sh_addr, 4, 0);
            integer_to_array (array_to_integer (phdr.p_offset, 4, 0), shdr.sh_offset, 4, 0);
            integer_to_array (array_to_integer (phdr.p_memsz, 4, 0), shdr.sh_size, 4, 0);
            integer_to_array (array_to_integer (phdr.p_align, 4, 0), shdr.sh_addralign, 4, 0);
            
            integer_to_array (shstrtab_i, shdr.sh_name, 4, 0);
            shstrtab_i += strlen (section->name) + 1;
            
            memcpy (shdr_pos, &shdr, sizeof (shdr));
            shdr_pos += sizeof (shdr);
        
        }
        
        memcpy (phdr_pos, &phdr, sizeof (phdr));
        phdr_pos += sizeof (phdr);
    
    }
    
    return pos;

}

static unsigned char *write_sections64 (unsigned char *data, struct elf64_exec *header, uint64_t shstrtab_i) {

    struct elf64_phdr phdr = { 0 };
    struct elf64_shdr shdr = { 0 };
    
    struct section *section;
    
    unsigned char *pos, *phdr_pos, *shdr_pos;
    uint32_t flags;
    
    phdr_pos = data + array_to_integer (header->e_phoff, 8, 0);
    pos = data + sizeof (header);
    
    /*if (generate_section_headers) */{
    
        shdr_pos = data + array_to_integer (header->e_shoff, 8, 0);
        
        integer_to_array (SHT_NULL, shdr.sh_type, 4, 0);
        integer_to_array (SHN_UNDEF, shdr.sh_link, 4, 0);
        
        memcpy (shdr_pos, &shdr, sizeof (shdr));
        shdr_pos += sizeof (shdr);
    
    }
    
    for (section = all_sections; section; section = section->next) {
    
        integer_to_array (PT_LOAD, phdr.p_type, 4, 0);
        
        integer_to_array (state->base_address + section->rva, phdr.p_paddr, 8, 0);
        integer_to_array (state->base_address + section->rva, phdr.p_vaddr, 8, 0);
        
        integer_to_array (section->total_size, phdr.p_memsz, 8, 0);
        
        if (!section->is_bss) {
        
            integer_to_array (section->total_size, phdr.p_filesz, 8, 0);
            
            pos = data + ALIGN (pos - data, section->section_alignment);
            integer_to_array (pos - data, phdr.p_offset, 8, 0);
            
            section_write (section, pos);
            pos += section->total_size;
        
        } else {
        
            integer_to_array (0, phdr.p_filesz, 8, 0);
            integer_to_array (0, phdr.p_offset, 8, 0);
        
        }
        
        flags = translate_section_flags_to_p_flags (section->flags);
        integer_to_array (flags, phdr.p_flags, 4, 0);
        
        integer_to_array (section->section_alignment, phdr.p_align, 8, 0);
        
        /*if (generate_section_headers) */{
        
            integer_to_array (section->is_bss ? SHT_NOBITS : SHT_PROGBITS, shdr.sh_type, 4, 0);
            
            flags = translate_section_flags_to_sh_flags (section->flags);
            integer_to_array (flags, shdr.sh_flags, 8, 0);
            
            integer_to_array (array_to_integer (phdr.p_vaddr,  8, 0), shdr.sh_addr, 8, 0);
            integer_to_array (array_to_integer (phdr.p_offset, 8, 0), shdr.sh_offset, 8, 0);
            integer_to_array (array_to_integer (phdr.p_memsz,  8, 0), shdr.sh_size, 8, 0);
            integer_to_array (array_to_integer (phdr.p_align,  8, 0), shdr.sh_addralign, 8, 0);
            
            integer_to_array (shstrtab_i, shdr.sh_name, 4, 0);
            shstrtab_i += strlen (section->name) + 1;
            
            memcpy (shdr_pos, &shdr, sizeof (shdr));
            shdr_pos += sizeof (shdr);
        
        }
        
        memcpy (phdr_pos, &phdr, sizeof (phdr));
        phdr_pos += sizeof (phdr);
    
    }
    
    return pos;

}

void elf32_write (const char *filename) {

    struct elf32_exec header = { 0 };
    FILE *fp;
    
    unsigned long data_size = 0;
    unsigned char *data, *pos;
    
    struct section *section;
    uint16_t e_phnum = 0, e_shnum = 1;

    uint64_t shstrtab_size, shstrtab_start_i = 0;
    
    if (!(fp = fopen (filename, "wb"))) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to open '%s' for writing", filename);
        return;
    
    }
    
    header.e_ident[0] = 0x7F;
    header.e_ident[1] = 'E';
    header.e_ident[2] = 'L';
    header.e_ident[3] = 'F';
    
    header.e_ident[EI_CLASS] = ELF_CLASS32;
    header.e_ident[EI_DATA] = ELF_DATA2LSB;
    
    header.e_ident[EI_VERSION] = EV_CURRENT;
    
    integer_to_array (ET_EXEC, header.e_type, 2, 0);
    integer_to_array (EM_I386, header.e_machine, 2, 0);
    integer_to_array (EV_CURRENT, header.e_version, 4, 0);
    
    integer_to_array (state->entry_point + state->base_address, header.e_entry, 4, 0);
    integer_to_array (sizeof (header), header.e_ehsize, 2, 0);
    
    data_size += sizeof (header);
    
    for (section = all_sections; section; section = section->next) {
    
        if (!section->is_bss) {
        
            data_size = ALIGN (data_size, section->section_alignment);
            data_size += section->total_size;
        
        }
        
        e_phnum++;
    
    }
    
    /*if (generate_section_headers) */{
    
        shstrtab_start_i = shstrtab_size = 1 + sizeof (".shstrtab");
        
        for (section = all_sections; section; section = section->next) {
            shstrtab_size += strlen (section->name) + 1;
        }
        
        data_size += shstrtab_size;
    
    }
    
    data_size = ALIGN (data_size, 4);
    
    integer_to_array (data_size, header.e_phoff, 4, 0);
    integer_to_array (sizeof (struct elf32_phdr), header.e_phentsize, 2, 0);
    integer_to_array (e_phnum, header.e_phnum, 2, 0);
    
    data_size += e_phnum * sizeof (struct elf32_phdr);
    
    /*if (generate_section_headers) */{
    
        data_size = ALIGN (data_size, 4);
        
        integer_to_array (data_size, header.e_shoff, 4, 0);
        integer_to_array (sizeof (struct elf32_shdr), header.e_shentsize, 2, 0);
        
        for (section = all_sections; section; section = section->next) {
            section->target_index = e_shnum++;
        }
        
        integer_to_array (e_shnum++, header.e_shstrndx, 2, 0);
        integer_to_array (e_shnum, header.e_shnum, 2, 0);
        
        data_size += (e_shnum * sizeof (struct elf32_shdr));
    
    }
    
    data = xmalloc (data_size);
    memcpy (data, &header, sizeof (header));
    
    pos = write_sections (data, &header, shstrtab_start_i);
    
    /*if (generate_section_headers) */{
    
        struct elf32_shdr shstrshdr = { 0 };
        
        unsigned char *shdr_pos = data + array_to_integer (header.e_shoff, 4, 0) + array_to_integer (header.e_shstrndx, 2, 0) * sizeof (struct elf32_shdr);
        unsigned char *saved_pos = pos;
        
        integer_to_array (1, shstrshdr.sh_name, 4, 0);
        integer_to_array (SHT_STRTAB, shstrshdr.sh_type, 4, 0);
        integer_to_array (saved_pos - data, shstrshdr.sh_offset, 4, 0);
        integer_to_array (1, shstrshdr.sh_addralign, 4, 0);
        
        *pos++ = '\0';
        
        memcpy (pos, ".shstrtab", sizeof (".shstrtab"));
        pos += sizeof (".shstrtab");
        
        for (section = all_sections; section; section = section->next) {
        
            uint64_t name_len = strlen (section->name);
            
            memcpy (pos, section->name, name_len);
            pos[name_len] = '\0';
            
            pos += name_len + 1;
        
        }
        
        integer_to_array (pos - saved_pos, shstrshdr.sh_size, 4, 0);
        memcpy (shdr_pos, &shstrshdr, sizeof (shstrshdr));
    
    }
    
    if (fwrite (data, data_size, 1, fp) != 1) {
        report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", filename);
    }
    
    free (data);
    fclose (fp);

}

void elf64_write (const char *filename) {

    struct elf64_exec header = { 0 };
    FILE *fp;
    
    unsigned long data_size = 0;
    unsigned char *data, *pos;
    
    struct section *section;
    uint16_t e_phnum = 0, e_shnum = 1;
    
    uint64_t shstrtab_size, shstrtab_start_i = 0;
    
    if (!(fp = fopen (filename, "wb"))) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to open '%s' for writing", filename);
        return;
    
    }
    
    header.e_ident[0] = 0x7F;
    header.e_ident[1] = 'E';
    header.e_ident[2] = 'L';
    header.e_ident[3] = 'F';
    
    header.e_ident[EI_CLASS] = ELF_CLASS64;
    header.e_ident[EI_DATA] = ELF_DATA2LSB;
    
    header.e_ident[EI_VERSION] = EV_CURRENT;
    
    integer_to_array (ET_EXEC, header.e_type, 2, 0);
    integer_to_array (EM_AMD64, header.e_machine, 2, 0);
    integer_to_array (EV_CURRENT, header.e_version, 4, 0);
    
    integer_to_array (state->entry_point + state->base_address, header.e_entry, 8, 0);
    integer_to_array (sizeof (header), header.e_ehsize, 2, 0);
    
    data_size += sizeof (header);
    
    for (section = all_sections; section; section = section->next) {
    
        if (!section->is_bss) {
        
            data_size = ALIGN (data_size, section->section_alignment);
            data_size += section->total_size;
        
        }
        
        e_phnum++;
    
    }
    
    /*if (generate_section_headers) */{
    
        shstrtab_start_i = shstrtab_size = 1 + sizeof (".shstrtab");
        
        for (section = all_sections; section; section = section->next) {
            shstrtab_size += strlen (section->name) + 1;
        }
        
        data_size += shstrtab_size;
    
    }
    
    data_size = ALIGN (data_size, 8);
    
    integer_to_array (data_size, header.e_phoff, 8, 0);
    integer_to_array (sizeof (struct elf64_phdr), header.e_phentsize, 2, 0);
    integer_to_array (e_phnum, header.e_phnum, 2, 0);
    
    data_size += e_phnum * sizeof (struct elf64_phdr);
    
    /*if (generate_section_headers) */{
    
        data_size = ALIGN (data_size, 8);
        
        integer_to_array (data_size, header.e_shoff, 8, 0);
        integer_to_array (sizeof (struct elf64_shdr), header.e_shentsize, 2, 0);
        
        for (section = all_sections; section; section = section->next) {
            section->target_index = e_shnum++;
        }
        
        integer_to_array (e_shnum++, header.e_shstrndx, 2, 0);
        integer_to_array (e_shnum, header.e_shnum, 2, 0);
        
        data_size += (e_shnum * sizeof (struct elf64_shdr));
    
    }
    
    data = xmalloc (data_size);
    memcpy (data, &header, sizeof (header));
    
    pos = write_sections64 (data, &header, shstrtab_start_i);
    
    /*if (generate_section_headers) */{
    
        struct elf64_shdr shstrshdr = { 0 };
        
        unsigned char *shdr_pos = data + array_to_integer (header.e_shoff, 8, 0) + array_to_integer (header.e_shstrndx, 2, 0) * sizeof (struct elf64_shdr);
        unsigned char *saved_pos = pos;
        
        integer_to_array (1, shstrshdr.sh_name, 4, 0);
        integer_to_array (SHT_STRTAB, shstrshdr.sh_type, 4, 0);
        integer_to_array (saved_pos - data, shstrshdr.sh_offset, 8, 0);
        integer_to_array (1, shstrshdr.sh_addralign, 8, 0);
        
        *pos++ = '\0';
        
        memcpy (pos, ".shstrtab", sizeof (".shstrtab"));
        pos += sizeof (".shstrtab");
        
        for (section = all_sections; section; section = section->next) {
        
            uint64_t name_len = strlen (section->name);
            
            memcpy (pos, section->name, name_len);
            pos[name_len] = '\0';
            
            pos += name_len + 1;
        
        }
        
        integer_to_array (pos - saved_pos, shstrshdr.sh_size, 8, 0);
        memcpy (shdr_pos, &shstrshdr, sizeof (shstrshdr));
    
    }
    
    if (fwrite (data, data_size, 1, fp) != 1) {
        report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", filename);
    }
    
    free (data);
    fclose (fp);

}
