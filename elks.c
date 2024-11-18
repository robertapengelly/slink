/******************************************************************************
 * @file            elks.c
 *****************************************************************************/
#include    <limits.h>
#include    <stddef.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>
#include    <time.h>

#include    "aout.h"
#include    "elks.h"
#include    "ld.h"
#include    "lib.h"
#include    "pe.h"
#include    "report.h"
#include    "write7x.h"

typedef     signed char                 int8_t;
typedef     signed short                int16_t;

#if     INT_MAX == 32767
typedef     signed long                 int32_t;
#else
typedef     signed int                  int32_t;
#endif

static unsigned long header_size = 0, output_size = 0;
static void *data = 0, *output = 0, *text = 0;


struct gr {

    long relocations_count, relocations_max;
    struct elks_relocation_info *relocations;

};

static struct gr tgr = { 0, 64, NULL };
static struct gr dgr = { 0, 64, NULL };

static int get_symbol (struct elks_object **obj_out, long *index, const char *name, int quiet) {

    long object_i, symbol_i;
    
    for (object_i = 0; object_i < state->nb_elks_objs; ++object_i) {
    
        struct elks_object *obj = state->elks_objs[object_i];
        
        for (symbol_i = 0; symbol_i < obj->symtab_count; symbol_i++) {
        
            struct elks_nlist *sym = &obj->symtab[symbol_i];
            char *symname = obj->strtab + GET_INT32 (sym->n_strx);
            
            if ((sym->n_type & N_EXT) == 0) {
                continue;
            }
            
            if ((sym->n_type & N_TYPE) != N_TEXT && (sym->n_type & N_TYPE) != N_DATA && (sym->n_type & N_TYPE) != N_BSS && (sym->n_type & N_TYPE) != N_ABS) {
                continue;
            }
            
            if (strcmp (symname, name) == 0) {
            
                if (obj_out) {
                    *obj_out = obj;
                }
                
                if (index) {
                    *index = symbol_i;
                }
                
                return 0;
            
            }
        
        }
    
    }
    
    if (!quiet) {
        report_at (program_name, 0, REPORT_ERROR, "undefined symbol '%s'", name);
    }
    
    return 1;

}

static unsigned long get_entry (void) {

    struct elks_object *symobj;
    long symidx;
    
    if (get_symbol (&symobj, &symidx, state->entry, 1)) {
    
        report_at (program_name, 0, REPORT_WARNING, "cannot find entry symbol %s; defaulting to 00000000", state->entry);
        return 0;
    
    }
    
    return GET_UINT32 (symobj->symtab[symidx].n_value);

}

static void number_to_chars (unsigned char *p, unsigned long number, unsigned long size) {
    
    unsigned long i;
    
    for (i = 0; i < size; i++) {
        p[i] = (number >> (8 * i)) & 0xff;
    }

}

static long objtextsize = 0, objdatasize = 0, objbsssize = 0;
static unsigned long text_ptr = 0, data_ptr = 0, bss_ptr = 0;

static void apply_slides (struct elks_object *object) {

    long i;
    
    for (i = 0; i < object->symtab_count; i++) {
    
        struct elks_nlist *symbol = &object->symtab[i];
        unsigned long final_slide = 0, n_value = GET_UINT32 (symbol->n_value);
        
        if ((symbol->n_type & N_TYPE) != N_TEXT && (symbol->n_type & N_TYPE) != N_DATA && (symbol->n_type & N_TYPE) != N_BSS) {
            continue;
        }
        
        switch (symbol->n_type & N_TYPE) {
        
            case N_BSS:
            
                final_slide += state->text_size;
                final_slide += state->data_size;
                final_slide += object->bss_slide;
                
                break;
            
            case N_DATA:
            
                final_slide += state->text_size;
                final_slide += object->data_slide;
                
                break;
            
            case N_TEXT:
            
                final_slide += object->text_slide;
                break;
        
        }
        
        n_value += final_slide;
        
        switch (symbol->n_type & N_TYPE) {
        
            case N_BSS:
            
                n_value -= GET_UINT32 (object->header->a_data);
                /* fall through */
            
            case N_DATA:
            
                n_value -= GET_UINT32 (object->header->a_text);
                break;
        
        }
        
        write741_to_byte_array (symbol->n_value, n_value);
    
    }
    
    for (i = 0; i < object->trelocs_count; i++) {
    
        struct elks_relocation_info *rel = &object->trelocs[i];
        
        long r_address = GET_INT32 (rel->r_address);
        r_address += object->text_slide;
        
        write741_to_byte_array ((unsigned char *) rel->r_address, r_address);
    
    }
    
    for (i = 0; i < object->drelocs_count; i++) {
    
        struct elks_relocation_info *rel = &object->drelocs[i];
        
        long r_address = GET_INT32 (rel->r_address);
        r_address += state->text_size + object->data_slide;
        
        write741_to_byte_array ((unsigned char *) rel->r_address, r_address);
    
    }

}

static void paste (struct elks_object *object) {

    struct elks_exec *header = object->header;
    
    char *obj_text, *obj_data;
    unsigned long obj_text_size, obj_data_size, obj_bss_size;
    
    object->text_slide = text_ptr;
    obj_text = (char *) object->raw + sizeof (*header);
    
    if (state->impure) {
        obj_text_size = GET_UINT32 (header->a_text);
    } else {
        obj_text_size = ALIGN_UP (GET_UINT32 (header->a_text), SECTION_ALIGNMENT);
    }
    
    memcpy ((char *) text + text_ptr, obj_text, GET_UINT32 (header->a_text));
    text_ptr += obj_text_size;
    
    object->data_slide = data_ptr;
    obj_data = (char *) object->raw + sizeof (*header) + GET_UINT32 (header->a_text);
    
    if (state->impure) {
        obj_data_size = GET_UINT32 (header->a_data);
    } else {
        obj_data_size = ALIGN_UP (GET_UINT32 (header->a_data), SECTION_ALIGNMENT);
    }
    
    memcpy ((char *) data + data_ptr, obj_data, GET_UINT32 (header->a_data));
    data_ptr += obj_data_size;
    
    object->bss_slide = bss_ptr;
    
    if (state->impure) {
        obj_bss_size = GET_UINT32 (header->a_bss);
    } else {
        obj_bss_size = ALIGN_UP (GET_UINT32 (header->a_bss), SECTION_ALIGNMENT);
    }
    
    bss_ptr += obj_bss_size;

}

static void undef_collect (struct elks_object *object) {

    long i, val;
    
    for (i = 0; i < object->symtab_count; i++) {
    
        struct elks_nlist *sym = &object->symtab[i];
        char *symname = object->strtab + GET_INT32 (sym->n_strx);
        
        if ((sym->n_type & N_TYPE) != N_UNDF || GET_UINT32 (sym->n_value) == 0) {
            continue;
        }
        
        if (get_symbol (NULL, NULL, symname, 1)) {
            continue;
        }
        
        sym->n_type = N_BSS | N_EXT;
        val = GET_UINT32 (sym->n_value);
        
        write741_to_byte_array (sym->n_value, state->text_size + state->data_size + state->bss_size);
        state->bss_size += val;
    
    }

}

static int add_relocation (struct gr *gr, struct elks_relocation_info *r) {

    if (gr->relocations == NULL) {
    
        if ((gr->relocations = malloc (gr->relocations_max * sizeof (*r))) == NULL) {
            return 1;
        }
    
    }
    
    if (gr->relocations_count >= gr->relocations_max) {
    
        void *tmp;
        
        gr->relocations_max *= 2;
        
        if ((tmp = realloc (gr->relocations, gr->relocations_max * sizeof (*r))) == NULL) {
            return 1;
        }
        
        gr->relocations = tmp;
    
    }
    
    gr->relocations[gr->relocations_count] = *r;
    gr->relocations_count++;
    
    return 0;

}

static int relocate (struct elks_object *object, struct elks_relocation_info *r, int is_data) {

    struct elks_nlist *symbol;
    unsigned char *p;
    
    unsigned long r_symbolnum = GET_UINT32 (r->r_symbolnum);
    long result = 0, symbolnum = 0;
    
    int far_call = 0, pcrel = 0, ext = 0, length = 0;
    /*int need_relocate = 1;*/
    
    symbolnum = r_symbolnum & 0x7ffffff;
    length    = (r_symbolnum & (3LU << 29)) >> 29;
    
    pcrel     = (r_symbolnum & (1LU << 28)) >> 28;
    ext       = (r_symbolnum & (1LU << 31)) >> 31;
    
    far_call  = (r_symbolnum & (1LU << 27)) >> 27;
    
    if ((is_data && pcrel) || far_call) {
    
        report_at (program_name, 0, REPORT_ERROR, "unsupported relocation type");
        return 1;
    
    }
    
    switch (length) {
    
        case 0:
        
            length = 1;
            break;
        
        case 1:
        
            length = 2;
            break;
        
        case 2:
        
            length = 4;
            break;
    
    }
    
    symbol = &object->symtab[symbolnum];
    p = (unsigned char *) output + header_size + GET_INT32 (r->r_address);
    
    if (ext) {
    
        char *symname = object->strtab + GET_INT32 (symbol->n_strx);
        
        struct elks_object *symobj;
        long symidx;
        
        if (strcmp (symname, "__edata") == 0) {
        
            int32_t data_addr = ((char *) text - (char *) output) - header_size;
            data_addr += state->text_size;
            
            write741_to_byte_array (symbol->n_value, data_addr / 16);
            /*need_relocate = 0;*/
        
        } else if (strcmp (symname, "__end") == 0) {
        
            int32_t data_addr = ((char *) data - (char *) output) - header_size;
            
            data_addr += state->data_size;
            data_addr += state->bss_size;
            
            write741_to_byte_array (symbol->n_value, data_addr % 16);
            /*need_relocate = 0;*/
        
        } else if (!get_symbol (&symobj, &symidx, symname, 0)) {
            symbol = &symobj->symtab[symidx];
        } else {
            return 1;
        }
    
    }
    
    if (pcrel) {
    
        if (result == 0) {
            result = (long) GET_UINT32 (symbol->n_value) - (GET_INT32 (r->r_address) + length);
        }
    
    } else {
    
        if (!ext || (symbol->n_type & N_TYPE) == N_BSS || (symbol->n_type & N_TYPE) == N_DATA || (symbol->n_type & N_TYPE) == N_TEXT) {
        
            struct elks_relocation_info new_relocation;
            
            unsigned long r_symbolnum;
            long r_address;
            
            r_symbolnum = GET_UINT32 (r->r_symbolnum) & (3L << 29);
            r_address = GET_INT32 (r->r_address);
            
            if (state->format == LD_FORMAT_IA16_ELKS || state->format == LD_FORMAT_I386_ELKS || state->format == LD_FORMAT_I386_AOUT || ((r_symbolnum >> 28) & 0xff) != N_ABS) {
            
                if (state->format == LD_FORMAT_BIN || state->format == LD_FORMAT_COM) {
                
                    report_at (object->filename, 0, REPORT_ERROR, "segment relocation at %04x:%04x", r_address / 0xffff, r_address % 0xffff);
                    return 1;
                
                }
                
                if (is_data) {
                    r_address -= state->text_size;
                }
                
                write741_to_byte_array ((unsigned char *) new_relocation.r_address, r_address);
                write741_to_byte_array (new_relocation.r_symbolnum, r_symbolnum);
                
                add_relocation (is_data ? &dgr : &tgr, &new_relocation);
            
            }
            
        }
        
        if (result == 0) {
        
            int32_t r_address = GET_INT32 (r->r_address);
            
            if (length == 4) {
                result = *(int32_t *) ((char *) output + header_size + r_address);
            } else if (length == 2) {
                result = *(int16_t *) ((char *) output + header_size + r_address);
            } else if (length == 1) {
                result = *(int8_t *) ((char *) output + header_size + r_address);
            }
        
        }
        
        if (ext) {
        
            symbolnum = (symbol->n_type & N_TYPE);
            
            result += GET_UINT32 (symbol->n_value);
            result += state->psp;
        
        } else {
        
            if ((symbolnum == 6) || (symbolnum == 8)) {
            
                result -= GET_UINT32 (object->header->a_text);
                result += state->text_size;
            
            }
            
            if (symbolnum == 4) {
                result += objtextsize;
            }
            
            if (symbolnum == 6) {
                result += objdatasize;
            }
            
            if (symbolnum == 8) {
            
                result -= GET_UINT32 (object->header->a_data);
                result += state->data_size;
                result += objbsssize;
            
            }
            
            result += state->psp;
        
        }
    
    }
    
    number_to_chars (p, result, length);
    return 0;

}

static int glue (struct elks_object *object) {

    long i, err = 0;
    
    for (i = 0; i < object->trelocs_count; i++) {
    
        if (relocate (object, &object->trelocs[i], 0)) {
            err = 1;
        }
    
    }
    
    for (i = 0; i < object->drelocs_count; i++) {
    
        if (relocate (object, &object->drelocs[i], 1)) {
            err = 1;
        }
    
    }
    
    objtextsize += GET_UINT32 (object->header->a_text);
    objdatasize += GET_UINT32 (object->header->a_data);
    objbsssize  += GET_UINT32 (object->header->a_bss);
    
    return err;

}


static int init_elks_object (void) {

    if (state->format == LD_FORMAT_I386_AOUT) {
        header_size = sizeof (struct aout_exec);
    } else if (state->format == LD_FORMAT_IA16_ELKS || state->format == LD_FORMAT_I386_ELKS) {
        header_size = sizeof (struct elks_exec);
    }
    
    if (!state->impure) {
        header_size = ALIGN_UP (header_size, SECTION_ALIGNMENT);
    }
    
    output_size = header_size + state->text_size + state->data_size;
    
    if ((output = malloc (output_size)) == NULL) {
        return 1;
    }
    
    memset (output, 0, output_size);
    
    text = (void *) ((char *) output + header_size);
    data = (void *) ((char *) text + state->text_size);
    
    return 0;

}

static int write_elks_object (unsigned long a_entry) {

    if (state->format == LD_FORMAT_I386_AOUT) {
    
        struct aout_exec *header = output;
        
        write741_to_byte_array (header->a_info, state->impure ? OMAGIC : ZMAGIC);
        write741_to_byte_array (header->a_text, state->text_size);
        write741_to_byte_array (header->a_data, state->data_size);
        write741_to_byte_array (header->a_bss, state->bss_size);
        write741_to_byte_array (header->a_entry, a_entry);
        write741_to_byte_array (header->a_trsize, tgr.relocations_count * sizeof (struct relocation_info));
        write741_to_byte_array (header->a_drsize, dgr.relocations_count * sizeof (struct relocation_info));
    
    } else if (state->format == LD_FORMAT_IA16_ELKS || state->format == LD_FORMAT_I386_ELKS) {
    
        struct elks_exec *header = output;
        
        header->a_magic[0] = (ELKS_MAGIC >> 8) & 0xff;
        header->a_magic[1] = ELKS_MAGIC & 0xff;
        
        header->a_flags = 0x10;
        header->a_cpu = (state->format == LD_FORMAT_I386_ELKS) ? 0x10 : 0x04;
        header->a_hdrlen = sizeof (*header);
        
        write741_to_byte_array (header->a_text, state->text_size);
        write741_to_byte_array (header->a_data, state->data_size);
        write741_to_byte_array (header->a_bss, state->bss_size);
        write741_to_byte_array (header->a_entry, a_entry);
        write721_to_byte_array (header->a_total, (state->text_size + state->data_size) + 0x8000);
        
        write741_to_byte_array (header->a_trsize, tgr.relocations_count * sizeof (struct elks_relocation_info));
        write741_to_byte_array (header->a_drsize, dgr.relocations_count * sizeof (struct elks_relocation_info)); 
    
    }
    
    if (fwrite ((char *) output, output_size, 1, state->ofp) != 1) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", state->ofile);
        return 1;
    
    }
    
    if (state->format == LD_FORMAT_I386_AOUT) {
    
        if (tgr.relocations_count > 0) {
        
            if (fwrite (tgr.relocations, tgr.relocations_count * sizeof (struct relocation_info), 1, state->ofp) != 1) {
            
                report_at (program_name, 0, REPORT_ERROR, "failed to write text relocations to '%s'", state->ofile);
                return 1;
            
            }
        
        }
        
        if (dgr.relocations_count > 0) {
        
            if (fwrite (dgr.relocations, dgr.relocations_count * sizeof (struct relocation_info), 1, state->ofp) != 1) {
            
                report_at (program_name, 0, REPORT_ERROR, "failed to write data relocations to '%s'", state->ofile);
                return 1;
            
            }
        
        }
    
    } else if (state->format == LD_FORMAT_IA16_ELKS || state->format == LD_FORMAT_I386_ELKS) {
    
        if (tgr.relocations_count > 0) {
        
            if (fwrite (tgr.relocations, tgr.relocations_count * sizeof (struct elks_relocation_info), 1, state->ofp) != 1) {
            
                report_at (program_name, 0, REPORT_ERROR, "failed to write text relocations to '%s'", state->ofile);
                return 1;
            
            }
        
        }
        
        if (dgr.relocations_count > 0) {
        
            if (fwrite (dgr.relocations, dgr.relocations_count * sizeof (struct elks_relocation_info), 1, state->ofp) != 1) {
            
                report_at (program_name, 0, REPORT_ERROR, "failed to write data relocations to '%s'", state->ofile);
                return 1;
            
            }
        
        }
    
    }
    
    return 0;

}


static struct msdos_header *doshdr;
static struct pe_header *pehdr;
static struct pe_optional_header *opthdr;

static struct section_table_entry *section_text;
static struct section_table_entry *section_data;

unsigned char dos_stub[] = {

    0x0E,   0x1F,   0xBA,   0x0E,   0x00,   0xB4,   0x09,   0xCD,
    0x21,   0xB8,   0x01,   0x4C,   0xCD,   0x21,   0x54,   0x68,
    
    0x69,   0x73,   0x20,   0x70,   0x72,   0x6F,   0x67,   0x72,
    0x61,   0x6D,   0x20,   0x63,   0x61,   0x6E,   0x6E,   0x6F,
    
    0x74,   0x20,   0x62,   0x65,   0x20,   0x72,   0x75,   0x6E,
    0x20,   0x69,   0x6E,   0x20,   0x44,   0x4F,   0x53,   0x20,
    
    0x6D,   0x6F,   0x64,   0x65,   0x2E,   0x0D,   0x0D,   0x0A,
    0x24,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00

};

static int no_sections = 0;

static unsigned short chksum (unsigned int checksum, void *base, int count) {

    register int sum = 0;
    int *data;
    
    if (count && base != NULL) {
    
        data = (int *) base;
        
        do {
        
            sum = *(unsigned short *) data + checksum;
            data = (int *) ((char *) data + 2);
            
            checksum = (unsigned short) sum + (sum >> 16);
        
        } while (--count);
    
    }
    
    return checksum + (checksum >> 16);

}

static int pe_chksum (void *base, unsigned int size) {

    void *remaining_data;
    int remaining_data_size;
    
    unsigned int pe_header_chksum, file_chksum;
    unsigned int pe_header_size;
    
    pe_header_size = (unsigned long) pehdr - (unsigned long) base + \
        ((unsigned long) &opthdr->Checksum - (unsigned long) pehdr);
    
    remaining_data_size = (size - pe_header_size - 4) >> 1;
    remaining_data = &opthdr->Subsystem;
    
    pe_header_chksum = chksum (0, base, pe_header_size >> 1);
    file_chksum = chksum (pe_header_chksum, remaining_data, remaining_data_size);
    
    if (size & 1) {
        file_chksum += (unsigned short) *((char *) base + size - 1);
    }
    
    return size + file_chksum;

}

static int init_pe_object (void) {

    header_size = sizeof (*doshdr) + sizeof (dos_stub) + sizeof (*pehdr) + sizeof (*opthdr);
    no_sections = 0;
    
    if (state->raw_text_size > 0) {
    
        header_size += sizeof (*section_text);
        no_sections++;
    
    }
    
    if (state->raw_data_size > 0) {
    
        header_size += sizeof (*section_data);
        no_sections++;
    
    }
    
    header_size = ALIGN_UP (header_size, SECTION_ALIGNMENT);
    output_size = header_size + ALIGN_UP (state->text_size, SECTION_ALIGNMENT) + ALIGN_UP (state->data_size, SECTION_ALIGNMENT);
    
    if ((output = malloc (output_size)) == NULL) {
        return 2;
    }
    
    memset (output, 0, output_size);
    
    doshdr = (struct msdos_header *) output;
    pehdr  = (struct pe_header *) ((char *) doshdr + sizeof (*doshdr) + sizeof (dos_stub));
    opthdr = (struct pe_optional_header *) ((char *) pehdr + sizeof (*pehdr));
    
    section_text = (struct section_table_entry *) ((char *) opthdr + sizeof (*opthdr));
    section_data = (struct section_table_entry *) ((char *) section_text + sizeof (*section_text));
    
    text = (void *) ((char *) output + header_size);
    data = (void *) ((char *) text + ALIGN_UP (state->text_size, SECTION_ALIGNMENT));
    
    return 0;

}

static int write_pe_object (unsigned long entry) {

    doshdr->e_magic[0] = 'M';
    doshdr->e_magic[1] = 'Z';
    
    write721_to_byte_array (doshdr->e_cblp, 0x0090);
    write721_to_byte_array (doshdr->e_cp, 0x0003);
    
    write721_to_byte_array (doshdr->e_cparhdr, ALIGN_UP (sizeof (*doshdr), 16) / 16);
    
    write721_to_byte_array (doshdr->e_maxalloc, 0xFFFF);
    write721_to_byte_array (doshdr->e_sp, 0x00B8);
    
    write721_to_byte_array (doshdr->e_lfarlc, sizeof (*doshdr));
    write741_to_byte_array (doshdr->e_lfanew, sizeof (*doshdr) + sizeof (dos_stub));
    
    memcpy ((char *)  output + GET_UINT16 (doshdr->e_lfarlc), dos_stub, sizeof (dos_stub));
    
    
    pehdr->Signature[0] = 'P';
    pehdr->Signature[1] = 'E';
    
    write721_to_byte_array (pehdr->Machine, IMAGE_FILE_MACHINE_I386);
    write721_to_byte_array (pehdr->NumberOfSections, no_sections);
    write741_to_byte_array (pehdr->TimeDateStamp, time (0));
    write721_to_byte_array (pehdr->SizeOfOptionalHeader, sizeof (*opthdr));
    
    {
    
        unsigned short characteristics = 0;
        
        characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
        characteristics |= IMAGE_FILE_EXECUTABLE_IMAGE;
        characteristics |= IMAGE_FILE_LINE_NUMS_STRIPPED;
        characteristics |= IMAGE_FILE_LOCAL_SYMS_STRIPPED;
        characteristics |= IMAGE_FILE_32BIT_MACHINE;
        characteristics |= IMAGE_FILE_DEBUG_STRIPPED;
        
        write721_to_byte_array (pehdr->Characteristics, characteristics);
    
    }
    
    
    write721_to_byte_array (opthdr->Magic, IMAGE_FILE_MAGIC_I386);
    
    opthdr->MajorLinkerVersion = 2;
    opthdr->MinorLinkerVersion = 1;
    
    write741_to_byte_array (opthdr->SizeOfCode, ALIGN_UP (state->text_size, SECTION_ALIGNMENT));
    write741_to_byte_array (opthdr->SizeOfInitializedData, ALIGN_UP (state->data_size, SECTION_ALIGNMENT));
    write741_to_byte_array (opthdr->SizeOfUninitializedData,  ALIGN_UP (state->bss_size, SECTION_ALIGNMENT));
    write741_to_byte_array (opthdr->AddressOfEntryPoint, ALIGN_UP ((char *) text - (char *) output, SECTION_ALIGNMENT) + entry);
    write741_to_byte_array (opthdr->BaseOfCode, ALIGN_UP ((char *) text - (char *) output, SECTION_ALIGNMENT));
    write741_to_byte_array (opthdr->BaseOfData, ALIGN_UP ((char *) data - (char *) output, SECTION_ALIGNMENT));
    
    write741_to_byte_array (opthdr->ImageBase, state->psp);
    write741_to_byte_array (opthdr->SectionAlignment, SECTION_ALIGNMENT);
    write741_to_byte_array (opthdr->FileAlignment, SECTION_ALIGNMENT);
    
    write721_to_byte_array (opthdr->MajorOperatingSystemVersion, 4);
    write721_to_byte_array (opthdr->MajorImageVersion, 1);
    write721_to_byte_array (opthdr->MajorSubsystemVersion, 4);
    
    write741_to_byte_array (opthdr->SizeOfImage, GET_UINT32 (opthdr->BaseOfData) + ALIGN_UP (GET_UINT32 (opthdr->SizeOfInitializedData), SECTION_ALIGNMENT));
    write741_to_byte_array (opthdr->SizeOfHeaders, ALIGN_UP (header_size, SECTION_ALIGNMENT));
    write741_to_byte_array (opthdr->Checksum, pe_chksum (output, output_size));
    
    write721_to_byte_array (opthdr->Subsystem, state->subsystem);
    
    {
    
        unsigned long ibss_addr = ((char *) data - (char *) output) + state->data_size;
        unsigned long ibss_size = state->bss_size;
        
        unsigned long stack_addr = ibss_addr + ibss_size;
        unsigned long stack_size = ALIGN_UP (stack_addr, SECTION_ALIGNMENT);
        
        write741_to_byte_array (opthdr->SizeOfStackReserved, SECTION_ALIGNMENT << 9);
        write741_to_byte_array (opthdr->SizeOfStackCommit, ALIGN_UP (stack_addr % 16 + stack_size, SECTION_ALIGNMENT));
        write741_to_byte_array (opthdr->SizeOfHeapReserved, SECTION_ALIGNMENT << 8);
        write741_to_byte_array (opthdr->SizeOfHeapCommit, ALIGN_UP (stack_addr % 16 + stack_size, SECTION_ALIGNMENT));
    
    }
    
    write741_to_byte_array (opthdr->NumberOfRvaAndSizes, 16);
    
    
    if (state->raw_text_size > 0) {
    
        unsigned long characteristics = 0;
        memcpy (section_text->Name, ".text", 5);
        
        write741_to_byte_array (section_text->VirtualSize, state->text_size);
        write741_to_byte_array (section_text->VirtualAddress, GET_UINT32 (opthdr->BaseOfCode));
        write741_to_byte_array (section_text->SizeOfRawData, state->raw_text_size);
        write741_to_byte_array (section_text->PointerToRawData, ((char *) text - (char *) output));
        
        characteristics |= IMAGE_SCN_CNT_CODE;
        characteristics |= IMAGE_SCN_ALIGN_4BYTES;
        characteristics |= IMAGE_SCN_MEM_EXECUTE;
        characteristics |= IMAGE_SCN_MEM_READ;
        
        write741_to_byte_array (section_text->Characteristics, characteristics);
    
    }
    
    if (state->raw_data_size > 0) {
    
        unsigned long characteristics = 0;
        memcpy (section_text->Name, ".data", 5);
        
        write741_to_byte_array (section_data->VirtualSize, state->data_size);
        write741_to_byte_array (section_data->VirtualAddress, GET_UINT32 (opthdr->BaseOfData));
        write741_to_byte_array (section_data->SizeOfRawData, state->raw_data_size);
        write741_to_byte_array (section_data->PointerToRawData, ((char *) data - (char *) output));
        
        characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
        characteristics |= IMAGE_SCN_ALIGN_4BYTES;
        characteristics |= IMAGE_SCN_MEM_READ;
        characteristics |= IMAGE_SCN_MEM_WRITE;
        
        write741_to_byte_array (section_data->Characteristics, characteristics);
    
    }
    
    
    /* write the file */
    if (fwrite ((char *) output, output_size, 1, state->ofp) != 1) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", state->ofile);
        return 1;
    
    }
    
    return 0;

}


int create_executable_from_elks_objects (void) {

    struct elks_object *object;
    long i;
    
    unsigned long entry = 0;
    int err = 0;
    
    if (state->format == LD_FORMAT_BIN || state->format == LD_FORMAT_COM) {
    
        output_size = state->text_size + state->data_size;
        
        if ((output = malloc (output_size)) == NULL) {
            return EXIT_FAILURE;
        }
        
        memset (output, 0, output_size);
        
        text = (void *) (char *) output;
        data = (void *) ((char *) text + state->text_size);
    
    } else if (state->format == LD_FORMAT_IA16_ELKS || state->format == LD_FORMAT_I386_ELKS || state->format == LD_FORMAT_I386_AOUT) {
    
        if (init_elks_object ()) {
        
            report_at (program_name, 0, REPORT_ERROR, "failed to initialize a.out object");
            return EXIT_FAILURE;
        
        }
    
    } else if (state->format == LD_FORMAT_I386_PE) {
    
        if (init_pe_object ()) {
        
            report_at (program_name, 0, REPORT_ERROR, "failed to initialize pe object");
            return EXIT_FAILURE;
        
        }
    
    }
    
    for (i = 0; i < state->nb_elks_objs; ++i) {
        paste (state->elks_objs[i]);
    }
    
    for (i = 0; i < state->nb_elks_objs; ++i) {
        apply_slides (state->elks_objs[i]);
    }
    
    for (i = 0; i < state->nb_elks_objs; ++i) {
        undef_collect (state->elks_objs[i]);
    }
    
    if (!state->impure) {
        state->bss_size = ALIGN_UP (state->bss_size, SECTION_ALIGNMENT);
    }
    
    for (i = 0; i < state->nb_elks_objs; ++i) {
    
        if (glue (state->elks_objs[i])) {
            err = 1;
        }
    
    }
    
    if (err) {
        return EXIT_FAILURE;
    }
    
    if (state->format == LD_FORMAT_IA16_ELKS || state->format == LD_FORMAT_I386_ELKS || state->format == LD_FORMAT_I386_AOUT || state->format == LD_FORMAT_I386_PE) {
        entry = get_entry ();
    }
    
    for (i = 0; i < state->nb_elks_objs; i++) {
    
        if ((object = state->elks_objs[i]) == NULL) {
            return EXIT_FAILURE;
        }
        
        /*if (state->mapfile) {
            init_map (object);
        }*/
        
        free (object->raw);
        free (object);
    
    }
    
    state->nb_elks_objs = 0;
    
    /*if (state->mapfile) {
    
        set_map_sections_size (state->text_size, state->data_size, state->bss_size);
        set_map_sections_start (0, state->text_size, state->text_size + state->data_size);
        
        generate_map ();
    
    }*/
    
    if ((state->ofp = fopen (state->ofile, "wb")) == NULL) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to open '%s' for writing", state->ofile);
        return EXIT_FAILURE;
    
    }
    
    if (state->format == LD_FORMAT_BIN || state->format == LD_FORMAT_COM) {
    
        if (fwrite ((char *) output, output_size, 1, state->ofp) != 1) {
        
            report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", state->ofile);
            return EXIT_FAILURE;
        
        }
    
    } else if (state->format == LD_FORMAT_IA16_ELKS || state->format == LD_FORMAT_I386_ELKS || state->format == LD_FORMAT_I386_AOUT) {
    
        if (write_elks_object (entry)) {
        
            report_at (program_name, 0, REPORT_ERROR, "failed to write a.out object");
            return EXIT_FAILURE;
        
        }
    
    } else if (state->format == LD_FORMAT_I386_PE) {
    
        if (write_pe_object (entry)) {
        
            report_at (program_name, 0, REPORT_ERROR, "failed to write pe object");
            return EXIT_FAILURE;
        
        }
    }
    
    return EXIT_SUCCESS;

}
