/******************************************************************************
 * @file            aout.c
 *****************************************************************************/
#include    <limits.h>
#include    <stddef.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "aout.h"
#include    "ld.h"
#include    "lib.h"
#include    "report.h"
#include    "write7x.h"

#include    <limits.h>

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
    struct relocation_info *relocations;

};

static struct gr tgr = { 0, 64, NULL };
static struct gr dgr = { 0, 64, NULL };

static int get_symbol (struct aout_object **obj_out, long *index, const char *name, int quiet) {

    long object_i, symbol_i;
    
    for (object_i = 0; object_i < state->nb_aout_objs; ++object_i) {
    
        struct aout_object *obj = state->aout_objs[object_i];
        
        for (symbol_i = 0; symbol_i < obj->symtab_count; symbol_i++) {
        
            struct nlist *sym = &obj->symtab[symbol_i];
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

    struct aout_object *symobj;
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

static void apply_slides (struct aout_object *object) {

    long i;
    
    for (i = 0; i < object->symtab_count; i++) {
    
        struct nlist *symbol = &object->symtab[i];
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
    
        struct relocation_info *rel = &object->trelocs[i];
        
        long r_address = GET_INT32 (rel->r_address);
        r_address += object->text_slide;
        
        write741_to_byte_array ((unsigned char *) rel->r_address, r_address);
    
    }
    
    for (i = 0; i < object->drelocs_count; i++) {
    
        struct relocation_info *rel = &object->drelocs[i];
        
        long r_address = GET_INT32 (rel->r_address);
        r_address += state->text_size + object->data_slide;
        
        write741_to_byte_array ((unsigned char *) rel->r_address, r_address);
    
    }

}

static void paste (struct aout_object *object) {

    struct i386_aout_exec *header = object->header;
    
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

static void undef_collect (struct aout_object *object) {

    long i, val;
    
    for (i = 0; i < object->symtab_count; i++) {
    
        struct nlist *sym = &object->symtab[i];
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

static int add_relocation (struct gr *gr, struct relocation_info *r) {

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

static int relocate (struct aout_object *object, struct relocation_info *r, int is_data) {

    struct nlist *symbol;
    unsigned char *p;
    
    unsigned long r_symbolnum = GET_UINT32 (r->r_symbolnum);
    long result = 0, symbolnum = 0;
    
    int far_call = 0, pcrel = 0, ext = 0, length = 0;
    
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
        
        struct aout_object *symobj;
        long symidx;
        
        if (!get_symbol (&symobj, &symidx, symname, 0)) {
            symbol = &symobj->symtab[symidx];
        } else {
            return 1;
        }
    
    }
    
    if (pcrel) {
        result = (long) GET_UINT32 (symbol->n_value) - (GET_INT32 (r->r_address) + length);
    } else {
    
        long r_address;
        
        if (!ext || (symbol->n_type & N_TYPE) == N_BSS || (symbol->n_type & N_TYPE) == N_DATA || (symbol->n_type & N_TYPE) == N_TEXT) {
        
            struct relocation_info new_relocation;
            
            unsigned long r_symbolnum;
            long r_address;
            
            r_symbolnum = GET_UINT32 (r->r_symbolnum) & (3L << 29);
            r_address = GET_INT32 (r->r_address);
            
            if (state->format == LD_FORMAT_IA16_AOUT || state->format == LD_FORMAT_I386_AOUT || ((r_symbolnum >> 28) & 0xff) != N_ABS) {
            
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
        
        r_address = GET_INT32 (r->r_address);
        
        if (length == 4) {
            result = *(int32_t *) ((char *) output + header_size + r_address);
        } else if (length == 2) {
            result = *(int16_t *) ((char *) output + header_size + r_address);
        } else if (length == 1) {
            result = *(int8_t *) ((char *) output + header_size + r_address);
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

static int glue (struct aout_object *object) {

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


static int init_aout_object (void) {

    if (state->format == LD_FORMAT_I386_AOUT) {
        header_size = sizeof (struct i386_aout_exec);
    } else if (state->format == LD_FORMAT_IA16_AOUT) {
        header_size = sizeof (struct ia16_aout_exec);
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

static int write_aout_object (unsigned long a_entry) {

    if (state->format == LD_FORMAT_I386_AOUT) {
    
        struct i386_aout_exec *aout_hdr = output;
        
        write741_to_byte_array (aout_hdr->a_info, state->impure ? OMAGIC : ZMAGIC);
        write741_to_byte_array (aout_hdr->a_text, state->text_size);
        write741_to_byte_array (aout_hdr->a_data, state->data_size);
        write741_to_byte_array (aout_hdr->a_bss, state->bss_size);
        write741_to_byte_array (aout_hdr->a_entry, a_entry);
        write741_to_byte_array (aout_hdr->a_trsize, tgr.relocations_count * sizeof (struct relocation_info));
        write741_to_byte_array (aout_hdr->a_drsize, dgr.relocations_count * sizeof (struct relocation_info));
    
    } else if (state->format == LD_FORMAT_IA16_AOUT) {
    
        struct ia16_aout_exec *aout_hdr = output;
        
        aout_hdr->a_magic[0] = 0x01;
        aout_hdr->a_magic[1] = 0x03;
        
        aout_hdr->a_flags = 0x10;
        aout_hdr->a_cpu = 0x04;
        aout_hdr->a_hdrlen = sizeof (*aout_hdr);
        
        write741_to_byte_array (aout_hdr->a_text, state->text_size);
        write741_to_byte_array (aout_hdr->a_data, state->data_size);
        write741_to_byte_array (aout_hdr->a_bss, state->bss_size);
        write741_to_byte_array (aout_hdr->a_entry, a_entry);
        write721_to_byte_array (aout_hdr->a_total, (state->text_size + state->data_size) + 0x8000);
        
        write741_to_byte_array (aout_hdr->a_trsize, tgr.relocations_count * sizeof (struct relocation_info));
        write741_to_byte_array (aout_hdr->a_drsize, dgr.relocations_count * sizeof (struct relocation_info)); 
    
    }
    
    if (fwrite ((char *) output, output_size, 1, state->ofp) != 1) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", state->ofile);
        return 1;
    
    }
    
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
    
    return 0;

}


int create_executable_from_aout_objects (void) {

    struct aout_object *object;
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
    
    } else if (state->format == LD_FORMAT_IA16_AOUT || state->format == LD_FORMAT_I386_AOUT) {
    
        if (init_aout_object ()) {
        
            report_at (program_name, 0, REPORT_ERROR, "failed to initialize a.out object");
            return EXIT_FAILURE;
        
        }
    
    }
    
    for (i = 0; i < state->nb_aout_objs; ++i) {
        paste (state->aout_objs[i]);
    }
    
    for (i = 0; i < state->nb_aout_objs; ++i) {
        apply_slides (state->aout_objs[i]);
    }
    
    for (i = 0; i < state->nb_aout_objs; ++i) {
        undef_collect (state->aout_objs[i]);
    }
    
    if (!state->impure) {
        state->bss_size = ALIGN_UP (state->bss_size, SECTION_ALIGNMENT);
    }
    
    for (i = 0; i < state->nb_aout_objs; ++i) {
    
        if (glue (state->aout_objs[i])) {
            err = 1;
        }
    
    }
    
    if (err) {
        return EXIT_FAILURE;
    }
    
    if (state->format == LD_FORMAT_IA16_AOUT || state->format == LD_FORMAT_I386_AOUT) {
        entry = get_entry ();
    }
    
    for (i = 0; i < state->nb_aout_objs; i++) {
    
        if ((object = state->aout_objs[i]) == NULL) {
            return EXIT_FAILURE;
        }
        
        /*if (state->mapfile) {
            init_map (object);
        }*/
        
        free (object->raw);
        free (object);
    
    }
    
    state->nb_aout_objs = 0;
    
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
    
    } else if (state->format == LD_FORMAT_IA16_AOUT || state->format == LD_FORMAT_I386_AOUT) {
    
        if (write_aout_object (entry)) {
        
            report_at (program_name, 0, REPORT_ERROR, "failed to write a.out object");
            return EXIT_FAILURE;
        
        }
    
    }
    
    return EXIT_SUCCESS;

}
