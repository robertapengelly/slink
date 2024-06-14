/******************************************************************************
 * @file            ld.c
 *****************************************************************************/
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "aout.h"
#include    "hashtab.h"
#include    "ld.h"
#include    "lib.h"
#include    "report.h"
#include    "vector.h"

struct ld_state *state = 0;
const char *program_name = 0;

static void cleanup (void) {

    long i;
    
    if (state->ofp) {
        fclose (state->ofp);
    }
    
    if (get_error_count () > 0) {
    
        if (state->ofile) {
            remove (state->ofile);
        }
    
    }
    
    for (i = 0; i < state->nb_aout_objs; ++i) {
    
        struct aout_object *obj = state->aout_objs[i];
        
        if (obj == NULL) {
            continue;
        }
        
        if (obj->raw != NULL) {
            free (obj->raw);
        }
        
        free (obj);
    
    }

}


static unsigned long conv_dec (char *str, long max) {

    unsigned long value = 0;
    
    while (*str != ' ' && max-- > 0) {
    
        value *= 10;
        value += *str++ - '0';
    
    }
    
    return value;

}

static struct hashtab hashtab_globals = { 0 };
static struct vector vec_undef = { 0 };

static int process_aout (void *obj, unsigned long sz, const char *fname, int quiet) {

    struct i386_aout_exec *hdr = obj;
    
    struct aout_object *data_obj;
    struct nlist *symtab;
    
    struct relocation_info *trelocs;
    struct relocation_info *drelocs;
    
    long symtab_count, trelocs_count, drelocs_count;
    unsigned long symtab_off, strtab_off, trelocs_off, drelocs_off;
    
    char *strtab;
    long i;
    
    if (!(hdr->a_info[0] == 0x39 && hdr->a_info[1] == 0x01 && hdr->a_info[2] == 0x64 && hdr->a_info[3] == 0x00)) {
    
        if (!quiet) {
            report_at (program_name, 0, REPORT_ERROR, "'%s' is not a valid object", fname);
        }
        
        return 1;
    
    }
    
    for (i = 0; i < state->nb_aout_objs; ++i) {
    
        struct aout_object *obj_to_compare = state->aout_objs[i];
        
        if (obj_to_compare->size != sz) {
            continue;
        }
        
        if (memcmp (obj_to_compare->raw, obj, sz) == 0) {
            return 0;
        }
    
    }
    
    if (state->impure) {
    
        state->text_size    += GET_UINT32 (hdr->a_text);
        state->data_size    += GET_UINT32 (hdr->a_data);
        state->bss_size     += GET_UINT32 (hdr->a_bss);
    
    } else {
    
        state->text_size    += ALIGN_UP (GET_UINT32 (hdr->a_text),   SECTION_ALIGNMENT);
        state->data_size    += ALIGN_UP (GET_UINT32 (hdr->a_data),   SECTION_ALIGNMENT);
        state->bss_size     += ALIGN_UP (GET_UINT32 (hdr->a_bss),    SECTION_ALIGNMENT);
    
    }
    
    trelocs_off     = sizeof (*hdr) + GET_UINT32 (hdr->a_text) + GET_UINT32 (hdr->a_data);
    drelocs_off     = trelocs_off + GET_UINT32 (hdr->a_trsize);
    symtab_off      = drelocs_off + GET_UINT32 (hdr->a_drsize);
    strtab_off      = symtab_off + GET_UINT32 (hdr->a_syms);
    
    trelocs_count   = GET_UINT32 (hdr->a_trsize) / sizeof (*trelocs);
    drelocs_count   = GET_UINT32 (hdr->a_drsize) / sizeof (*drelocs);
    symtab_count    = GET_UINT32 (hdr->a_syms) / sizeof (*symtab);
    
    trelocs = (void *) ((char *) obj + trelocs_off);
    drelocs = (void *) ((char *) obj + drelocs_off);
    symtab  = (void *) ((char *) obj + symtab_off);
    strtab  = (char *) obj + strtab_off;
    
    if (!(data_obj = malloc (sizeof (*data_obj)))) {
        return 1;
    }
    
    memset (data_obj, 0, sizeof (*data_obj));
    
    data_obj->filename = fname;
    data_obj->header = hdr;
    data_obj->raw = obj;
    data_obj->size = sz;
    
    data_obj->trelocs = trelocs;
    data_obj->drelocs = drelocs;
    data_obj->symtab = symtab;
    data_obj->strtab = strtab;
    data_obj->trelocs_count = trelocs_count;
    data_obj->drelocs_count = drelocs_count;
    data_obj->symtab_count = symtab_count;
    
    dynarray_add (&state->aout_objs, &state->nb_aout_objs, data_obj);
    
    for (i = 0; i < symtab_count; ++i) {
    
        struct nlist *sym = &symtab[i];
        char *symname = strtab + GET_INT32 (sym->n_strx);
        
        if ((sym->n_type & N_TYPE) == N_UNDF) {
            vec_push (&vec_undef, (void *) symname);
        } else if (sym->n_type == 5 || sym->n_type == 7 || sym->n_type == 9) {
        
            struct hashtab_name *key;
            
            if ((key = hashtab_alloc_name (symname)) == NULL) {
            
                free (key);
                
                report_at (program_name, 0, REPORT_ERROR, "failed to allocate memory (memory full)");
                return 1;
            
            }
            
            if (hashtab_get (&hashtab_globals, key) != NULL) {
            
                free (key);
                continue;
            
            }
            
            hashtab_put (&hashtab_globals, key, symname);
        
        }
    
    }
    
    return 0;

}

struct ar_header {

    char name[16];
    char mtime[12];
    char owner[6];
    char group[6];
    char mode[8];
    char size[10];
    char endsig[2];

};

static int read_ar_obj (FILE *ar_file, const char *root_fname, unsigned long index) {

    struct ar_header hdr;
    unsigned long sz, sz_aligned;
    
    int i;
    
    char *fname, *path;
    void *obj;
    
    if ((fname = malloc (17)) == NULL) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to allocation memory (memory full)");
        return 1;
    
    }
    
    fseek (ar_file, index, SEEK_SET);
    
    if (fread (&hdr, sizeof (hdr), 1, ar_file) != 1) {
    
        if (feof (ar_file)) {
            return 0;
        }
        
        report_at (program_name, 0, REPORT_ERROR, "failed whilst reading '%s'", root_fname);
        return 1;
    
    }
    
    sz = conv_dec (hdr.size, 10);
    sz_aligned = (sz % 2) ? (sz + 1) : sz;
    
    memcpy (fname, hdr.name, 16);
    
    for (i = 0; i < 16; ++i) {
    
        if (fname[i] == 0x20 || fname[i] == '/') {
        
            fname[i] = '\0';
            break;
        
        }
    
    }
    
    if ((obj = malloc (sz_aligned)) == NULL) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to allocate memory (memory full)");
        return 1;
    
    }
    
    if (fread (obj, sz_aligned, 1, ar_file) != 1) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed whilst reading '%s'", root_fname);
        free (obj);
        
        return 1;
    
    }
    
    if (fname) {
    
        unsigned long len = strlen (root_fname) + 1 + strlen (fname) + 2;
        
        if ((path = malloc (len)) == NULL) {
        
            report_at (program_name, 0, REPORT_ERROR, "failed to allocate memory (memory full)");
            free (obj);
            
            return 1;
        
        }
        
        memset (path, 0, len);
        sprintf (path, "%s(%s)", root_fname, fname);
        
        if (process_aout (obj, sz, path, 1)) {
        
            free (obj);
            return 1;
        
        }
    
    } else {
    
        if (process_aout (obj, sz, "", 1)) {
        
            free (obj);
            return 1;
        
        }
    
    }
    
    free (fname);
    return 0;

}

static int process_archive (FILE *ar_file, const char *root_fname) {

    struct vector vec_undef2 = { 0 };
    char *fname, *path;
    
    void *obj;
    
    if ((fname = malloc (17)) == NULL) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to allocation memory (memory full)");
        return 1;
    
    }
    
    if (fseek (ar_file, 8, SEEK_SET) != 0) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed whilst seeking '%s'", root_fname);
        return 1;
    
    }
    
    for (;;) {
    
        struct ar_header hdr;
        
        int err, i;
        unsigned long sz, sz_aligned;
        
        if (fread (&hdr, sizeof (hdr), 1, ar_file) != 1) {
        
            if (feof (ar_file)) {
                break;
            }
            
            report_at (program_name, 0, REPORT_ERROR, "failed whilst reading '%s'", root_fname);
            return 1;
        
        }
            
        sz = conv_dec (hdr.size, 10);
        sz_aligned = (sz % 2) ? (sz + 1) : sz;
        
        if (memcmp (hdr.name, "__.SYMDEF", 9) == 0 || memcmp (hdr.name, "/", 1) == 0) {
        
            unsigned char temp[4], *temp3;
            unsigned long cnt, j, k, *temp2;
            
            if (fread (temp, 4, 1, ar_file) != 1) {
            
                report_at (program_name, 0, REPORT_ERROR, "failed to read symdef count");
                return 1;
            
            }
            
            cnt = (unsigned long) temp[3] | (((unsigned long) temp[2]) << 8) | (((unsigned long) temp[1]) << 16) | (((unsigned long) temp[0]) << 24);
            sz -= 4;
            
            if ((temp2 = (unsigned long *) malloc (cnt * sizeof (unsigned long))) == NULL) {
            
                report_at (program_name, 0, REPORT_ERROR, "failed to allocate memory (memory full)");
                return 1;
            
            }
            
            for (j = 0; j < cnt; ++j) {
            
                if (fread (temp, 4, 1, ar_file) != 1) {
                
                    report_at (program_name, 0, REPORT_ERROR, "failed to read symdef index");
                    return 1;
                
                }
                
                temp2[j] = (unsigned long) temp[3] | (((unsigned long) temp[2]) << 8) | (((unsigned long) temp[1]) << 16) | (((unsigned long) temp[0]) << 24);
            
            }
            
            sz -= cnt * 4;
            
            if ((temp3 = (unsigned char *) malloc (sz)) == NULL) {
            
                report_at (program_name, 0, REPORT_ERROR, "failed to allocate memory (memory full)");
                return 1;
            
            }
            
            if (fread (temp3, sz, 1, ar_file) != 1) {
            
                report_at (program_name, 0, REPORT_ERROR, "failed to read symdef symbols");
                return 1;
            
            }
            
            while (vec_undef.length > 0) {
            
                char *symname = (char *) vec_pop (&vec_undef);
                
                struct hashtab_name *key;
                char *temp;
                
                if ((key = hashtab_alloc_name (symname)) == NULL) {
                
                    report_at (program_name, 0, REPORT_ERROR, "failed to allocate memory (memory full)");
                    return 1;
                
                }
                
                if ((temp = hashtab_get (&hashtab_globals, key)) != NULL) {
                
                    if (strcmp (temp, symname) != 0) {
                    
                        free (key);
                        
                        report_at (program_name, 0, REPORT_ERROR, "hashtab collison");
                        return 1;
                    
                    }
                    
                    continue;
                
                }
                
                free (key);
                
                for (j = 0, k = 0; k < sz; ) {
                
                    unsigned long len = strlen ((char *) temp3 + k) + 1;
                    
                    if (strcmp ((char *) temp3 + k, symname) == 0) {
                        break;
                    }
                    
                    k += len;
                    j++;
                
                }
                
                if (j >= cnt) {
                
                    vec_push (&vec_undef2, symname);
                    continue;
                
                }
                
                if (read_ar_obj (ar_file, root_fname, temp2[j])) {
                
                    report_at (program_name, 0, REPORT_ERROR, "failed whilst reading ar object");
                    return 1;
                
                }
            
            }
            
            memcpy (&vec_undef, &vec_undef2, sizeof (vec_undef));
            return 0;
        
        }
        
        memcpy (fname, hdr.name, 16);
        
        for (i = 0; i < 16; ++i) {
        
            if (fname[i] == 0x20 || fname[i] == '/') {
            
                fname[i] = '\0';
                break;
            
            }
        
        }
        
        if ((obj = malloc (sz_aligned)) == NULL) {
        
            report_at (program_name, 0, REPORT_ERROR, "failed to allocate memory (memory full)");
            return 1;
        
        }
        
        if (fread (obj, sz_aligned, 1, ar_file) != 1) {
        
            report_at (program_name, 0, REPORT_ERROR, "failed whilst reading '%s'", root_fname);
            free (obj);
            
            return 1;
        
        }
        
        if (fname) {
        
            unsigned long len = strlen (root_fname) + 1 + strlen (fname) + 2;
            
            if ((path = malloc (len)) == NULL) {
            
                report_at (program_name, 0, REPORT_ERROR, "failed to allocate memory (memory full)");
                free (obj);
                
                return 1;
            
            }
            
            memset (path, 0, len);
            sprintf (path, "%s(%s)", root_fname, fname);
            
            if ((err = process_aout (obj, sz, path, 1))) {
                free (obj);
            }
        
        } else {
        
            if ((err = process_aout (obj, sz, "", 1))) {
                free (obj);
            }
        
        }
        
        obj = NULL;
    
    }
    
    free (fname);
    return 0;

}

static int process_file (const char *fname) {

    FILE *ifp;
    void *obj;
    
    char *ar_magic[8];
    long obj_sz;
    
    int err;
    
    if ((ifp = fopen (fname, "rb")) == NULL) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to open '%s' for reading", fname);
        return 1;
    
    }
    
    if (fread (ar_magic, 8, 1, ifp) != 1) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed whilst reading '%s'", fname);
        fclose (ifp);
        
        return 1;
    
    }
    
    if (memcmp (ar_magic, "!<arch>\n", 8) == 0) {
    
        int err = process_archive (ifp, fname);
        fclose (ifp);
        
        if (err) {
            return EXIT_FAILURE;
        }
        
        return EXIT_SUCCESS;
    
    }
    
    if (fseek (ifp, 0, SEEK_END) != 0) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed whist seeking '%s'", fname);
        fclose (ifp);
        
        return 1;
    
    }
    
    if ((obj_sz = ftell (ifp)) == -1) {
    
        report_at (program_name, 0, REPORT_ERROR, "size of '%s' is -1", fname);
        fclose (ifp);
        
        return 1;
    
    }
    
    rewind (ifp);
    
    if ((obj = malloc (obj_sz)) == NULL) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to allocation memory (memory full)");
        fclose (ifp);
        
        return 1;
    
    }
    
    if (fread (obj, obj_sz, 1, ifp) != 1) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed whilst reading '%s'", fname);
        free (obj);
        
        fclose (ifp);
        return 1;
    
    }
    
    if ((err = process_aout (obj, obj_sz, fname, 1))) {
    
        report_at (fname, 0, REPORT_ERROR, "file format not recognized");
        free (obj);
        
        fclose (ifp);
        return 1;
    
    }
    
    fclose (ifp);
    return 0;

}

int main (int argc, char **argv) {

    long i;
    
    if (argc && *argv) {
    
        char *p;
        program_name = *argv;
        
        if ((p = strrchr (program_name, '/')) || (p = strrchr (program_name, '\\'))) {
            program_name = (p + 1);
        }
    
    }
    
    atexit (cleanup);
    
    state = xmalloc (sizeof (*state));
    parse_args (argc, argv, 1);
    
    if (state->nb_files == 0) {
    
        report_at (program_name, 0, REPORT_ERROR, "no input files provided");
        exit (EXIT_FAILURE);
    
    }
    
    if (!state->entry || strcmp (state->entry, "") == 0) {
        state->entry = "_start";
    }
    
    if (!state->ofile) {
        state->ofile = xstrdup ("a.out");
    }
    
    if (state->format == LD_FORMAT_BIN || state->format == LD_FORMAT_COM) {
    
        if (state->format == LD_FORMAT_COM) {
            state->psp = 0x100;
        }
        
        state->impure = 1;
    
    }
    
    for (i = 0; i < state->nb_files; i++) {
    
        if (process_file (state->files[i])) {
            return EXIT_FAILURE;
        }
    
    }
    
    if (state->nb_aout_objs > 0) {
    
        if (create_executable_from_aout_objects ()) {
            return EXIT_FAILURE;
        }
    
    }
    
    return EXIT_SUCCESS;

}
