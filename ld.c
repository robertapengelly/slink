/******************************************************************************
 * @file            ld.c
 *****************************************************************************/
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "aout.h"
#include    "elks.h"
#include    "ld.h"
#include    "lib.h"
#include    "pe.h"
#include    "report.h"
#include    "section.h"

struct ld_state *state = 0;
const char *program_name = 0;

static void cleanup (void) {

    if (get_error_count () > 0) {
    
        if (state->output_filename) {
            remove (state->output_filename);
        }
    
    }

}

static int read_file_into_memory (const char *filename, unsigned char **memory_p, unsigned long *size_p) {

    unsigned char *memory;
    FILE *fp;
    
    unsigned long mem_size;
    
    if (!(fp = fopen (filename, "rb"))) {
        return 1;
    }
    
    fseek (fp, 0, SEEK_END);
    mem_size = ftell (fp);
    
    fseek (fp, 0, SEEK_SET);
    memory = xmalloc (mem_size);
    
    if (fread (memory, mem_size, 1, fp) != 1) {
    
        fclose (fp);
        
        free (memory);
        return 1;
    
    }
    
    fclose (fp);
    
    *memory_p = memory;
    *size_p = mem_size;
    
    return 0;

}

static void read_input_file (const char *filename) {

    unsigned char *data;
    unsigned long data_size;
    
    if (read_file_into_memory (filename, &data, &data_size)) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to read file '%s' into memory", filename);
        return;
    
    }
    
    /*if (memcmp (data, "!<arch>\n", 8) == 0) {
        read_archive (filename, data, data_size);
    } else*/ if (data[0] == 0x01 && data[1] == 0x03) {
        read_elks_object (filename, data, data_size);
    } else if (data[0] == 0x07 && data[1] == 0x01) {
        read_aout_object (filename, data, data_size);
    } else {
        report_at (program_name, 0, REPORT_ERROR, "%s: unrecognised file format", filename);
    }
    
    free (data);

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
    
    if (state->nb_input_files == 0) {
    
        report_at (program_name, 0, REPORT_ERROR, "no input files provided");
        exit (EXIT_FAILURE);
    
    }
    
    if (state->format == LD_FORMAT_I386_AOUT || state->format == LD_FORMAT_I386_ELKS || state->format == LD_FORMAT_IA16_ELKS) {
    
        section_find_or_make (".text");
        section_find_or_make (".data");
        section_find_or_make (".bss");
    
    }
    
    if (!state->output_filename) {
        state->output_filename = "a.out";
    }
    
    for (i = 0; i < state->nb_input_files; i++) {
        read_input_file (state->input_files[i]);
    }
    
    if (get_error_count () > 0) { return EXIT_FAILURE; }
    sections_destroy_empty_before_collapse ();
    
    if (!state->use_custom_base_address) {
    
        if (state->format == LD_FORMAT_COM) {
            state->base_address = 0x00000100;
        } else if (state->format == LD_FORMAT_I386_PE) {
            state->base_address = 0x00400000;
        }
    
    }
    
    if (state->format == LD_FORMAT_I386_PE) {
        pe_before_link ();
    }
    
    link ();
    
    if (get_error_count () > 0) {
        return EXIT_FAILURE;
    }
    
    if (state->format == LD_FORMAT_BIN || state->format == LD_FORMAT_COM) {
    
        FILE *fp;
        
        unsigned char *data;
        unsigned long data_size = 0;
        
        struct section *section;
        
        if (!(fp = fopen (state->output_filename, "wb"))) {
        
            report_at (program_name, 0, REPORT_ERROR, "cannot open '%s' for writing", state->output_filename);
            return EXIT_FAILURE;
        
        }
        
        for (section = all_sections; section; section = section->next) {
        
            if (data_size < section->rva + section->total_size) {
                data_size = section->rva + section->total_size;
            }
        
        }
        
        data = xmalloc (data_size);
        
        for (section = all_sections; section; section = section->next) {
        
            if (section->is_bss) {
                continue;
            }
            
            section_write (section, data + section->rva);
        
        }
        
        if (fwrite (data, data_size, 1, fp) != 1) {
            report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", state->output_filename);
        }
        
        free (data);
        fclose (fp);
    
    } else if (state->format == LD_FORMAT_I386_AOUT) {
        aout_write (state->output_filename);
    } else if (state->format == LD_FORMAT_I386_ELKS || state->format == LD_FORMAT_IA16_ELKS) {
        elks_write (state->output_filename);
    } else if (state->format == LD_FORMAT_I386_PE) {
    
        pe_after_link ();
        pe_write (state->output_filename);
    
    }
    
    if (state->output_map_filename) {
        map_write (state->output_map_filename);
    }
    
    return (get_error_count () > 0 ? EXIT_FAILURE : EXIT_SUCCESS);

}
