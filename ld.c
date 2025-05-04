/******************************************************************************
 * @file            ld.c
 *****************************************************************************/
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "aout.h"
#include    "ar.h"
#include    "coff.h"
#include    "elks.h"
#include    "ld.h"
#include    "lib.h"
#include    "mz.h"
#include    "omf.h"
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

static int read_object_file (const char *filename, unsigned char *data, unsigned long data_size) {

    /*report_at (program_name, 0, REPORT_ERROR, "%s: signature: %#x:%#x", filename, data[0], data[1]);*/
    /*printf ("reading: %s\n", filename);*/
    
    if (data[0] == 0x01 && data[1] == 0x03) {
    
        read_elks_object (filename, data, data_size);
        return 0;
    
    }
    
    if (data[0] == 0x07 && data[1] == 0x01) {
    
        read_aout_object (filename, data, data_size);
        return 0;
    
    }
    
    if (data[0] == 0x4C && data[1] == 0x01) {
    
        read_coff_object (filename, data, data_size);
        return 0;
    
    }
    
    if (data[0] == 0 && data[1] == 0) {
    
        if (data[2] == 0xff && data[3] == 0xff) {
        
            read_pe_import_library (filename, data);
            return 0;
        
        }
    
    }
    
    if (data[0] == RECORD_TYPE_THEADR) {
    
        read_omf_object (filename, data, data_size);
        return 0;
    
    }
    
    report_at (program_name, 0, REPORT_ERROR, "%s: unrecognised file format", filename);
    return 1;

}

struct offset_name_table {

    char *name;
    unsigned long offset;

};

#define     ALREADY_READ                "Already read"

static int read_archive_memeber (unsigned char *pos, const char *filename) {

    struct ar_header *hdr = (struct ar_header *) pos;
    
    char *temp, *name;
    unsigned long data_size;
    
    int ret;
    
    if (memcmp (pos, ALREADY_READ, sizeof (ALREADY_READ)) == 0) {
        return 0;
    }
    
    hdr = (struct ar_header *) pos;
    
    temp = xstrndup (hdr->name, sizeof (hdr->name));
    strip_trailing_spaces (temp);
    
    if (temp) {
    
        unsigned long member_name_len = strlen (temp);
        
        if (member_name_len && temp[member_name_len - 1] == '/' && temp[0] != '/') {
            temp[member_name_len - 1] = '\0';
        }
    
    }
    
    name = xmalloc (strlen (filename) + 1 + strlen (temp) + 1 + 1);
    sprintf (name, "%s(%s)", filename, temp);
    
    free (temp);
    
    temp = xstrndup (hdr->size, sizeof (hdr->size));
    strip_trailing_spaces (temp);
    
    data_size = strtoul (temp, NULL, 10);
    free (temp);
    
    ret = read_object_file (name, pos + sizeof (*hdr), data_size);
    free (name);
    
    memcpy (pos, ALREADY_READ, sizeof (ALREADY_READ));
    return ret;

}

static void read_archive (const char *filename, unsigned char *data) {

    unsigned char *pos = data + 8;
    
    struct ar_header *hdr = (struct ar_header *) pos;
    struct offset_name_table *offset_name_table;
    
    char *string_table_pos, *name;
    unsigned long no_symbols, i;
    
    unsigned long start_header_object_offset = 0;
    unsigned long end_header_object_offset = 0;
    
    name = xstrndup (hdr->name, sizeof (hdr->name));
    strip_trailing_spaces (name);
    
    if (strcmp (name, "/") != 0) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: unable to add symbols: archive has no index; run ranlib to add one", filename);
        
        free (name);
        return;
    
    }
    
    free (name);
    pos += sizeof (*hdr);
    
    no_symbols = byte_array_to_integer (pos, 4, 1);
    pos += 4;
    
    offset_name_table = xmalloc (sizeof (*offset_name_table) * no_symbols);
    string_table_pos = (char *) pos + (no_symbols * 4);
    
    for (i = 0; i < no_symbols; i++) {
    
        offset_name_table[i].offset = byte_array_to_integer (pos, 4, 1);
        offset_name_table[i].name = (char *) string_table_pos;
        
        string_table_pos += strlen (offset_name_table[i].name) + 1;
        pos += 4;
    
    }
    
    if (state->format == LD_FORMAT_I386_PE) {
    
        for (i = 0; i < no_symbols && (!start_header_object_offset || !end_header_object_offset); i++) {
        
            char *symbol_name = offset_name_table[i].name;
            
            if (strncmp (symbol_name, "__head_", 7) == 0) {
                start_header_object_offset = offset_name_table[i].offset;
            } else if (strlen (symbol_name) > 6 && strncmp (symbol_name + strlen (symbol_name) - 6, "_iname", 6) == 0) {
                end_header_object_offset = offset_name_table[i].offset;
            }
        
        }
        
        if (start_header_object_offset) {
            read_archive_memeber (data + start_header_object_offset, filename);
        }
    
    }
    
    while (1) {
    
        struct symbol *symbol;
        int change = 0;
        
        for (i = 0; i < no_symbols; i++) {
        
            if (!(symbol = symbol_find (offset_name_table[i].name)) || !symbol_is_undefined (symbol)) {
                continue;
            }
            
            if (offset_name_table[i].offset == start_header_object_offset || offset_name_table[i].offset == end_header_object_offset) {
                continue;
            }
            
            if (!read_archive_memeber (data + offset_name_table[i].offset, filename)) {
                change = 1;
            }
        
        }
        
        if (change == 0) {
            break;
        }
    
    }
    
    if (state->format == LD_FORMAT_I386_PE) {
    
        if (end_header_object_offset) {
            read_archive_memeber (data + end_header_object_offset, filename);
        }
        
        pe_archive_end ();
    
    }
    
    free (offset_name_table);

}

static void read_input_file (const char *filename) {

    unsigned char *data;
    unsigned long data_size;
    
    if (read_file_into_memory (filename, &data, &data_size)) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to read file '%s' into memory", filename);
        return;
    
    }
    
    if (memcmp (data, "!<arch>\n", 8) == 0) {
        read_archive (filename, data);
    } else {
        read_object_file (filename, data, data_size);
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
    
    if (state->format == LD_FORMAT_I386_AOUT || state->format == LD_FORMAT_I386_ELKS || state->format == LD_FORMAT_IA16_ELKS || state->format == LD_FORMAT_MZ) {
    
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
    
    if (state->format == LD_FORMAT_I386_COFF) {
        coff_before_link ();
    } else if (state->format == LD_FORMAT_I386_PE) {
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
        
        if (data_size > 0 && fwrite (data, data_size, 1, fp) != 1) {
            report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", state->output_filename);
        }
        
        free (data);
        fclose (fp);
    
    } else if (state->format == LD_FORMAT_MZ) {
        mz_write (state->output_filename);
    } else if (state->format == LD_FORMAT_I386_AOUT) {
        aout_write (state->output_filename);
    } else if (state->format == LD_FORMAT_I386_ELKS || state->format == LD_FORMAT_IA16_ELKS) {
        elks_write (state->output_filename);
    } else if (state->format == LD_FORMAT_I386_PE) {
    
        pe_after_link ();
        pe_write (state->output_filename);
    
    } else if (state->format == LD_FORMAT_I386_COFF) {
    
        coff_after_link ();
        coff_write (state->output_filename);
    
    }
    
    if (state->output_map_filename) {
        map_write (state->output_map_filename);
    }
    
    return (get_error_count () > 0 ? EXIT_FAILURE : EXIT_SUCCESS);

}
