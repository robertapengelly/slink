/******************************************************************************
 * @file            map.c
 *****************************************************************************/
#include    "stdint.h"

#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "inttypes.h"
#include    "ld.h"
#include    "report.h"
#include    "section.h"
#include    "symbol.h"

static int symbol_compare (const void *a, const void *b) {

    const struct symbol *sa = a, *sb = b;
    
    if (sa->auxiliary && sb->auxiliary) {
        return 0;
    }
    
    if (sa->auxiliary) {
        return 1;
    }
    
    if (sb->auxiliary) {
        return -1;
    }
    
    if (symbol_get_value_with_base (sa) < symbol_get_value_with_base (sb)) {
        return -1;
    }
    
    if (symbol_get_value_with_base (sa) > symbol_get_value_with_base (sb)) {
        return 1;
    }
    
    return 0;

}

static void sort_symbols (void) {

    struct object_file *of;
    
    for (of = all_object_files; of; of = of->next) {
        qsort (of->symbol_arr, of->symbol_cnt, sizeof (*of->symbol_arr), &symbol_compare);
    }

}

void map_write (const char *filename) {

    FILE *fp;
    
    struct symbol *symbol;
    struct section *section;
    struct section_part *part;
    
    int printed_chars;
    
    if (strcmp (filename, "") == 0) {
        fp = stdout;
    } else if (!(fp = fopen (filename, "wb"))) {
    
        report_at (program_name, 0, REPORT_ERROR, "cannot open '%s' for writing", filename);
        return;
    
    }
    
    sort_symbols ();
    
    for (section = all_sections; section; section = section->next) {
    
        if ((printed_chars = fprintf (fp, "%-16s", section->name)) > 16) {
            fprintf (fp, "\n%-16s", "");
        }
        
        fprintf (fp, "0x%08"PRIx64"  %12"PRIu64"\n\n", state->base_address + section->rva, section->total_size);
        
        for (part = section->first_part; part; part = part->next) {
        
            if ((printed_chars = fprintf (fp, "    %-12s", section->name)) > 16) {
                fprintf (fp, "\n%-16s", "");
            }
            
            fprintf (fp, "0x%08"PRIx64"  %12"PRIu64" %s\n", state->base_address + part->rva, part->content_size, part->of->filename);
            
            for (symbol = part->of->symbol_arr; symbol < part->of->symbol_arr + part->of->symbol_cnt; symbol++) {
            
                if (symbol->auxiliary || symbol->part != part) {
                    continue;
                }
                
                if (symbol->value == 0 || strncmp (section->name, symbol->name, strlen (section->name)) == 0) {
                    continue;
                }
                
                fprintf (fp, "%-16s %12"PRIu64" %10s %s\n", "", symbol_get_value_with_base (symbol), "", symbol->name);
            
            }
        
        }
        
        fprintf (fp, "\n");
    
    }
    
    fprintf (fp, "\n");
    
    {
    
        struct section *last_section = 0;
        
        for (section = all_sections; section; section = section->next) {
            last_section = section;
        }
        
        fprintf (fp, "Sizeof Module: %"PRIu64" bytes\n", last_section ? (last_section->rva + last_section->total_size) : 0);
    
    }
    
    fprintf (fp, "Entry Point: 0x%08lx\n", state->base_address + state->entry_point);
    
    if (strcmp (filename, "") != 0) {
        fclose (fp);
    }

}
