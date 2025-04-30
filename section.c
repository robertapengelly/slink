/******************************************************************************
 * @file            section.c
 *****************************************************************************/
#include    <string.h>

#include    "lib.h"
#include    "section.h"

struct object_file *all_object_files = 0;
struct section *all_sections = 0;

static struct object_file **last_object_file_p = &all_object_files;
static struct section **last_section_p = &all_sections;

static struct section *discarded_sections = 0;

struct object_file *object_file_make (const char *filename, unsigned long symbol_cnt) {

    struct object_file *of = xmalloc (sizeof (*of));
    
    of->filename = xstrdup (filename);
    
    of->symbol_arr = symbol_cnt ? xmalloc (sizeof (*of->symbol_arr) * symbol_cnt) : 0;
    of->symbol_cnt = symbol_cnt;
    
    *last_object_file_p = of;
    last_object_file_p = &of->next;
    
    return of;

}

struct section *section_find (const char *name) {

    struct section *section = 0;
    
    for (section = all_sections; section; section = section->next) {
    
        if (strcmp (section->name, name) == 0) {
            break;
        }
    
    }
    
    return section;

}

struct section *section_find_or_make (const char *name) {

    struct section *section;
    
    if ((section = section_find (name))) {
        return section;
    }
    
    section = xmalloc (sizeof (*section));
    section->name = xstrdup (name);
    
    section->last_part_p = &section->first_part;
    section->section_alignment = 1;
    
    *last_section_p = section;
    last_section_p = &section->next;
    
    return section;

}

struct section_part *section_part_new (struct section *section, struct object_file *of) {

    struct section_part *part = xmalloc (sizeof (*part));
    
    part->section = section;
    part->of = of;
    part->alignment = 1;
    
    return part;

}

void section_append_section_part (struct section *section, struct section_part *part) {

    *section->last_part_p = part;
    section->last_part_p = &part->next;

}

void sections_destroy_empty_before_collapse (void) {

    struct section *section, **next_p;
    
    struct section_part *part;
    struct subsection *subsection;
    
    for (next_p = &all_sections, section = *next_p; section; section = *next_p) {
    
        for (part = section->first_part; part; part = part->next) {
        
            if (part->content_size) {
                goto _done_section;
            }
        
        }
        
        for (subsection = section->all_subsections; subsection; subsection = subsection->next) {
        
            for (part = subsection->first_part; part; part = part->next) {
            
                if (part->content_size) {
                    goto _done_section;
                }
            
            }
        
        }
        
    _done_section:
        
        if (part && part->content_size) {
            next_p = &section->next;
        } else {
        
            *next_p = section->next;
            
            section->next = discarded_sections;
            discarded_sections = section;
        
        }
    
    }
    
    last_section_p = next_p;

}

void section_write (struct section *section, unsigned char *memory) {

    struct section_part *part;
    
    for (part = section->first_part; part; part = part->next) {
    
        if (part->content_size > 0) {
        
            memcpy (memory, part->content, part->content_size);
            memory += part->content_size;
        
        }
    
    }

}

int section_count (void) {

    struct section *section;
    int cnt = 0;
    
    for (section = all_sections; section; section = section->next) {
        cnt++;
    }
    
    return cnt;

}

struct subsection *subsection_find (struct section *section, const char *name) {

    struct subsection *subsection;
    
    for (subsection = section->all_subsections; subsection; subsection = subsection->next) {
    
        if (strcmp (subsection->name, name) == 0) {
            break;
        }
    
    }
    
    return subsection;

}

struct subsection *subsection_find_or_make (struct section *section, const char *name) {

    struct subsection *subsection, **next_p;
    
    for (subsection = *(next_p = &section->all_subsections); subsection; subsection = *(next_p = &subsection->next)) {
    
        if (strcmp (name, subsection->name) <= 0) {
            break;
        }
    
    }
    
    if (!subsection || strcmp (name, subsection->name) != 0) {
    
        subsection = xmalloc (sizeof (*subsection));
        
        subsection->name = xstrdup (name);
        subsection->next = *next_p;
        subsection->last_part_p = &subsection->first_part;
        
        *next_p = subsection;
    
    }
    
    return subsection;

}

void subsection_append_section_part (struct subsection *subsection, struct section_part *part) {

    *subsection->last_part_p = part;
    subsection->last_part_p = &part->next;

}
