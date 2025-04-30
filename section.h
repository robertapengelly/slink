/******************************************************************************
 * @file            section.h
 *****************************************************************************/
#ifndef     _SECTION_H
#define     _SECTION_H

#include    "reloc.h"
#include    "symbol.h"

struct object_file {

    char *filename;
    
    struct symbol *symbol_arr;
    unsigned long symbol_cnt;
    
    struct object_file *next;

};

struct section_part {

    struct section *section;
    struct object_file *of;
    
    unsigned char *content;
    unsigned long content_size, alignment;
    
    struct reloc_entry *reloc_arr;
    unsigned long reloc_cnt;
    
    unsigned long rva;
    struct section_part *next;

};

struct subsection {

    char *name;
    
    struct section_part *first_part;
    struct section_part **last_part_p;
    
    struct subsection *next;

};

#define     UNDEFINED_SECTION_NUMBER    0
#define     ABSOLUTE_SECTION_NUMBER     (-1)

struct section {

    char *name;
    int flags;
    
    struct section_part *first_part;
    struct section_part **last_part_p;
    
    struct subsection *all_subsections;
    
    unsigned long total_size;
    int is_bss;
    
    unsigned long rva;
    unsigned long section_alignment;
    
    int target_index;
    void *object_dependent_data;
    
    struct section *next;

};

#define     SECTION_FLAG_ALLOC          (1U << 0)
#define     SECTION_FLAG_LOAD           (1U << 1)
#define     SECTION_FLAG_READONLY       (1U << 2)
#define     SECTION_FLAG_CODE           (1U << 3)
#define     SECTION_FLAG_DATA           (1U << 4)
#define     SECTION_FLAG_NEVER_LOAD     (1U << 5)
#define     SECTION_FLAG_DEBUGGING      (1U << 6)
#define     SECTION_FLAG_EXCLUDE        (1U << 7)
#define     SECTION_FLAG_NOREAD         (1U << 8)
#define     SECTION_FLAG_SHARED         (1U << 9)

extern struct object_file *all_object_files;
extern struct section *all_sections;

struct object_file *object_file_make (const char *filename, unsigned long symbol_cnt);

struct section_part *section_part_new (struct section *section, struct object_file *of);
void section_append_section_part (struct section *section, struct section_part *part);

struct section *section_find (const char *name);
struct section *section_find_or_make (const char *name);

void sections_destroy_empty_before_collapse (void);
void section_write (struct section *section, unsigned char *memory);

int section_count (void);

struct subsection *subsection_find (struct section *section, const char *name);
struct subsection *subsection_find_or_make (struct section *section, const char *name);

void subsection_append_section_part (struct subsection *subsection, struct section_part *part);

#endif      /* _SECTION_H */
