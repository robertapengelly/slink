/******************************************************************************
 * @file            symbol.h
 *****************************************************************************/
#ifndef     _SYMBOL_H
#define     _SYMBOL_H

#include    "section.h"

struct symbol {

    char *name;
    int flags, n_type;
    
    unsigned long value;
    unsigned long size;
    
    long section_number;                /* 1-based, 0 means undefined, negative numbers have special meaning. */
    int auxiliary;                      /* such symbol should be ignored and is only a filter. */
    
    struct section_part *part;

};

#define     SYMBOL_FLAG_EXCLUDE_EXPORT                      (1U << 0)
#define     SYMBOL_FLAG_SECTION_SYMBOL                      (1U << 1)

struct symbol *symbol_find (const char *name);

void symbol_record_external_symbol (struct symbol *symbol);
int symbol_is_undefined (const struct symbol *symbol);

void symbol_add_to_hashtab (struct symbol *symbol);
void symbol_remove_from_hashtab (struct symbol *symbol);

unsigned long symbol_get_value_with_base (const struct symbol *symbol);
unsigned long symbol_get_value_no_base (const struct symbol *symbol);

#endif      /* _SYMBOL_H */
