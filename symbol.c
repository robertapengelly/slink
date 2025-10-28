/******************************************************************************
 * @file            symbol.c
 *****************************************************************************/
#include    <stdlib.h>

#include    "hashtab.h"
#include    "ld.h"
#include    "report.h"
#include    "symbol.h"

static struct hashtab symbol_hashtab = { 0 };

struct symbol *symbol_find (const char *name) {

    struct hashtab_name *key;
    struct symbol *symbol;
    
    if (!(key = hashtab_alloc_name (name))) {
        return 0;
    }
    
    symbol = hashtab_get (&symbol_hashtab, key);
    free (key);
    
    return symbol;

}

void symbol_record_external_symbol (struct symbol *symbol) {

    struct symbol *old_symbol = symbol_find (symbol->name);
    
    if (!old_symbol) {
    
        symbol_add_to_hashtab (symbol);
        return;
    
    }
    
    if (symbol_is_undefined (old_symbol)) {
    
        symbol_remove_from_hashtab (old_symbol);
        symbol_add_to_hashtab (symbol);
        
        return;
    
    }
    
    if (symbol_is_undefined (symbol)) {
        return;
    }
    
    report_at (program_name, 0, REPORT_ERROR, "%s:(%s+0x%lx): multiple definition of '%s'", symbol->part->of->filename, symbol->part->section->name, symbol->value, symbol->name);
    report_at (program_name, 0, REPORT_NOTE, "%s:(%s+0x%lx): multiple definition of '%s'", old_symbol->part->of->filename, old_symbol->part->section->name, old_symbol->value, old_symbol->name);

}

int symbol_is_undefined (const struct symbol *symbol) {
    return symbol->section_number == UNDEFINED_SECTION_NUMBER;
}

void symbol_add_to_hashtab (struct symbol *symbol) {

    struct hashtab_name *key;
    
    if (!(key = hashtab_alloc_name (symbol->name))) {
        return;
    }
    
    hashtab_put (&symbol_hashtab, key, symbol);

}

void symbol_remove_from_hashtab (struct symbol *symbol) {

    struct hashtab_name *key;
    
    if (!(key = hashtab_alloc_name (symbol->name))) {
        return;
    }
    
    hashtab_remove (&symbol_hashtab, key);
    free (key);

}

uint64_t symbol_get_value_with_base (const struct symbol *symbol) {

    if (symbol->part) {
        return state->base_address + symbol->part->rva + symbol->value;
    }
    
    return symbol->value;

}

uint64_t symbol_get_value_no_base (const struct symbol *symbol) {

    if (symbol->part) {
        return symbol->part->rva + symbol->value;
    }
    
    return (symbol->value - state->base_address);

}

void symbols_for_each_global (void (*symbol_callback) (struct symbol *)) {

    struct hashtab_entry *entry;
    int i;
    
    for (i = 0; i < symbol_hashtab.capacity; i++) {
    
        if (!(entry = &symbol_hashtab.entries[i])) {
            continue;
        }
        
        if (!entry->key || !entry->value) {
            continue;
        }
        
        symbol_callback (entry->value);
    
    }

}
