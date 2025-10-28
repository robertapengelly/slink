/******************************************************************************
 * @file            reloc.h
 *****************************************************************************/
#ifndef     _RELOC_H
#define     _RELOC_H

enum {

    RELOC_TYPE_IGNORED,
    
    RELOC_TYPE_64,
    RELOC_TYPE_32,
    RELOC_TYPE_16,
    RELOC_TYPE_8,
    
    RELOC_TYPE_PC64,
    RELOC_TYPE_PC32,
    RELOC_TYPE_PC16,
    RELOC_TYPE_PC8,
    
    RELOC_TYPE_32_NO_BASE,
    
    RELOC_TYPE_64_ADD,
    RELOC_TYPE_32_ADD,
    RELOC_TYPE_24_ADD,
    RELOC_TYPE_16_ADD,
    RELOC_TYPE_8_ADD,
    
    RELOC_TYPE_64_SUB,
    RELOC_TYPE_32_SUB,
    RELOC_TYPE_24_SUB,
    RELOC_TYPE_16_SUB,
    RELOC_TYPE_8_SUB,
    
    RELOC_TYPE_AARCH64_ADR_PREL_PG_HI21,
    RELOC_TYPE_AARCH64_ADD_ABS_LO12_NC,
    RELOC_TYPE_AARCH64_LDST8_ABS_LO12_NC,
    RELOC_TYPE_AARCH64_LDST16_ABS_LO12_NC,
    RELOC_TYPE_AARCH64_LDST32_ABS_LO12_NC,
    RELOC_TYPE_AARCH64_LDST64_ABS_LO12_NC,
    RELOC_TYPE_AARCH64_LDST128_ABS_LO12_NC,
    RELOC_TYPE_AARCH64_JUMP26,
    RELOC_TYPE_AARCH64_CALL26,
    
    RELOC_TYPE_END

};

struct section_part;
struct symbol;
struct reloc_entry;

struct reloc_howto {

    int size;
    int pc_rel;
    int no_base;
    int final_right_shift;
    
    void (*special_function) (struct section_part *part, struct reloc_entry *rel, struct symbol *symbol);
    
    const char *name;
    unsigned long dst_mask;
    
    int final_left_shift;

};

extern struct reloc_howto reloc_howtos[RELOC_TYPE_END];

struct reloc_entry {

    struct symbol *symbol;
    
    unsigned long offset;
    unsigned long addend;
    
    unsigned long symbolnum, r_symbolnum;
    unsigned int n_type, n_ext;
    
    struct reloc_howto *howto;

};

#endif      /* _RELOC_H */
