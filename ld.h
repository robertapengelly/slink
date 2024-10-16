/******************************************************************************
 * @file            ld.h
 *****************************************************************************/
#ifndef     _LD_H
#define     _LD_H

#include    "aout.h"

struct elks_object {

    const char *filename;
    void *raw;
    
    unsigned long size;
    
    struct elks_exec *header;
    struct elks_relocation_info *trelocs, *drelocs;
    
    struct elks_nlist *symtab;
    char *strtab;
    
    long symtab_count, trelocs_count, drelocs_count;
    unsigned long text_slide, data_slide, bss_slide;

};

#define     GET_INT32(arr)              ((long) arr[0] | (((long) arr[1]) << 8) | (((long) arr[2]) << 16) | (((long) arr[3]) << 24))
#define     GET_UINT32(arr)             ((unsigned long) arr[0] | (((unsigned long) arr[1]) << 8) | (((unsigned long) arr[2]) << 16) | (((unsigned long) arr[3]) << 24))

#include    <stdio.h>

struct ld_state {

    const char **files;
    long nb_files;
    
    const char *ofile;
    FILE *ofp;
    
    int format, impure;
    int psp;
    
    struct elks_object **elks_objs;
    long nb_elks_objs;
    
    unsigned long text_size, data_size, bss_size;
    char *entry;

};

#define     LD_FORMAT_COM               0x00
#define     LD_FORMAT_BIN               0x01

#define     LD_FORMAT_IA16_AOUT         0x02
#define     LD_FORMAT_I386_AOUT         0x04

extern struct ld_state *state;
extern const char *program_name;

#define     FILE_ALIGNMENT              512
#define     SECTION_ALIGNMENT           4096

#define     DIV_ROUNDUP(a, b)           (((a) + ((b) - 1)) / (b))
#define     ALIGN_UP(x, a)              (DIV_ROUNDUP ((x), (a)) * (a))

#endif      /* _LD_H */
