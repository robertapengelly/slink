/******************************************************************************
 * @file            aout.h
 *****************************************************************************/
#ifndef     _AOUT_H
#define     _AOUT_H

struct aout_exec {

    unsigned char a_info[4];
    unsigned char a_text[4];
    unsigned char a_data[4];
    unsigned char a_bss[4];
    unsigned char a_syms[4];
    unsigned char a_entry[4];
    unsigned char a_trsize[4];
    unsigned char a_drsize[4];

};

#define     N_UNDF                      0x00
#define     N_ABS                       0x02
#define     N_TEXT                      0x04
#define     N_DATA                      0x06
#define     N_BSS                       0x08

struct relocation_info {

    unsigned char r_address[4];
    unsigned char r_symbolnum[4];

};

#define     N_EXT                       0x01

struct nlist {

    unsigned char n_strx[4];
    unsigned char n_type;
    
    unsigned char n_value[4];

};

#define     N_TYPE                      0x1e
int create_executable_from_aout_objects (void);

#endif      /* _AOUT_H */
