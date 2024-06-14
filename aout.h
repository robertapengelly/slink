/******************************************************************************
 * @file            aout.h
 *****************************************************************************/
#ifndef     _AOUT_H
#define     _AOUT_H

struct ia16_aout_exec {

    unsigned char a_magic[2];
    unsigned char a_flags;
    unsigned char a_cpu;
    unsigned char a_hdrlen;
    unsigned char a_unused;
    unsigned char a_version[2];
    
    unsigned char a_text[4];
    unsigned char a_data[4];
    unsigned char a_bss[4];
    unsigned char a_entry[4];
    unsigned char a_total[4];
    unsigned char a_syms[4];
    
    unsigned char a_trsize[4];
    unsigned char a_drsize[4];
    unsigned char a_trbase[4];
    unsigned char a_drbase[4];

};

struct i386_aout_exec {

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

#define     OMAGIC                      0407
#define     ZMAGIC                      0413

/*struct aout_nlist {

    unsigned char n_strx[4];
    unsigned char n_type;
    
    unsigned char n_other;
    unsigned char n_desc[2];
    
    unsigned char n_value[4];

};*/

#define     N_TYPE                      0x1e
int create_executable_from_aout_objects (void);

#endif      /* _AOUT_H */
