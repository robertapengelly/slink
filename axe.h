/******************************************************************************
 * @file            axe.h
 *****************************************************************************/
#ifndef     _axe_H
#define     _axe_H

struct axe_exec32 {

    unsigned char a_info[4];
    unsigned char a_text[4];
    unsigned char a_data[4];
    unsigned char a_bss[4];
    unsigned char a_syms[4];
    unsigned char a_entry[4];
    unsigned char a_trsize[4];
    unsigned char a_drsize[4];

};

struct axe_exec64 {

    unsigned char a_info[8];
    unsigned char a_text[8];
    unsigned char a_data[8];
    unsigned char a_bss[8];
    unsigned char a_syms[8];
    unsigned char a_entry[8];
    unsigned char a_trsize[8];
    unsigned char a_drsize[8];

};

#define     AXE_UNDF                    0x00
#define     AXE_ABS                     0x02
#define     AXE_TEXT                    0x04
#define     AXE_DATA                    0x06
#define     AXE_BSS                     0x08
#define     AXE_COMM                    0x12

struct axe_relocation_info32 {

    unsigned char r_address[4];
    unsigned char r_symbolnum[4];

};

struct axe_relocation_info64 {

    unsigned char r_address[8];
    unsigned char r_symbolnum[8];

};

#define     AXE_EXT                     0x01

struct axe_nlist {

    unsigned char n_strx[4];
    unsigned char n_type;
    
    unsigned char n_other;
    unsigned char n_desc[2];
    
    unsigned char n_value[4];

};

#define     AXE_TYPE                      0x1e
void axe_before_link (void);

void axe_write32 (const char *filename);
void axe_write64 (const char *filename);

#endif      /* _axe_H */
