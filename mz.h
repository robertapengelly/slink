/******************************************************************************
 * @file            pe.h
 *****************************************************************************/
#ifndef     _MZ_H
#define     _MZ_H

#define     DEFAULT_SECTION_ALIGNMENT       0x1000
#define     DEFAULT_FILE_ALIGNMENT          0x0200

struct mz_exec {

    unsigned char e_magic[2];           /* Magic number                         */
    unsigned char e_cblp[2];            /* Bytes on last page of file           */
    unsigned char e_cp[2];              /* Pages in file                        */
    unsigned char e_crlc[2];            /* Relocations                          */
    unsigned char e_cparhdr[2];         /* Size of header in paragraphs         */
    unsigned char e_minalloc[2];        /* Minimum extra paragraphs needed      */
    unsigned char e_maxalloc[2];        /* Maximum extra paragraphs needed      */
    unsigned char e_ss[2];              /* Initial (relative) SS value          */
    unsigned char e_sp[2];              /* Initial SP value                     */
    unsigned char e_csum[2];            /* Checksum                             */
    unsigned char e_ip[2];              /* Initial IP value                     */
    unsigned char e_cs[2];              /* Initial (relative) CS value          */
    unsigned char e_lfarlc[2];          /* File address of relocation table     */
    unsigned char e_ovno[2];            /* Overlay number                       */

};

void mz_write (const char *filename);

#endif      /* _MZ_H */
