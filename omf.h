/******************************************************************************
 * @file            omf.h
 *****************************************************************************/
#ifndef     _OMF_H
#define     _OMF_H

#define     RECORD_TYPE_THEADR          0x80
#define     RECORD_TYPE_COMENT          0x88
#define     RECORD_TYPE_MODEND          0x8A
#define     RECORD_TYPE_EXTDEF          0x8C
#define     RECORD_TYPE_PUBDEF          0x90
#define     RECORD_TYPE_LNAMES          0x96
#define     RECORD_TYPE_SEGDEF          0x98
#define     RECORD_TYPE_GRPDEF          0x9A
#define     RECORD_TYPE_FIXUPP          0x9C
#define     RECORD_TYPE_LEDATA          0xA0

#define     SEGMENT_ATTR_P              0x1

#define     METHOD_T2_EXTDEF            2
#define     METHOD_F5                   5

void read_omf_object (const char *filename, unsigned char *data, unsigned long data_size);

#endif      /* _OMF_H */
