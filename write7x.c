/******************************************************************************
 * @file            write7x.c
 *****************************************************************************/
#include    <limits.h>

#include    "write7x.h"

void write721_to_byte_array (unsigned char *dest, unsigned int val) {

    int i;
    
    for (i = 0; i < 2; ++i) {
        dest[i] = (val >> (CHAR_BIT * i)) & UCHAR_MAX;
    }

}

void write741_to_byte_array (unsigned char *dest, unsigned long val) {

    int i;
    
    for (i = 0; i < 4; ++i) {
        dest[i] = (val >> (CHAR_BIT * i)) & UCHAR_MAX;
    }

}
