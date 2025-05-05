/******************************************************************************
 * @file            lib.h
 *****************************************************************************/
#ifndef     _LIB_H
#define     _LIB_H

#define     ALIGN(a, b)                 (((a) / (b) + (((a) % (b)) ? 1 : 0)) * (b))
enum ld_option_type { LD_OPTION_TYPE_SHORT, LD_OPTION_TYPE_LONG };

struct ld_option {

    const char *name;
    
    enum ld_option_type type;
    int idx, flgs;

};

#define     LD_OPTION_NO_ARG            0
#define     LD_OPTION_HAS_ARG           1

unsigned long array_to_integer (unsigned char *arr, int size);
unsigned long byte_array_to_integer (unsigned char *arr, int size, int big_endian);

void integer_to_array (unsigned long value, unsigned char *dest, int size);
void integer_to_byte_array (unsigned long value, unsigned char *dest, int size, int big_endian);

int xstrcasecmp (const char *__s1, const char *__s2);

int strstart (const char *val, const char **str);
void dynarray_add (void *ptab, long *nb_ptr, void *data);

char *xstrdup (const char *__p);
char *xstrndup (const char *__p, unsigned long __size);

void parse_args (int argc, char **argv, int optind);
void strip_trailing_spaces (char *__p);

void *xmalloc (unsigned long __size);
void *xrealloc (void *__ptr, unsigned long __size);

#endif      /* _LIB_H */
