/******************************************************************************
 * @file            lib.h
 *****************************************************************************/
#ifndef     _LIB_H
#define     _LIB_H

int xstrcasecmp (const char *__s1, const char *__s2);

int strstart (const char *val, const char **str);
void dynarray_add (void *ptab, long *nb_ptr, void *data);

char *xstrdup (const char *__p);
void parse_args (int argc, char **argv, int optind);

void *xmalloc (unsigned long __size);
void *xrealloc (void *__ptr, unsigned long __size);

#endif      /* _LIB_H */
