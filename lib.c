/******************************************************************************
 * @file            lib.c
 *****************************************************************************/
#include    <ctype.h>
#include    <errno.h>
#include    <limits.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "ld.h"
#include    "lib.h"
#include    "pe.h"
#include    "report.h"

struct options_with_use {

    int (*check_option) (const char *cmd_arg, int argc, char **argv, int *optind, const char **optarg);
    void (*use_option) (const char *cmd_arg, int idx, const char *optarg);

};

static struct options_with_use fmt_tbl[] = {

    {   0,                      0               },
    {   0,                      0               },
    {   0,                      0               },
    {   0,                      0               },
    {   0,                      0               },
    {   &pe_check_option,       &pe_use_option  }

};

#define     LD_OPTION_IGNORED                               0
#define     LD_OPTION_EMIT_RELOCS                           1
#define     LD_OPTION_ENTRY                                 2
#define     LD_OPTION_FORMAT                                3
#define     LD_OPTION_GENERATE_SYMBOLS_TABLE                4
#define     LD_OPTION_HELP                                  5
#define     LD_OPTION_IMAGE_BASE                            6
#define     LD_OPTION_MAP                                   7
#define     LD_OPTION_MAP_FILE                              8
#define     LD_OPTION_OUTFILE                               9

static struct ld_option opts[] = {

    {   "-M",                           LD_OPTION_MAP,                          LD_OPTION_NO_ARG    },
    {   "-Map",                         LD_OPTION_MAP_FILE,                     LD_OPTION_HAS_ARG   },
    {   "-N",                           LD_OPTION_IGNORED,                      LD_OPTION_NO_ARG    },
    
    {   "-e",                           LD_OPTION_ENTRY,                        LD_OPTION_HAS_ARG   },
    {   "-o",                           LD_OPTION_OUTFILE,                      LD_OPTION_HAS_ARG   },
    {   "-s",                           LD_OPTION_IGNORED,                      LD_OPTION_NO_ARG    },
    {   "-q",                           LD_OPTION_EMIT_RELOCS,                  LD_OPTION_NO_ARG    },
    
    
    {   "--emit-relocs",                LD_OPTION_EMIT_RELOCS,                  LD_OPTION_NO_ARG    },
    {   "--entry",                      LD_OPTION_ENTRY,                        LD_OPTION_HAS_ARG   },
    {   "--help",                       LD_OPTION_HELP,                         LD_OPTION_NO_ARG    },
    {   "--image-base",                 LD_OPTION_IMAGE_BASE,                   LD_OPTION_HAS_ARG   },
    {   "--oformat",                    LD_OPTION_FORMAT,                       LD_OPTION_HAS_ARG   },
    {   "--omagic",                     LD_OPTION_IGNORED,                      LD_OPTION_NO_ARG    },
    {   "--output",                     LD_OPTION_OUTFILE,                      LD_OPTION_HAS_ARG   },
    {   "--print-map",                  LD_OPTION_MAP,                          LD_OPTION_NO_ARG    },
    {   "--strip-all",                  LD_OPTION_IGNORED,                      LD_OPTION_NO_ARG    },
    
    
    {   "--generate-symbols-table",     LD_OPTION_GENERATE_SYMBOLS_TABLE,       LD_OPTION_NO_ARG    },
    {   0,                              0,                                      0                   }

};


static void print_usage (void) {

    if (program_name) {
    
        fprintf (stderr, "Usage: %s [options] file...\n\n", program_name);
        fprintf (stderr, "Options:\n\n");
        
        fprintf (stderr, "    -e ADDRESS, --entry ADDRESS       Set start address.\n");
        fprintf (stderr, "    -q, --emit-relocs                 Generate relocations in final output.\n");
        fprintf (stderr, "    -s, --strip-all                   Ignored.\n");
        
        fprintf (stderr, "\n");
        
        fprintf (stderr, "    -M, --print-map                   Print map file on standard output.\n");
        fprintf (stderr, "    -N, --omagic                      Ignored.\n");
        
        fprintf (stderr, "\n");
        fprintf (stderr, "    -Map FILE                         Write a linker map to FILE.\n");
        
        fprintf (stderr, "\n");
        
        fprintf (stderr, "    --generate-symbols-table          Generate a symbols table from global symbols.\n");
        fprintf (stderr, "    --help                            Print option help.\n");
        fprintf (stderr, "    --oformat FORMAT                  Specify the format of output file (default msdos)\n");
        fprintf (stderr, "                                          Supported formats are:\n");
        fprintf (stderr, "                                              a.out-i386, elks-ia16, elks-i386, pe-i386\n");
        fprintf (stderr, "                                              binary, msdos\n");
        fprintf (stderr, "    --image-base <address>            Set base address of the executable.\n");
        
        fprintf (stderr, "\n");
        pe_print_help ();
        fprintf (stderr, "\n");
    
    }

}

static void use_option (const char *cmd_arg, int idx, const char *optarg) {

    switch (idx) {
    
        case LD_OPTION_IGNORED: {
        
            break;
        
        }
        
        case LD_OPTION_EMIT_RELOCS: {
        
            state->emit_relocs = 1;
            break;
        
        }
        
        case LD_OPTION_ENTRY: {
        
            char *p;
            state->entry_point = strtoul (optarg, &p, 0);
            
            if (p == optarg + strlen (optarg)) {
                state->entry_symbol_name = "";
            } else {
            
                state->entry_point = 0;
                state->entry_symbol_name = optarg;
            
            }
            
            break;
        
        }
        
        case LD_OPTION_FORMAT: {
        
            if (xstrcasecmp (optarg, "binary") == 0) {
            
                state->format = LD_FORMAT_BIN;
                break;
            
            }
            
            if (xstrcasecmp (optarg, "msdos") == 0) {
            
                state->format = LD_FORMAT_COM;
                break;
            
            }
            
            if (xstrcasecmp (optarg, "elks-ia16") == 0) {
            
                state->format = LD_FORMAT_IA16_ELKS;
                break;
            
            }
            
            if (xstrcasecmp (optarg, "elks-i386") == 0) {
            
                state->format = LD_FORMAT_I386_ELKS;
                break;
            
            }
            
            if (xstrcasecmp (optarg, "a.out-i386") == 0) {
            
                state->format = LD_FORMAT_I386_AOUT;
                break;
            
            }
            
            if (xstrcasecmp (optarg, "pe-i386") == 0) {
            
                state->format = LD_FORMAT_I386_PE;
                break;
            
            }
            
            report_at (program_name, 0, REPORT_ERROR, "unrecognised output format '%s'", optarg);
            exit (EXIT_FAILURE);
        
        }
        
        case LD_OPTION_GENERATE_SYMBOLS_TABLE: {
        
            state->generate_symbols_table = 1;
            break;
        
        }
        
        case LD_OPTION_HELP: {
        
            print_usage ();
            exit (EXIT_SUCCESS);
        
        }
        
        case LD_OPTION_IMAGE_BASE: {
        
            long conversion;
            char *temp;
            
            errno = 0;
            conversion = strtol (optarg, &temp, 0);
            
            if (!*optarg || isspace ((int) *optarg) || errno || *temp) {
            
                report_at (program_name, 0, REPORT_ERROR, "bad number for base address");
                exit (EXIT_FAILURE);
            
            }
            
            state->base_address = (unsigned long) conversion;
            state->use_custom_base_address = 1;
            
            break;
        
        }
        
        case LD_OPTION_MAP: {
        
            state->output_map_filename = "";
            break;
        
        }
        
        case LD_OPTION_MAP_FILE: {
        
            state->output_map_filename = optarg;
            break;
        
        }
        
        case LD_OPTION_OUTFILE: {
        
            if (state->output_filename) {
            
                report_at (program_name, 0, REPORT_ERROR, "multiple output files provided");
                exit (EXIT_FAILURE);
            
            }
            
            state->output_filename = optarg;
            break;
        
        }
        
        default: {
        
            report_at (program_name, 0, REPORT_ERROR, "unsupported option '%s'", cmd_arg);
            exit (EXIT_FAILURE);
        
        }
    
    }

}

unsigned long array_to_integer (unsigned char *arr, int size) {

    unsigned long value = 0;
    int i;
    
    for (i = 0; i < size; i++) {
        value |= arr[i] << (CHAR_BIT * i);
    }
    
    return value;

}

unsigned long byte_array_to_integer (unsigned char *arr, int size, int big_endian) {

    if (big_endian) {
    
        unsigned long value = 0;
        int i, j;
        
        for (i = size, j = 0; i > 0; i--, j++) {
            value |= arr[j] << (CHAR_BIT * (i - 1));
        }
        
        return value;
    
    }
    
    return array_to_integer (arr, size);

}

void integer_to_array (unsigned long value, unsigned char *dest, int size) {

    int i;
    
    for (i = 0; i < size; i++) {
        dest[i] = (value >> (CHAR_BIT * i)) & UCHAR_MAX;
    }

}

char *xstrdup (const char *__p) {

    char *p = xmalloc (strlen (__p) + 1);
    
    strcpy (p, __p);
    return p;

}

char *xstrndup (const char *__p, unsigned long __size) {

    char *p = xmalloc (__size + 1);
    
    memcpy (p, __p, __size);
    return p;

}

int xstrcasecmp (const char *__s1, const char *__s2) {

    const unsigned char *p1 = (const unsigned char *) __s1;
    const unsigned char *p2 = (const unsigned char *) __s2;
    
    while (*p1 != '\0') {
    
        if (tolower ((int) *p1) < tolower ((int) *p2)) {
            return (-1);
        } else if (tolower ((int) *p1) > tolower ((int) *p2)) {
            return (1);
        }
        
        p1++;
        p2++;
    
    }
    
    if (*p2 == '\0') {
        return (0);
    }
    
    return (-1);

}

int strstart (const char *val, const char **str) {

    const char *p = *str;
    const char *q = val;
    
    while (*q != '\0') {
    
        if (*p != *q) {
            return 0;
        }
        
        ++p;
        ++q;
    
    }
    
    *str = p;
    return 1;

}

void dynarray_add (void *ptab, long *nb_ptr, void *data) {

    long nb, nb_alloc;
    void **pp;
    
    nb = *nb_ptr;
    pp = *(void ***) ptab;
    
    if ((nb & (nb - 1)) == 0) {
    
        if (!nb) {
            nb_alloc = 1;
        } else {
            nb_alloc = nb * 2;
        }
        
        pp = xrealloc (pp, nb_alloc * sizeof (void *));
        *(void ***) ptab = pp;
    
    }
    
    pp[nb++] = data;
    *nb_ptr = nb;

}

void parse_args (int argc, char **argv, int optind) {

    struct options_with_use *options_with_use;
    struct ld_option *popt;
    
    const char *optarg, *r;
    
    if (argc <= optind) {
    
        print_usage ();
        exit (EXIT_SUCCESS);
    
    }
    
    while (optind < argc) {
    
        r = argv[optind++];
        
        if (r[0] != '-' || r[1] == '\0') {
        
            dynarray_add (&state->input_files, &state->nb_input_files, xstrdup (r));
            continue;
        
        }
        
        for (popt = opts; ; popt++) {
        
            const char *p1 = popt->name;
            const char *r1 = r;
            
            if (!p1) {
                break;    
            }
            
            if (!strstart (p1, &r1)) {
                continue;
            }
            
            optarg = r1;
            
            if (popt->flgs & LD_OPTION_HAS_ARG) {
            
                if (*r1 == '\0') {
                
                    if (optind >= argc) {
                    
                        report_at (program_name, 0, REPORT_ERROR, "argument to '%s' is missing", r);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    optarg = argv[optind++];
                
                }
            
            } else if (*r1 != '\0') {
                continue;
            }
            
            break;
        
        }
        
        if (popt && popt->name) {
        
            use_option (r, popt->idx, optarg);
            continue;
        
        }
        
        options_with_use = &fmt_tbl[state->format];
        
        if (options_with_use->check_option && options_with_use->use_option) {
        
            int idx;
            
            if ((idx = options_with_use->check_option (r, argc, argv, &optind, &optarg)) >= 0) {
            
                options_with_use->use_option (r, idx, optarg);
                continue;
            
            }
        
        }
        
        report_at (program_name, 0, REPORT_ERROR, "invalid option -- '%s'", r);
        exit (EXIT_FAILURE);
    
    }

}

void strip_trailing_spaces (char *__p) {

    char *p = __p + strlen (__p);
    
    while (p > __p && p[-1] == ' ') {
        *--p = '\0';
    }

}

void *xmalloc (unsigned long __size) {

    void *ptr = malloc (__size);
    
    if (!ptr && __size) {
    
        report_at (program_name, 0, REPORT_ERROR, "memory full (malloc)");
        exit (EXIT_FAILURE);
    
    }
    
    memset (ptr, 0, __size);
    return ptr;

}

void *xrealloc (void *__ptr, unsigned long __size) {

    void *ptr = realloc (__ptr, __size);
    
    if (!ptr && __size) {
    
        report_at (program_name, 0, REPORT_ERROR, "memory full (realloc)");
        exit (EXIT_FAILURE);
    
    }
    
    return ptr;

}
