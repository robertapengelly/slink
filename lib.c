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
#include    "report.h"

#if     defined (_WIN32)
# define    PATHSEP                     ';'
#else
# define    PATHSEP                     ':'
#endif

struct ld_option {

    const char *name;
    int idx, flgs;

};

#define     LD_OPTION_NO_ARG            0
#define     LD_OPTION_HAS_ARG           1

#define     LD_OPTION_NONE              0
#define     LD_OPTION_ENTRY             1
#define     LD_OPTION_FORMAT            2
#define     LD_OPTION_HELP              3
#define     LD_OPTION_IMPURE            4
#define     LD_OPTION_MAP               5
#define     LD_OPTION_OUTFILE           6
#define     LD_OPTION_PSP               7

static struct ld_option opts[] = {

    {   "-N",           LD_OPTION_IMPURE,       LD_OPTION_NO_ARG    },
    {   "-T",           LD_OPTION_PSP,          LD_OPTION_HAS_ARG   },
    
    {   "-e",           LD_OPTION_ENTRY,        LD_OPTION_HAS_ARG   },
    {   "-o",           LD_OPTION_OUTFILE,      LD_OPTION_HAS_ARG   },
    
    {   "--oformat",    LD_OPTION_FORMAT,       LD_OPTION_HAS_ARG   },
    {   "--help",       LD_OPTION_HELP,         LD_OPTION_NO_ARG    },
    
    {   0,              0,                      0                   }

};


static void print_usage (void) {

    if (program_name) {
    
        fprintf (stderr, "Usage: %s [options] file...\n\n", program_name);
        fprintf (stderr, "Options:\n\n");
        
        fprintf (stderr, "    -N                    Do not page align data.\n");
        fprintf (stderr, "    -T OFFSET             Offset addresses by the specified offset.\n");
        
        fprintf (stderr, "    --oformat FORMAT      Specify the format of output file (default msdos)\n");
        fprintf (stderr, "                              Supported formats are:\n");
        fprintf (stderr, "                                  a.out-i386, elks-ia16, elks-i386,\n");
        fprintf (stderr, "                                  binary, msdos\n");
        
        fprintf (stderr, "    -e ADDRESS            Set start address.\n");
        fprintf (stderr, "    -s                    Ignored.\n");
        
        fprintf (stderr, "    -o FILE               Set output file name (default a.out).\n");
        fprintf (stderr, "    --help                Print this help information.\n");
        
        fprintf (stderr, "\n");
    
    }

}

char *xstrdup (const char *__p) {

    char *p = xmalloc (strlen (__p) + 1);
    
    strcpy (p, __p);
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

    struct ld_option *popt;
    const char *optarg, *r;
    
    if (argc <= optind) {
    
        print_usage ();
        exit (EXIT_SUCCESS);
    
    }
    
    while (optind < argc) {
    
        r = argv[optind++];
        
        if (r[0] != '-' || r[1] == '\0') {
        
            dynarray_add (&state->files, &state->nb_files, xstrdup (r));
            continue;
        
        }
        
        for (popt = opts; ; popt++) {
        
            const char *p1 = popt->name;
            const char *r1 = r;
            
            if (!p1) {
            
                report_at (program_name, 0, REPORT_ERROR, "invalid option -- '%s'", r);
                exit (EXIT_FAILURE);
            
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
        
        switch (popt->idx) {
        
            case LD_OPTION_ENTRY: {
            
                if (state->entry) {
                    free (state->entry);
                }
                
                state->entry = xstrdup (optarg);
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
                
                report_at (program_name, 0, REPORT_ERROR, "unrecognised output format '%s'", optarg);
                exit (EXIT_FAILURE);
            
            }
            
            case LD_OPTION_HELP: {
            
                print_usage ();
                exit (EXIT_SUCCESS);
            
            }
            
            case LD_OPTION_IMPURE: {
            
                state->impure = 1;
                break;
            
            }
            
            case LD_OPTION_OUTFILE: {
            
                if (state->ofile) {
                
                    report_at (program_name, 0, REPORT_ERROR, "multiple output files provided");
                    exit (EXIT_FAILURE);
                
                }
                
                state->ofile = xstrdup (optarg);
                break;
            
            }
            
            case LD_OPTION_PSP: {
            
                long conversion;
                char *temp;
                
                errno = 0;
                conversion = strtol (optarg, &temp, 0);
                
                if (!*optarg || isspace ((int) *optarg) || errno || *temp) {
                
                    report_at (program_name, 0, REPORT_ERROR, "bad number for text start");
                    exit (EXIT_FAILURE);
                
                }
                
                if (conversion < 0 || conversion > LONG_MAX) {
                
                    report_at (program_name, 0, REPORT_ERROR, "text start must be between 0 and %u", ULONG_MAX);
                    exit (EXIT_FAILURE);
                
                }
                
                state->psp = (unsigned long) conversion;
                break;
            
            }
            
            default: {
            
                report_at (program_name, 0, REPORT_ERROR, "unsupported option '%s'", r);
                exit (EXIT_FAILURE);
            
            }
        
        }
    
    }
    
    if (!state->ofile) { state->ofile = "a.out"; }

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
