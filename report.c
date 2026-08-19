/******************************************************************************
 * @file            report.c
 *****************************************************************************/
#include    <stdarg.h>
#include    <stdio.h>
#include    <string.h>

#include    "report.h"
unsigned int errors = 0;

#if     defined (unix) || defined (__unix) || defined (__unix__) || defined (__APPLE__)
static void reset_console_color (void) {
    fprintf (stderr, "\033[0m");
}

static void set_console_color (int color) {
    fprintf (stderr, "\033[%dm", color);
}
#elif   defined (_WIN32)
# include   <windows.h>
static int OriginalConsoleColor = -1;

static void reset_console_color (void) {

    HANDLE hStdError = GetStdHandle (STD_ERROR_HANDLE);
    
    if (OriginalConsoleColor == -1) { return; }
    
    SetConsoleTextAttribute (hStdError, OriginalConsoleColor);
    OriginalConsoleColor = -1;

}

static void set_console_color (int color) {

    HANDLE hStdError = GetStdHandle (STD_ERROR_HANDLE);
    WORD wColor;
    
    if (OriginalConsoleColor == -1) {
    
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        
        if (!GetConsoleScreenBufferInfo (hStdError, &csbi)) {
            return;
        }
        
        OriginalConsoleColor = csbi.wAttributes;
    
    }
    
    wColor = (OriginalConsoleColor & 0xF0) + (color & 0xF);
    SetConsoleTextAttribute (hStdError, wColor);

}
#endif

static void output_message (const char *filename, unsigned int lineno, unsigned int idx, int type, const char *fmt, va_list ap) {

    if (filename) {
    
        if (lineno == 0) {
            fprintf (stderr, "%s: ", filename);
        } else {
            fprintf (stderr, "%s:", filename);
        }
    
    }
    
    if (lineno > 0) {
    
        if (idx == 0) {
            fprintf (stderr, "%u: ", lineno);
        } else {
            fprintf (stderr, "%u:", lineno);
        }
    
    }
    
    if (idx > 0) {
        fprintf (stderr, "%u: ", idx);
    }
    
    if (type == REPORT_ERROR || type == REPORT_FATAL_ERROR) {
    
#if     defined (unix) || defined (__unix) || defined (__unix__) || defined (__APPLE__) || defined (_WIN32)
        set_console_color (COLOR_ERROR);
#endif
        
        if (type == REPORT_ERROR) {
            fprintf (stderr, "error:");
        } else {
            fprintf (stderr, "fatal error:");
        }
    
    } else if (type == REPORT_INTERNAL_ERROR) {
    
#if     defined (unix) || defined (__unix) || defined (__unix__) || defined (__APPLE__) || defined (_WIN32)
        set_console_color (COLOR_INTERNAL_ERROR);
#endif
        
        fprintf (stderr, "internal error:");
    
    } else if (type == REPORT_WARNING) {
    
#if     defined (unix) || defined (__unix) || defined (__unix__) || defined (__APPLE__) || defined (_WIN32)
        set_console_color (COLOR_WARNING);
#endif
        
        fprintf (stderr, "warning:");
    
    }
    
#if     defined (unix) || defined (__unix) || defined (__unix__) || defined (__APPLE__) || defined (_WIN32)
    reset_console_color ();
#endif
    
    fprintf (stderr, " ");
    vfprintf (stderr, fmt, ap);
    fprintf (stderr, "\n");
    
    if (type != REPORT_WARNING) {
        ++errors;
    }

}

unsigned int get_error_count (void) {
    return errors;
}

void report_at (const char *filename, unsigned int lineno, int type, const char *fmt, ...) {

    va_list ap;
    
    va_start (ap, fmt);
    output_message (filename, lineno, 0, type, fmt, ap);
    va_end (ap);

}
