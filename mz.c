/******************************************************************************
 * @file            mz.c
 *****************************************************************************/
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "ld.h"
#include    "lib.h"
#include    "mz.h"
#include    "report.h"
#include    "section.h"
#include    "symbol.h"
#include    "write7x.h"

static unsigned long section_get_num_relocs (struct section *section) {

    unsigned long num_relocs = 0, i;
    
    struct section_part *part;
    struct reloc_howto *howto;
    
    for (part = section->first_part; part; part = part->next) {
    
        for (i = 0; i < part->reloc_cnt; i++) {
        
            howto = part->reloc_arr[i].howto;
            
            if (howto == &reloc_howtos[RELOC_TYPE_32] || howto == &reloc_howtos[RELOC_TYPE_16] || howto == &reloc_howtos[RELOC_TYPE_8]) {
                num_relocs++;
            }
        
        }
    
    }
    
    return num_relocs;

}

static unsigned char *write_relocs_for_section (unsigned char *pos, struct section *section) {

    struct section_part *part;
    unsigned long i, addr;
    
    for (part = section->first_part; part; part = part->next) {
        
        for (i = 0; i < part->reloc_cnt; i++) {
        
            if (part->reloc_arr[i].howto == &reloc_howtos[RELOC_TYPE_8] || part->reloc_arr[i].howto == &reloc_howtos[RELOC_TYPE_16] || part->reloc_arr[i].howto == &reloc_howtos[RELOC_TYPE_32]) {
            
                addr = part->rva + part->reloc_arr[i].offset;
                
                integer_to_array (addr % 65536, pos, 2);
                pos += 2;
                
                integer_to_array (addr / 65536, pos, 2);
                pos += 2;
            
            }
        
        }
    
    }
    
    return pos;

}

void mz_write (const char *filename) {

    FILE *fp;
    
    unsigned long data_size = 0;
    unsigned char *data, *pos;
    
    struct section *text_section, *data_section, *bss_section;
    unsigned long header_size;
    
    unsigned long reloc_size = 0, reloc_count = 0;
    unsigned long ibss_addr = 0, ibss_size = 0;
    unsigned long stack_addr = 0, stack_size = 0;
    
    struct mz_exec exec;
    memset (&exec, 0, sizeof (exec));
    
    if (!(fp = fopen (filename, "wb"))) {
    
        report_at (program_name, 0, REPORT_ERROR, "failed to open '%s' for writing", filename);
        return;
    
    }
    
    text_section = section_find (".text");
    data_section = section_find (".data");
    bss_section  = section_find (".bss");
    
    if (text_section) {
        reloc_count += section_get_num_relocs (text_section);
    }
    
    if (data_section) {
        reloc_count += section_get_num_relocs (data_section);
    }
    
    header_size = ALIGN (sizeof (exec), 16);
    reloc_size = ALIGN (reloc_count * 4, 16);
    
    data_size += header_size + reloc_size;
    
    if (data_section) {
    
        data_size += data_section->rva;;
        ibss_addr += data_section->rva;
        
        if (bss_section) {
        
            data_size += bss_section->rva - data_section->rva;
            ibss_addr += bss_section->rva - data_section->rva;
        
        } else {
        
            data_size += data_section->total_size;
            ibss_addr += data_section->total_size;
        
        }
    
    } else {
    
        if (bss_section) {
        
            data_size += bss_section->rva;
            ibss_addr += bss_section->rva;
        
        } else {
        
            data_size += text_section ? text_section->total_size : 0;
            ibss_addr += text_section ? text_section->total_size : 0;
        
        }
    
    }
    
    stack_addr = ibss_addr;
    
    if (bss_section) {
        ibss_size = bss_section->total_size;
    }
    
    /*stack_addr += ibss_size;*/
    stack_size = 0x1000;        /* Maybe get this from command line in the future. */
    
    exec.e_magic[0] = 'M';
    exec.e_magic[1] = 'Z';
    
    write721_to_byte_array (exec.e_cblp, ibss_addr % 512);
    write721_to_byte_array (exec.e_cp, ALIGN (ibss_addr, 512) / 512);
    
    write721_to_byte_array (exec.e_crlc, reloc_count);
    write721_to_byte_array (exec.e_cparhdr, (header_size + reloc_size) / 16);
    
    write721_to_byte_array (exec.e_minalloc, ALIGN (ibss_size + stack_size, 16) / 16);
    write721_to_byte_array (exec.e_maxalloc, 0xFFFF);
    
    write721_to_byte_array (exec.e_ss, stack_addr / 16);
    write721_to_byte_array (exec.e_sp, stack_addr % 16 + stack_size);
    
    write721_to_byte_array (exec.e_ip, state->entry_point % 16);
    write721_to_byte_array (exec.e_cs, state->entry_point / 16);
    
    write721_to_byte_array (exec.e_lfarlc, header_size);
    
    data = xmalloc (data_size);
    memcpy (data, &exec, sizeof (exec));
    
    pos = data + header_size;
    
    if (text_section) {
        pos = write_relocs_for_section (pos, text_section);
    }
    
    if (data_section) {
        pos = write_relocs_for_section (pos, data_section);
    }
    
    pos = data + header_size + reloc_size;
    
    if (text_section) {
    
        section_write (text_section, pos);
        pos += text_section->total_size;
    
    }
    
    if (data_section) {
        section_write (data_section, pos);
    }
    
    if (fwrite (data, data_size, 1, fp) != 1) {
        report_at (program_name, 0, REPORT_ERROR, "failed to write data to '%s'", filename);
    }
    
    free (data);
    fclose (fp);

}
