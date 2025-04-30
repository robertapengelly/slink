/******************************************************************************
 * @file            omf.c
 *****************************************************************************/
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#include    "ld.h"
#include    "lib.h"
#include    "omf.h"
#include    "reloc.h"
#include    "report.h"
#include    "section.h"
#include    "symbol.h"

static void estimate (void *data, unsigned long data_size, const char *filename, unsigned long *num_segments_p, unsigned long *num_extdefs_p, unsigned long *num_pubdefs_p, unsigned long *num_lnames_p) {

    unsigned char *pos = (unsigned char *) data;
    unsigned char base_segment_index;
    
    unsigned char record_type;
    unsigned short record_len;
    
    unsigned char *pubdef_name, *pubdef_name_end;
    unsigned char pubdef_name_len;
    
    unsigned char *extdef_name, *extdef_name_end;
    unsigned char extdef_name_len;
    
    unsigned char *lname, *lname_end;
    unsigned char lname_len;
    
    unsigned long num_segments = 0, num_extdefs = 0, num_pubdefs = 0, num_lnames = 0;
    int big_fields;
    
    while (pos < (unsigned char *) data + data_size) {
    
        record_type = pos[0];
        
        big_fields = record_type & 1;
        record_type &= ~1;
        
        record_len = array_to_integer (pos + 1, 2);
        
        {
        
            unsigned char checksum = 0;
            unsigned long i;
            
            for (i = 0; i < (unsigned long) record_len + 3; i++) {
                checksum += pos[i];
            }
            
            if (checksum != 0) {
                report_at (program_name, 0, REPORT_WARNING, "%s: invalid checksum", filename);
            }
        
        }
        
        pos += 3;
        
        if (record_type == RECORD_TYPE_EXTDEF) {
        
            extdef_name_end = (extdef_name = pos) + record_len - 1;
            
            while (extdef_name != extdef_name_end) {
            
                extdef_name_len = extdef_name[0];
                
                if (extdef_name + 1 + extdef_name_len + 1 > extdef_name_end) {
                
                    report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: incorrect extdef string length", filename);
                    exit (EXIT_FAILURE);
                
                }
                
                num_extdefs++;
                extdef_name = extdef_name + 1 + extdef_name_len + 1;
            
            }
        
        } else if (record_type == RECORD_TYPE_PUBDEF) {
        
            unsigned long prefix = 1;
            unsigned long suffix = 2 + 1;
            
            pubdef_name_end = pos + record_len - 1;
            
            if (big_fields) {
                suffix += 2;
            }
            
            base_segment_index = pos[1];
            
            if (!base_segment_index) {
            
                report_at (program_name, 0, REPORT_WARNING, "%s: PUBDEF Base Frame is not supported", filename);
                prefix += 2;
            
            }
            
            pubdef_name = pos + 2;
            
            while (pubdef_name != pubdef_name_end) {
            
                pubdef_name_len = pubdef_name[prefix - 1];
                
                if (pubdef_name + prefix + pubdef_name_len + suffix > pubdef_name_end) {
                
                    report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: incorrect pubdef string length", filename);
                    exit (EXIT_FAILURE);
                
                }
                
                num_pubdefs++;
                pubdef_name = pubdef_name + prefix + pubdef_name_len + suffix;
            
            }
        
        } else if (record_type == RECORD_TYPE_LNAMES) {
        
            lname_end = (lname = pos) + record_len - 1;
            
            while (lname != lname_end) {
            
                lname_len = lname[0];
                
                if (lname + 1 + lname_len > lname_end) {
                
                    report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: incorrect lname string length", filename);
                    exit (EXIT_FAILURE);
                
                }
                
                num_lnames++;
                lname = lname + 1 + lname_len;
            
            }
        
        } else if (record_type == RECORD_TYPE_SEGDEF) {
            num_segments++;
        }
        
        pos += record_len;
    
    }
    
    *num_segments_p = num_segments;
    *num_extdefs_p = num_extdefs;
    *num_pubdefs_p = num_pubdefs;
    *num_lnames_p = num_lnames;

}


void read_omf_object (const char *filename, unsigned char *data, unsigned long data_size) {

    unsigned char *pos = (unsigned char *) data;
    
    unsigned char base_segment_index;
    unsigned short public_offset;
    
    struct {
    
        struct section_part *part;
        unsigned long offset, size;
    
    } prev_ledata = { 0 };
    
    char **lnames;
    int big_fields;
    
    unsigned char record_type;
    unsigned short record_len;
    
    unsigned char *pubdef_name, *pubdef_name_end;
    unsigned char pubdef_name_len;
    
    unsigned char *extdef_name, *extdef_name_end;
    unsigned char extdef_name_len;
    
    unsigned char *lname, *lname_end;
    unsigned char lname_len;
    
    unsigned long num_segments, num_extdefs, num_pubdefs, num_lnames;
    unsigned long i_segments, i_extdefs, i_pubdefs, i_lnames;
    
    struct section_part **part_p_array, *part;
    struct section *section;
    
    struct object_file *of;
    struct symbol *symbol;
    
    estimate (data, data_size, filename, &num_segments, &num_extdefs, &num_pubdefs, &num_lnames);
    
    num_lnames++;
    num_segments++;
    
    i_lnames = 1;
    i_segments = 1;
    i_pubdefs = num_segments;
    i_extdefs = i_pubdefs + num_pubdefs;
    
    lnames = xmalloc (num_lnames * sizeof (*lnames));
    
    part_p_array = xmalloc (sizeof (*part_p_array) * num_segments);
    of = object_file_make (filename, num_segments + num_pubdefs + num_extdefs);
    
    while (pos < (unsigned char *) data + data_size) {
    
        record_type = pos[0];
        
        big_fields = record_type & 1;
        record_type &= ~1;
        
        record_len = array_to_integer (pos + 1, 2);
        pos += 3;
        
        if (record_type == RECORD_TYPE_THEADR) {
        
            unsigned char string_length = pos[0];
            
            if (string_length > record_len - 2) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: incorrect string length", filename);
                exit (EXIT_FAILURE);
            
            }
        
        } else if (record_type == RECORD_TYPE_COMENT) {
            /* Nothing needs to be done. */
        } else if (record_type == RECORD_TYPE_MODEND) {
        
            if (pos + record_len != data + data_size) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: MODEND record is not the last record", filename);
                exit (EXIT_FAILURE);
            
            }
        
        } else if (record_type == RECORD_TYPE_EXTDEF) {
        
            extdef_name_end = (extdef_name = pos) + record_len - 1;
            
            while (extdef_name != extdef_name_end) {
            
                extdef_name_len = extdef_name[0];
                
                symbol = of->symbol_arr + i_extdefs;
                i_extdefs++;
                
                symbol->name = xstrndup ((char *) extdef_name + 1, extdef_name_len);
                symbol->value = 0;
                symbol->part = 0;
                symbol->section_number = UNDEFINED_SECTION_NUMBER;
                
                symbol_record_external_symbol (symbol);
                extdef_name = extdef_name + 1 + extdef_name_len + 1;
            
            }
        
        } else if (record_type == RECORD_TYPE_PUBDEF) {
        
            unsigned long prefix = 1;
            unsigned long suffix = 2 + 1;
            
            pubdef_name_end = pos + record_len - 1;
            
            if (big_fields) {
                suffix += 2;
            }
            
            base_segment_index = pos[1];
            
            if (!base_segment_index) {
            
                report_at (program_name, 0, REPORT_WARNING, "%s: PUBDEF Base Frame is not supported", filename);
                prefix += 2;
            
            }
            
            pubdef_name = pos + 2;
            
            while (pubdef_name != pubdef_name_end) {
            
                pubdef_name_len = pubdef_name[prefix - 1];
                
                if (big_fields) {
                    public_offset = array_to_integer (pubdef_name + prefix + pubdef_name_len, 4);
                } else {
                    public_offset = array_to_integer (pubdef_name + prefix + pubdef_name_len, 2);
                }
                
                symbol = of->symbol_arr + i_pubdefs++;
                
                symbol->name = xstrndup ((char *) pubdef_name + prefix, pubdef_name_len);
                symbol->value = public_offset;
                symbol->part = part_p_array[base_segment_index];
                symbol->section_number = base_segment_index;
                
                symbol_record_external_symbol (symbol);
                pubdef_name = pubdef_name + prefix + pubdef_name_len + suffix;
            
            }
        
        } else if (record_type == RECORD_TYPE_LNAMES) {
        
            lname_end = (lname = pos) + record_len - 1;
            
            while (lname != lname_end) {
            
                lname_len = lname[0];
                
                lnames[i_lnames++] = xstrndup ((char *) lname + 1, lname_len);
                lname = lname + 1 + lname_len;
            
            }
        
        } else if (record_type == RECORD_TYPE_SEGDEF) {
        
            unsigned char attributes = pos[0];
            
            unsigned short segment_name_index;
            unsigned short class_name_index;
            
            unsigned long segment_len;
            
            if ((attributes >> 5) == 0) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: OMF absolute segments are not supported", filename);
                exit (EXIT_FAILURE);
            
            }
            
            if (big_fields) {
            
                segment_len = array_to_integer (pos + 1, 4);
                
                segment_name_index = pos[5];
                class_name_index = pos[6];
            
            } else {
            
                segment_len = array_to_integer (pos + 1, 2);
                
                segment_name_index = pos[3];
                class_name_index = pos[4];
            
            }
            
            if (segment_name_index >= i_lnames || !segment_name_index) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid segment name index", filename);
                exit (EXIT_FAILURE);
            
            }
            
            if (class_name_index >= i_lnames || !class_name_index) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid class name index", filename);
                exit (EXIT_FAILURE);
            
            }
            
            section = section_find_or_make (lnames[segment_name_index]);
            
            if (strcmp (lnames[class_name_index], "CODE") == 0) {
                section->flags = SECTION_FLAG_ALLOC | SECTION_FLAG_LOAD | SECTION_FLAG_READONLY | SECTION_FLAG_CODE;
            } else if (strcmp (lnames[class_name_index], "DATA") == 0) {
                section->flags = SECTION_FLAG_ALLOC | SECTION_FLAG_LOAD | SECTION_FLAG_DATA;
            } else {
                section->flags = SECTION_FLAG_ALLOC | SECTION_FLAG_LOAD | SECTION_FLAG_DATA;
            }
            
            part = section_part_new (section, of);
            
            switch (attributes >> 5) {
            
                case 1:
                
                    part->alignment = 1;
                    break;
                
                case 2:
                
                    part->alignment = 2;
                    break;
                
                case 3:
                
                    part->alignment = 16;
                    break;
                
                case 4:
                
                    part->alignment = 4096;
                    break;
                
                case 5:
                
                    part->alignment = 4;
                    break;
                
                default:
                
                    report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid segment alignment", filename);
                    exit (EXIT_FAILURE);
            
            }
            
            part->content = xmalloc (part->content_size = segment_len);
            symbol = of->symbol_arr + i_segments;
            
            symbol->name = xstrdup (section->name);
            symbol->flags = SYMBOL_FLAG_SECTION_SYMBOL;
            symbol->value = 0;
            symbol->size = 0;
            symbol->part = part;
            symbol->section_number = i_segments;
            
            section_append_section_part (section, part);
            part_p_array[i_segments++] = part;
        
        } else if (record_type == RECORD_TYPE_GRPDEF) {
            /* Nothing needs to be done. */
        } else if (record_type == RECORD_TYPE_FIXUPP) {
        
            struct section_part *part = prev_ledata.part;
            
            unsigned char *subrec = pos;
            unsigned char *end = pos + record_len - 1;
            
            if (!part) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: FIXUPP record has no preceding LEDATA record", filename);
                exit (EXIT_FAILURE);
            
            }
            
            while (subrec != end) {
            
                if (subrec[0] & 0x80) {
                
                    struct reloc_entry *reloc;
                    unsigned long old_reloc_count;
                    
                    unsigned char fixdat, frame_method, target_method;
                    unsigned short data_record_offset, target_datum;
                    
                    unsigned char loc;
                    int bits;
                    
                    /*seg_reloc = subrec[0] & 0x40;*/
                    loc = subrec[0] >> 2;
                    
                    if ((loc & 0x0F) == 1) {
                        bits = 16;
                    } else if ((loc & 0x0F) == 9) {
                        bits = 32;
                    } else {
                    
                        report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: only 16-bit/32-bit offset OMF fixups are supported", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    data_record_offset = ((unsigned short) (subrec[0] & 0x03)) << 8;
                    data_record_offset |= subrec[1];
                    
                    if (data_record_offset >= prev_ledata.size) {
                    
                        report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid data record", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    fixdat = subrec[2];
                    
                    if (fixdat & 0x80) {
                    
                        report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: only explicit frame methods in OMF fixups are supported", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    if (fixdat & 0x08) {
                    
                        report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: only explicit targets methods in OMF fixups are supported", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    if (!(fixdat & 0x04)) {
                    
                        report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: displacement fields in OMF fixups are supported", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    frame_method = (fixdat & 0x70) >> 4;
                    
                    target_method = fixdat & 0x03;
                    target_datum = subrec[3];
                    
                    if (frame_method != METHOD_F5) {
                        
                        report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: only F5 frame methods in OMF fixups are supported", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    if (target_method != METHOD_T2_EXTDEF) {
                        
                        report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: only T2 target methods in OMF fixups are supported", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    old_reloc_count = part->reloc_cnt;
                    part->reloc_cnt += 1;
                    
                    part->reloc_arr = xrealloc (part->reloc_arr, part->reloc_cnt * sizeof (*part->reloc_arr));
                    memset (part->reloc_arr + old_reloc_count, 0, (part->reloc_cnt - old_reloc_count) * sizeof *part->reloc_arr);
                    
                    reloc = part->reloc_arr + old_reloc_count;
                    
                    if (target_method == METHOD_T2_EXTDEF) {
                    
                        if (target_datum > num_extdefs || !target_datum) {
                        
                            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid target datum", filename);
                            exit (EXIT_FAILURE);
                        
                        }
                        
                        reloc->symbol = of->symbol_arr + num_segments + num_pubdefs + target_datum - 1;
                    
                    }
                    
                    reloc->offset = data_record_offset;
                    reloc->addend = 0;
                    
                    if (bits == 16) {
                        reloc->howto = &reloc_howtos[RELOC_TYPE_PC16];
                    } else {
                        reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                    }
                    
                    subrec += 4;
                
                } else {
                
                    report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: THREAD subrecords are not yet supported", filename);
                    exit (EXIT_FAILURE);
                
                }
            
            }
        
        } else if (record_type == RECORD_TYPE_LEDATA) {
        
            unsigned char seg_index = pos[0];
            
            unsigned char *data_bytes;
            unsigned short size;
            
            unsigned long offset;
            
            if (big_fields) {
            
                offset = array_to_integer (pos + 1, 4);
                
                size = record_len - 6;
                data_bytes = pos + 5;
            
            } else {
            
                offset = array_to_integer (pos + 1, 2);
                
                size = record_len - 4;
                data_bytes = pos + 3;
            
            }
            
            if (seg_index >= i_segments || !seg_index) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid seg index", filename);
                exit (EXIT_FAILURE);
            
            }
            
            part = part_p_array[seg_index];
            
            if (offset + size > part->content_size) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid LEDATA offset and size combination for segment", filename);
                exit (EXIT_FAILURE);
            
            }
            
            memcpy (part->content + offset, data_bytes, size);
            
            prev_ledata.part = part;
            prev_ledata.offset = offset;
            prev_ledata.size = size;
        
        } else {
        
            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: not yet supported record type %#x", filename, record_type | big_fields);
            exit (EXIT_FAILURE);
        
        }
        
        pos += record_len;
    
    }
    
    for (i_lnames = 0; i_lnames < num_lnames; i_lnames++) {
        free (lnames[i_lnames]);
    }
    
    free (lnames);
    free (part_p_array);

}
