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

#define     ALREADY_READ                "\0Already read"
#define     BLOCK_SIZE                  512

#define     IMP_PREFIX_STR              "__imp_"
#define     IMP_PREFIX_LEN              6

void read_omf_library (const char *filename, unsigned char *data) {

    unsigned char *pos = (unsigned char *) data;
    
    unsigned short record_len;
    unsigned short page_size;
    
    unsigned long dictionary_offset;
    unsigned short dictionary_num_blocks;
    
    int change;
    
    record_len = array_to_integer (pos + 1, 2, 0);
    pos += 3;
    
    if (record_len < 7) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: OMF Library Header length %u too short", filename, record_len);
        return;
    
    }
    
    page_size = record_len + 3;
    
    dictionary_offset = array_to_integer (pos, 4, 0);
    pos += 4;
    
    dictionary_num_blocks = array_to_integer (pos, 2, 0);
    pos += 2;
    
    if (dictionary_offset % BLOCK_SIZE) {
    
        report_at (program_name, 0, REPORT_ERROR, "%s: OMF Library Dictionary misaligned", filename);
        return;
    
    }
    
    pos = (unsigned char *) data + dictionary_offset;
    
    do {
    
        unsigned char *base;
        unsigned short block;
        
        change = 0;
        
        pos = (unsigned char *) data + dictionary_offset;
        base = pos;
        
        for (block = 0; block < dictionary_num_blocks; block++) {
        
            unsigned char *block_pos = base + block * BLOCK_SIZE;
            
            struct symbol *imp_symbol, *symbol;
            char *name, *p;
            
            unsigned long archive_name_len, member_name_len;
            int i;
            
            for (i = 0; i < 37; i++) {
            
                unsigned short page_number;
                char *new_filename;
                
                if (!block_pos[i]) {
                    continue;
                }
                
                pos = block_pos + block_pos[i] * 2;
                
                if (pos - block_pos + pos[0] > BLOCK_SIZE - 2) {
                
                    report_at (program_name, 0, REPORT_ERROR, "%s: OMF Library Dictionary invalid string length", filename);
                    return;
                
                }
                
                name = xmalloc (IMP_PREFIX_LEN + pos[0] + 1);
                
                memcpy (name, IMP_PREFIX_STR, IMP_PREFIX_LEN);
                memcpy (name + IMP_PREFIX_LEN, pos + 1, pos[0]);
                name[IMP_PREFIX_LEN + pos[0]] = '\0';
                
                imp_symbol = symbol_find (name);
                
                symbol = symbol_find (name + IMP_PREFIX_LEN);
                free (name);
                
                if ((imp_symbol == NULL || !symbol_is_undefined (imp_symbol)) && (symbol == NULL || !symbol_is_undefined (symbol))) {
                    continue;
                }
                
                page_number = array_to_integer (pos + 1 + pos[0], 2, 0);
                pos = (unsigned char *) data + page_number * page_size;
                
                if (pos >= base) {
                
                    report_at (program_name, 0, REPORT_ERROR, "%s: OMF Library member has invalid page number %u", filename, page_number);
                    return;
                
                }
                
                if (pos[0] != RECORD_TYPE_THEADR) {
                
                    if (pos[0] == '\0' && memcmp (pos, ALREADY_READ, sizeof (ALREADY_READ)) == 0) {
                        continue;
                    }
                    
                    report_at (program_name, 0, REPORT_ERROR, "%s: OMF Library member is not OMF object", filename);
                    return;
                
                }
                
                archive_name_len = strlen (filename);
                member_name_len = pos[3];
                
                new_filename = xmalloc (archive_name_len + 3 + 2 * sizeof (unsigned long) + 1 + member_name_len + 1 + 1);
                memcpy (new_filename, filename, archive_name_len);
                
                p = new_filename + archive_name_len;
                p += sprintf (p, "+%#lx", (unsigned long) (pos - data));
                
                *p = '(';
                
                memcpy (p + 1, pos + 4, member_name_len);
                p[1 + member_name_len] = ')';
                p[1 + member_name_len + 1] = '\0';
                
                change = 1;
                
                read_omf_object (new_filename, pos, base - pos);
                free (new_filename);
                
                memcpy (pos, ALREADY_READ, sizeof (ALREADY_READ));
            
            }
        
        }
    
    } while (change);

}

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
        
        record_len = array_to_integer (pos + 1, 2, 0);
        
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
        
        if (record_type == RECORD_TYPE_MODEND) {
            break;
        } else if (record_type == RECORD_TYPE_EXTDEF || record_type == RECORD_TYPE_LEXTDEF) {
        
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
        
        } else if (record_type == RECORD_TYPE_PUBDEF || record_type == RECORD_TYPE_LPUBDEF) {
        
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


static unsigned long unique_id = 0;

#define     LOCAL_SYMBOL_NAME_SUFFIX_FORMAT                 " (OMF symbol local to %s (unique id: %lu))"
#define     LOCAL_SYMBOL_NAME_SUFFIX_FORMAT_SIZE            (sizeof (LOCAL_SYMBOL_NAME_SUFFIX_FORMAT) + sizeof (unique_id) * 2)

void read_omf_object (const char *filename, unsigned char *data, unsigned long data_size) {

    unsigned char *pos = (unsigned char *) data;
    
    unsigned char base_segment_index;
    unsigned short public_offset;
    
    unsigned int offset32_loc = 0;
    unsigned char locat;
    
    char *local_name_suffix = 0;
    unsigned long local_name_suffix_size = 0;
    
    struct {
    
        struct section_part *part;
        unsigned long offset, size;
    
    } prev_ledata = { 0 };
    
    char **lnames = 0;
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
    
    struct section_part **part_p_array = 0, *part;
    struct section *section;
    
    struct object_file *of = 0;
    struct symbol *symbol;
    
    estimate (data, data_size, filename, &num_segments, &num_extdefs, &num_pubdefs, &num_lnames);
    
    if (!num_segments && !num_extdefs && !num_pubdefs && !num_lnames) {
        i_segments = i_extdefs = i_pubdefs = i_lnames = 0;
    } else {
        
        num_lnames++;
        
        lnames = xmalloc (num_lnames * sizeof (*lnames));
        i_lnames = 1;
        
        num_segments++;
        
        i_segments = 1;
        i_pubdefs = num_segments;
        i_extdefs = i_pubdefs + num_pubdefs;
        
        part_p_array = xmalloc (sizeof (*part_p_array) * num_segments);
        of = object_file_make (filename, num_segments + num_pubdefs + num_extdefs);
        
        local_name_suffix_size = LOCAL_SYMBOL_NAME_SUFFIX_FORMAT_SIZE + strlen (filename);
        
        local_name_suffix = xmalloc (local_name_suffix_size);
        sprintf (local_name_suffix, LOCAL_SYMBOL_NAME_SUFFIX_FORMAT, filename, unique_id++);
    
    }
    
    while (pos < (unsigned char *) data + data_size) {
    
        record_type = pos[0];
        
        big_fields = record_type & 1;
        record_type &= ~1;
        
        record_len = array_to_integer (pos + 1, 2, 0);
        pos += 3;
        
        if (record_type == RECORD_TYPE_THEADR) {
        
            unsigned char string_length = pos[0];
            
            if (string_length > record_len - 2) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: incorrect string length", filename);
                exit (EXIT_FAILURE);
            
            }
        
        } else if (record_type == RECORD_TYPE_COMENT) {
        
            unsigned char *saved_pos = pos, comment_class;
            
            if (record_len < 3) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: incorrect COMENT record length", filename);
                exit (EXIT_FAILURE);
            
            }
            
            comment_class = pos[1];
            
            if (comment_class == COMENT_CLASS_OMF_EXTENSION) {
            
                report_at (program_name, 0, REPORT_INTERNAL_ERROR, "%s: COMENT_CLASS_OMF_EXTENSION unimplemented", filename);
                exit (EXIT_FAILURE);
            
            } else if (comment_class == 0xFE) {
                /* Unknown but present in import libraries. */
            }
            
            pos = saved_pos;
        
        } else if (record_type == RECORD_TYPE_MODEND) {
            break;
        } else if (record_type == RECORD_TYPE_EXTDEF || record_type == RECORD_TYPE_LEXTDEF) {
        
            extdef_name_end = (extdef_name = pos) + record_len - 1;
            
            while (extdef_name != extdef_name_end) {
            
                extdef_name_len = extdef_name[0];
                symbol = of->symbol_arr + i_extdefs++;
                
                if (record_type == RECORD_TYPE_LEXTDEF) {
                
                    symbol->name = xmalloc (extdef_name_len + local_name_suffix_size);
                    
                    memcpy (symbol->name, extdef_name + 1, extdef_name_len);
                    memcpy (symbol->name + extdef_name_len, local_name_suffix, local_name_suffix_size);
                
                } else {
                    symbol->name = xstrndup ((char *) extdef_name + 1, extdef_name_len);
                }
                
                symbol->value = 0;
                symbol->part = 0;
                symbol->section_number = UNDEFINED_SECTION_NUMBER;
                
                symbol_record_external_symbol (symbol);
                extdef_name = extdef_name + 1 + extdef_name_len + 1;
            
            }
        
        } else if (record_type == RECORD_TYPE_PUBDEF || record_type == RECORD_TYPE_LPUBDEF) {
        
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
            
            if (base_segment_index >= i_segments || !base_segment_index) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid base segment index", filename);
                exit (EXIT_FAILURE);
            
            }
            
            pubdef_name = pos + 2;
            
            while (pubdef_name != pubdef_name_end) {
            
                pubdef_name_len = pubdef_name[prefix - 1];
                
                if (big_fields) {
                    public_offset = array_to_integer (pubdef_name + prefix + pubdef_name_len, 4, 0);
                } else {
                    public_offset = array_to_integer (pubdef_name + prefix + pubdef_name_len, 2, 0);
                }
                
                symbol = of->symbol_arr + i_pubdefs++;
                
                if (record_type == RECORD_TYPE_LPUBDEF) {
                
                    symbol->name = xmalloc (pubdef_name_len + local_name_suffix_size);
                    
                    memcpy (symbol->name, pubdef_name + prefix, pubdef_name_len);
                    memcpy (symbol->name + pubdef_name_len, local_name_suffix, local_name_suffix_size);
                
                } else {
                    symbol->name = xstrndup ((char *) pubdef_name + prefix, pubdef_name_len);
                }
                
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
            
                segment_len = array_to_integer (pos + 1, 4, 0);
                
                segment_name_index = pos[5];
                class_name_index = pos[6];
            
            } else {
            
                segment_len = array_to_integer (pos + 1, 2, 0);
                
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
            } else if (strcmp (lnames[class_name_index], "BSS") == 0) {
            
                section->flags = SECTION_FLAG_ALLOC | SECTION_FLAG_DATA;
                section->is_bss = 1;
            
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
            
            part->content_size = segment_len;
            
            if (!section->is_bss) {
                part->content = xmalloc (part->content_size);
            }
            
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
                    
                    locat = subrec[0];
                    
                    if (((locat >> 2) & 0x0F) == 3) {
                    
                        if (offset32_loc && offset32_loc != 3) {
                        
                            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: OMF LOC 3 and 9 inconsistency", filename);
                            exit (EXIT_FAILURE);
                        
                        }
                        
                        offset32_loc = 3;
                        
                        locat &= ~(0x0F << 2);
                        locat |= (9 << 2);
                    
                    } else if (((locat >> 2) & 0x0F) == 9) {
                    
                        if (offset32_loc && offset32_loc != 9) {
                        
                            report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: OMF LOC 3 and 9 inconsistency", filename);
                            exit (EXIT_FAILURE);
                        
                        }
                        
                        offset32_loc = 9;
                    
                    }
                    
                    if (((locat >> 2) & 0x0F) != 1 && ((locat >> 2) & 0x0F) != 9) {
                    
                        report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: only 16-bit/32-bit offset OMF fixups are supported", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    data_record_offset = ((unsigned short) (locat & 0x03)) << 8;
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
                    subrec += 3;
                    
                    if (frame_method != METHOD_F1_GRPDEF && frame_method != METHOD_F5) {
                        
                        report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: only F5 frame methods in OMF fixups are supported", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    if (target_method != METHOD_T0_SEGDEF && target_method != METHOD_T2_EXTDEF) {
                        
                        report_at (__FILE__, __LINE__, REPORT_INTERNAL_ERROR, "%s: only T2 target methods in OMF fixups are supported", filename);
                        exit (EXIT_FAILURE);
                    
                    }
                    
                    if (frame_method == METHOD_F1_GRPDEF) {
                    
                        /* Frame datum does not matter, just skip it. */
                        subrec++;
                    
                    }
                    
                    target_datum = subrec[0];
                    subrec++;
                    
                    old_reloc_count = part->reloc_cnt;
                    part->reloc_cnt += 1;
                    
                    part->reloc_arr = xrealloc (part->reloc_arr, part->reloc_cnt * sizeof (*part->reloc_arr));
                    memset (part->reloc_arr + old_reloc_count, 0, (part->reloc_cnt - old_reloc_count) * sizeof (*part->reloc_arr));
                    
                    reloc = part->reloc_arr + old_reloc_count;
                    
                    if (target_method == METHOD_T0_SEGDEF) {
                    
                        if (target_datum > num_segments || !target_datum) {
                        
                            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid target datum", filename);
                            exit (EXIT_FAILURE);
                        
                        }
                        
                        reloc->symbol = of->symbol_arr + target_datum;
                    
                    } else if (target_method == METHOD_T2_EXTDEF) {
                    
                        if (target_datum > num_extdefs || !target_datum) {
                        
                            report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid target datum", filename);
                            exit (EXIT_FAILURE);
                        
                        }
                        
                        reloc->symbol = of->symbol_arr + num_segments + num_pubdefs + target_datum - 1;
                    
                    }
                    
                    reloc->offset = prev_ledata.offset + data_record_offset;
                    reloc->addend = 0;
                    
                    if (((locat >> 2) & 0x0F) == 1) {
                    
                        if (locat & FIXUP_LOCAT_M_SEGMENT_RELATIVE) {
                            reloc->howto = &reloc_howtos[RELOC_TYPE_16];
                        } else {
                            reloc->howto = &reloc_howtos[RELOC_TYPE_PC16];
                        }
                    
                    } else {
                    
                        if (locat & FIXUP_LOCAT_M_SEGMENT_RELATIVE) {
                            reloc->howto = &reloc_howtos[RELOC_TYPE_32];
                        } else {
                            reloc->howto = &reloc_howtos[RELOC_TYPE_PC32];
                        }
                    
                    }
                
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
            
                offset = array_to_integer (pos + 1, 4, 0);
                
                size = record_len - 6;
                data_bytes = pos + 5;
            
            } else {
            
                offset = array_to_integer (pos + 1, 2, 0);
                
                size = record_len - 4;
                data_bytes = pos + 3;
            
            }
            
            if (seg_index >= i_segments || !seg_index) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: invalid seg index", filename);
                exit (EXIT_FAILURE);
            
            }
            
            part = part_p_array[seg_index];
            
            if (part->section->is_bss) {
            
                report_at (program_name, 0, REPORT_FATAL_ERROR, "%s: LEDATA seg index references BSS section", filename);
                exit (EXIT_FAILURE);
            
            }
            
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
    
    if (local_name_suffix) {
        free (local_name_suffix);
    }
    
    for (i_lnames = 0; i_lnames < num_lnames; i_lnames++) {
    
        if (lnames[i_lnames]) {
            free (lnames[i_lnames]);
        }
    
    }
    
    if (lnames) {
        free (lnames);
    }
    
    if (part_p_array) {
        free (part_p_array);
    }

}
