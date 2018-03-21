#!/usr/bin/python
import os
import sys
import tempfile
from elf_basic import *
from section_basic import *

class base_instrumentor(elf_basic):
    def __init__(self, file, option=None):
        super(base_instrumentor, self).__init__(file)
        self.task = option
        self.gen_tempfile(self.get_current_file())
        self.new_segment_base_addr      = None
        self.new_segment_offset         = None
        self.new_segment_offset_in_phdr = None
        self.new_segment_fsize          = None
        self.new_segment_msize          = None
        self.new_segment_flags          = 0
        self.new_segment_align          = None
        self.new_sections               = []
        self.new_interp_offset          = None
        self.new_interp_vaddr           = None
        self.new_interp_paddr           = None
        self.prefer_inject_new_segment = 1
    def get_name(self):
        return self.instrumentor_name

    def get_new_segment_info(self):
        new_segment = dict()
        new_segment['current_file'              ] = self.get_current_file()
        new_segment['new_segment_base_addr'     ] = self.new_segment_base_addr
        new_segment['new_segment_offset'        ] = self.new_segment_offset
        new_segment['new_segment_offset_in_phdr'] = self.new_segment_offset_in_phdr
        new_segment['new_segment_fsize'         ] = self.new_segment_fsize
        new_segment['new_segment_msize'         ] = self.new_segment_msize
        new_segment['new_segment_flags'         ] = self.new_segment_flags
        new_segment['new_segment_align'         ] = self.new_segment_align
        new_segment['new_sections'              ] = self.new_sections
        return new_segment

    def set_new_segment_info(self, new_segment):
        if(new_segment == None):
            return
        self.set_current_file(new_segment['current_file'])
        self.new_segment_base_addr      = new_segment['new_segment_base_addr'     ]
        self.new_segment_offset         = new_segment['new_segment_offset'        ]
        self.new_segment_offset_in_phdr = new_segment['new_segment_offset_in_phdr']
        self.new_segment_fsize          = new_segment['new_segment_fsize'         ]
        self.new_segment_msize          = new_segment['new_segment_msize'         ]
        self.new_segment_flags          = new_segment['new_segment_flags'         ]
        self.new_segment_align          = new_segment['new_segment_align'         ]
        self.new_sections               = new_segment['new_sections'              ]

    def get_new_segment_perm(self):
        return self.new_segment_flags

    def get_new_segment_phdr_offset(self):
        return self.new_segment_offset_in_phdr

    def get_new_segment_base(self):
        return self.new_segment_base_addr

    def get_new_segment_base_addr(self, binname):
        if(self.new_segment_base_addr != None):
            return self.new_segment_base_addr
        loadsegments = self.get_load_segments_info(binname)
        end_addr = loadsegments[-1]['vaddr'] + loadsegments[-1]['memsize']
        print "end addr 0x%08x" % end_addr
        end_addr = (end_addr & 0xfffff000) + 0x1000
        self.new_segment_base_addr = end_addr
        print "end addr 0x%08x" % end_addr
        return end_addr

    def get_new_segment_offset(self):
        return  self.new_segment_offset

    def interp_segment_exist(self, binname):
        if(None != self.get_segment_info(binname, "INTERP", 0, 'offset')):
            return True
        else:
            return False

    def compute_gap_to_extend_phdr(self, binname):
        phdrnum = self.get_elfhdr_info(binname, "Number of program headers:");
        phdrsize = self.get_elfhdr_info(binname,"Size of program headers:");
        phdrstart = self.get_elfhdr_info(binname,"Start of program headers:");
        phdrend = phdrstart + phdrsize * phdrnum

        if(not self.interp_segment_exist(binname)):
        # Compute the distance between end of phdr and the first critical
        # segment after.
            firstdynsection = self.get_dynamic_sections_info(binname)[0][1]
            fisrtdynsection = self.convert_vma_to_offset(binname,
                                                         firstdynsection)
            #print "first critical dynamic section: %x" % firstdynsection
            return firstdynsection - phdrend
        else:
        # Check if interp string is between end of phdr and the first critical
        # section recorded by .dynamic. If so, compute the distance between end
        # of interp str and the first critical section and the distance between
        # the end of phdr and beginning of interp. The function should return
        # whichever is larger. If the interpstr is not in between end of phdr
        # and 1st critical section, then return directly the distance of the
        # two.
            interpoffset = self.get_segment_info(binname, "INTERP", 0, 'offset')
            interpfsize = self.get_segment_info(binname, "INTERP", 0, 'fsize')
            interpend = interpoffset + interpfsize + 1
            firstdynsection = self.get_dynamic_sections_info(binname)[0][1]
            firstdynsecoffset = self.convert_vma_to_offset2(binname,
                                                            firstdynsection)
            print "firstdynsection: %x" % firstdynsecoffset
            print "interpend: %x" % interpend
            print "interpoffset: %x" % interpoffset
            print "phdrend: %x" % phdrend
        if(interpoffset >= phdrend and interpend <= firstdynsecoffset):
            dist_1stdyn2interp  = firstdynsecoffset - interpend
            dist_phdrend2interp = interpoffset - phdrend
            print "interp str is between phdrend and 1st dyn section"
            return max(dist_1stdyn2interp, dist_phdrend2interp)
        else:
            return firstdynsection - phdrend

    def relocate_interpstr(self, binname):
        #check if INTERP segment exists or not
        if(not self.interp_segment_exist(binname)):
            return
        interpoffset= self.get_segment_info(binname, "INTERP", 0, 'offset')
        interpvaddr = self.get_segment_info(binname, "INTERP", 0, 'vaddr')
        interppaddr = self.get_segment_info(binname, "INTERP", 0, 'paddr')
        interpfsize = self.get_segment_info(binname, "INTERP", 0, 'fsize')
        print "vaddr %x paddr %x " % (interpvaddr, interppaddr)
        #looking for the nearest critical information after interp string
        safeend = self.convert_vma_to_offset2(binname, self.get_dynamic_sections_info(binname)[0][1])
        #figure out safe interp offset and len
        safestart = safeend - interpfsize - 1
        if(safestart <= interpoffset):
            print "No need to move interp string"
            return
        interpstr = self.read_data(binname, interpoffset, interpfsize)
        self.write_data(binname, safestart, interpstr)
        self.write_data(binname, safestart + interpfsize, '\0')
        self.write_data(binname, safestart, interpstr)
        #update phdr for interp
        diff = safestart - interpoffset
        newvaddr = interpvaddr + diff
        self.modify_phdrtab_info(binname, phdr.PT_INTERP, phdr.p_offset, safestart)
        self.modify_phdrtab_info(binname, phdr.PT_INTERP, phdr.p_vaddr, newvaddr)
        self.modify_phdrtab_info(binname, phdr.PT_INTERP, phdr.p_paddr, newvaddr)
        self.modify_sectiontab_info(binname, ".interp", sectiontab.s_vaddr, newvaddr)
        self.modify_sectiontab_info(binname, ".interp", sectiontab.s_offset, safestart)
        self._handle_note_sections(binname)
        print interpstr
        print self.get_current_file()
        self.new_interp_offset = safestart
        self.new_interp_vaddr  = interpvaddr + diff
        self.new_interp_paddr  = interpvaddr + diff
        return

    def _handle_note_sections(self, binname):
        cmd = "readelf -W -S %s|grep -o '.note\.[^ ]*'"%binname
        lnotes = self.get_result_lines(cmd)
        for sec in lnotes:
            self.modify_sectiontab_info(binname, sec, sectiontab.s_size, 0)

    def _write_to_phdr(self, binname, segment_offset, stype=phdr.PT_LOAD, offset=0,
                       vaddr=0, paddr=0, fsize=0, msize=0, flags=0x5,
                       align=0x1000):
        if(stype == phdr.PT_LOAD):
                align=0x1000
        self.write_int(binname, segment_offset + phdr.p_type  , stype)
        self.write_int(binname, segment_offset + phdr.p_flags , flags)
        self.write_ptr(binname, segment_offset + phdr.p_offset, offset)
        self.write_ptr(binname, segment_offset + phdr.p_vaddr , vaddr)
        self.write_ptr(binname, segment_offset + phdr.p_paddr , paddr)
        self.write_ptr(binname, segment_offset + phdr.p_filesz, fsize)
        self.write_ptr(binname, segment_offset + phdr.p_memsz , msize)
        self.write_ptr(binname, segment_offset + phdr.p_align , align)

    def insert_new_phdr_entry(self, binname, stype=phdr.PT_LOAD, offset=0, vaddr=0, paddr=0,
                              fsize=0, msize=0, flags=0x5, align=0x1000):
        gap = self.compute_gap_to_extend_phdr(binname)
        phdr_size = self.get_elfhdr_info(binname,"Size of program headers:");
        if(gap < phdr_size):
            print "gap is too small to insert new segment"
            return None
        self.relocate_interpstr(binname)
        phdr_start = self.get_elfhdr_info(binname,"Start of program headers:");
        phdr_num = self.get_elfhdr_info(binname, "Number of program headers:");
        phdr_end = phdr_start + phdr_size * phdr_num
        phdr_num += 1
        self.write_short(binname, elfhdr.e_phdr_ent_cnt, phdr_num)
        self._write_to_phdr(binname, phdr_end, stype, offset, vaddr, paddr,
                               fsize, msize, flags, align)
        print binname
        return phdr_end

    def override_existing_phdr_entry(self, binname, segtype, idx=0, stype=phdr.PT_LOAD,
                                     offset=0, vaddr=0, paddr=0, fsize=0, msize=0,
                                     flags=0x5, align=0x1000):
        segment_offset = self.get_segment_offset_in_phdr(binname, segtype, idx)
        if(segment_offset == None):
            print "cannot find segment to override"
            return None
        self._write_to_phdr(binname, segment_offset, stype, offset, vaddr, paddr,
                            fsize, msize, flags, align)
        print self.get_current_file()
        return segment_offset

    def add_new_segment_in_phdr(self, binname, flags=0x5, stype=phdr.PT_LOAD,
                                align=0x1000, offset=0, vaddr=0, paddr=0,
                                fsize=0, msize=0):
        if(self.prefer_inject_new_segment == 0):
            offset_phdr = self.override_existing_phdr_entry(binname,
                                                            phdr.PT_NOTE, 0,
                                                            stype, offset,
                                                            vaddr, paddr,fsize,
                                                            msize, flags, align)
            if(offset_phdr != None):
                self.new_segment_offset_in_phdr = offset_phdr
                return offset_phdr
            print "failed to find a method to insert a new segment"
            raise

        offset_phdr = self.insert_new_phdr_entry(binname, stype, offset, vaddr, paddr,
                                              fsize, msize, flags, align)
        if(offset_phdr != None):
            self.new_segment_offset_in_phdr = offset_phdr
            return offset_phdr
        print "cannot insert new segment, trying to override existing one"
        offset_phdr = self.override_existing_phdr_entry(binname, phdr.PT_NOTE, 0, stype,
                                                        offset, vaddr, paddr,
                                                        fsize, msize, flags, align)
        if(offset_phdr != None):
            self.new_segment_offset_in_phdr = offset_phdr
            return offset_phdr
        print "failed to find a method to insert a new segment"
        raise

    def _is_new_segment_the_last(self, binname):
        phdr_start = self.get_elfhdr_info(binname, "Start of program headers:");
        phdr_num   = self.get_elfhdr_info(binname, "Number of program headers:");
        phdr_size  = self.get_elfhdr_info(binname, "Size of program headers:");
        last_entry = phdr_start + phdr_size * (phdr_num - 1)
        if(last_entry == self.get_new_segment_phdr_offset()):
            return True
        else:
            return False

    def insert_new_section(self, binname, secname, filename, align, perm):
        sectiontable = section_table(binname)
        sectiontable.insert_new_section(secname, filename, binname, perm, align)
        sectiontable.write2disk()
        self.new_sections.append(secname)

    # FIXME: we assume ".shstrtab" is the last (geolocation) effective section in ELF file.
    def relocate_section(self, binname, secname, align=None):
        if(secname == ".shstrtab"):
            print "no need to relocate section string table setion"
            return
        if(align == None):
            align = self.get_section_info(binname, secname, sectiontab.s_align)
        shstr_offset         = self.get_section_info(binname, ".shstrtab", "offset")
        shstr_size           = self.get_section_info(binname, ".shstrtab", "size")
        shstr_align          = self.get_section_info(binname, ".shstrtab", sectiontab.s_align)
        sec_start            = self.get_section_info(binname, secname, "offset")
        sec_size             = self.get_section_info(binname, secname, "size")
        newsec_start         = self.compute_align(shstr_offset, align)
        newshstr_offset      = self.compute_align(newsec_start + sec_size, shstr_align)
        sectiontab_entry     = self.get_elfhdr_info(binname, elfhdr.e_sechdr_offset)
        sectiontab_ent_sz    = self.get_elfhdr_info(binname, elfhdr.e_sechdr_ent_size)
        newsectiontab_offset = self.compute_align(newshstr_offset + shstr_size + 0x1000, sectiontab_ent_sz)
        # relocate sectiontab first.
        self.relocate_sectiontab(binname, newsectiontab_offset, elf_basic.ABSOLUTE)
        # relocate shstrtab then.
        self.modify_sectiontab_info(binname, ".shstrtab", sectiontab.s_offset, newshstr_offset)
        self.relocate_data(binname, shstr_offset, shstr_size, newshstr_offset)
        # inject section into new location and update section table
        self.relocate_data(binname, sec_start, sec_size, newsec_start)
        self.modify_sectiontab_info(binname, secname, sectiontab.s_offset, newsec_start)

    def validate_sectionlist(self, binname, sectionlist):
        if(len(sectionlist) == 0):
            return False
        for sec in sectionlist:
            if(self.get_section_info(binname, sec, 'offset') == None):
                return False
        return True

    def map_sections_to_new_segment(self, binname, align, perm):
        self.map_sections_to_segment(binname, self.new_sections,
                                     self.get_new_segment_phdr_offset(), align, perm)

    def map_sections_to_segment(self, binname, sectionlist, segment_offset, align, perm):
        if(self.validate_sectionlist(binname, sectionlist) == False):
            print "please sanitize the sectionlist and "\
                  "ensure that all sections are valid"
            return
        offset = self.get_section_info(binname, sectionlist[0], 'offset')
        fsize  = \
            self.get_section_info(binname, sectionlist[-1], 'offset') + \
            self.get_section_info(binname, sectionlist[-1], 'size') - \
            offset

        memsize = fsize
        vaddr = self.get_new_segment_base_addr(binname)
        paddr = vaddr
        align = align
        flags = perm
        self.new_segment_offset     = offset
        self.new_segment_size       = fsize
        self.new_segment_base_addr  = vaddr
        self.new_segment_fsize      = fsize
        self.new_segment_msize      = memsize
        self.new_segment_align      = align
        self.new_segment_flags      = flags
        self._write_to_phdr(binname, segment_offset, phdr.PT_LOAD, offset,
                            vaddr, paddr, fsize, memsize, flags, align)

    # Check if the new segment is the last'PT_LOAD' segment in phdr.
    # If yes: remove the segment by tweaking the segment number in elfhdr.
    # If no : do nothing.
    # Reason: objcopy does not support ELF with additional segments appended
    #         in phdr.
    def _remove_new_segment(self, binname):
        phdr_start = self.get_elfhdr_info(binname, "Start of program headers:");
        phdr_num   = self.get_elfhdr_info(binname, "Number of program headers:");
        phdr_size  = self.get_elfhdr_info(binname, "Size of program headers:");
        last_entry = phdr_start + phdr_size * (phdr_num - 1)
        if(last_entry == self.get_new_segment_phdr_offset()):
            print "removing new segment in phdr"
            self.write_short(binname, elfhdr.e_phdr_ent_cnt, phdr_num - 1)

    def _add_new_segment_back(self, binname):
        phdr_start = self.get_elfhdr_info(binname, "Start of program headers:");
        phdr_num   = self.get_elfhdr_info(binname, "Number of program headers:");
        phdr_size  = self.get_elfhdr_info(binname, "Size of program headers:");
        phdr_end = phdr_start + phdr_size * phdr_num
        if(phdr_end == self.get_new_segment_phdr_offset()):
            print "adding new segment back in phdr"
            self.write_short(binname, elfhdr.e_phdr_ent_cnt, phdr_num + 1)
#            self._write_to_phdr(binname,
#                                self.get_new_segment_offset_in_phdr(),
#                                phdr.PT_LOAD, self.get_new_segment_offset(),
#                                self.get_new_segment_base(),
#                                self.get_new_segment_base(),
#                                self.new_segment_fsize,
#                                self.new_segment_msize,
#                                self.new_segment_flags,
#                                self.new_segment_align)

    def add_instrumentation_data(self, binname, filename, secname, align, perm=None):
        if(secname in self.new_sections):
            return None
        if(perm == None):
            perm = sectiontab.SHF_ALLOC | sectiontab.SHF_EXECINSTR

        self.insert_new_section(binname, secname, filename, align, perm)
        segperm = self.trans_sec2seg_perm(perm)
        if(self.get_new_segment_phdr_offset() == None or
           self.get_new_segment_base() == None):
            if(self.add_new_segment_in_phdr(binname, segperm) == None):
                return None
        self.map_sections_to_new_segment(binname, align,
                                         segperm | self.get_new_segment_perm())
        print "segperm: %x" % segperm
        print "perm: %x" % perm
        return secname

def create_file():
    hexstr="\x90\x90"
    file = "/tmp/abc"
    f = open(file, 'w')
    f.write(hexstr)
    f.close()
    return file

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, help="file to instrument",
                        required=True)
    parser.add_argument("-t", "--instrument", type=str, help="instrument type",
                        required=False, default="remap_cptr")
    args = parser.parse_args()
    instrument = base_instrumentor(args.file, args.instrument)
    filename = create_file()
    instrument.add_instrumentation_data(instrument.get_current_file(), filename, ".mytext1", 0x1000, sectiontab.SHF_EXECINSTR)
    #instrument.add_instrumentation_data(instrument.get_current_file(), filename, ".mytext1", 0x1000)
    instrument.add_instrumentation_data(instrument.get_current_file(), filename, ".mytext2", 0x1000)
    instrument.add_instrumentation_data(instrument.get_current_file(), filename, ".mytext3", 0x1000)

    print instrument.get_current_file()
if __name__ == "__main__":
	main()
