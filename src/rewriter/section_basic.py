#!/usr/bin/python
import os,sys,inspect,platform
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)

from elf_basic import *


class section_table(elf_basic):
    def __init__(self, binname):
        super(section_table, self).__init__(binname)
        self.sectiontable = dict();
        self.stringtable  = dict();
        self.stringtable[0] = 1;
        self.strtaboffset = -1 # fail safe
        self.sectaboffset = -1 # fail safe
        self.sectabentsz  = self.get_elfhdr_info(binname, elfhdr.e_sechdr_ent_size)
        self.dsecname2idx = dict()
        self.init_sections()
        #self.write2disk()
        self.secname2idx = dict()
        self.load_sectiontable()

    def load_sectiontable(self):
        seclist = self.get_sectionlist(self.get_binname())
        self.secname2idx["NULL"] = 0
        secidx = 1
        if(len(seclist) > 0):
            for sec in seclist:
                attr = []
                self.secname2idx[sec] = secidx
                secidx += 1
                for a in self.attribute_list:
                    info = self.get_section_info(self.get_binname(), sec, a)
                    if( a == self.sectiontab.s_link):
                        if(info == 0):
                            attr.append("NULL")
                        else:
                            attr.append(seclist[info - 1])
                    else:
                        attr.append(info)
                self.assign_section(sec, attr)
                #print sec
                #print attr
        else:
            self.assign_section('.shstrtab', [1,3,0,0,self.strtaboffset,0,0,0,1,0])


    def save_sectiontable(self):
        self.write2disk(self.current_file)

    def _expand_shstrtab(self, name):
        if(name == None or len(name) == 0):
            print "invalid string name"
            raise
        offset = self.stringtable[0]
        self.stringtable[offset] = name
        self.stringtable[0] += len(name) + 1
        return offset

    def duplicate_section(self, origsec, newsec, binname=None,
                          align=None, tgtsec=None):
        if(align == None):
            align = self.sectiontable[origsec][self.sectiontab.s_align]
        if(tgtsec == None):
            tgtsec = self.get_last_section_in_mem()
        if(origsec not in self.sectiontable or \
           tgtsec not in self.sectiontable):
            return False
        if(tgtsec == ".bss"):
            align = 0x1000
        secoffset    = self.sectiontable[origsec][self.sectiontab.s_offset]
        secvaddr     = self.sectiontable[origsec][self.sectiontab.s_vaddr]
        secsize      = self.sectiontable[origsec][self.sectiontab.s_size]
        tgtsecoffset = self.sectiontable[tgtsec][self.sectiontab.s_offset]
        tgtsecsize   = self.sectiontable[tgtsec][self.sectiontab.s_size]
        tgtsecvaddr  = self.sectiontable[tgtsec][self.sectiontab.s_vaddr]
        tgtinjectoffset   = self.compute_align(tgtsecoffset + tgtsecsize, align)
        tgtinjectvaddr    = self.compute_align(tgtsecvaddr + tgtsecsize, align)
        print "location to inject 0x%x" % tgtinjectoffset
        if(binname == None):
            self.relocate_data(self.filename, secoffset, secsize,
                               tgtinjectoffset)
        else:
            self.relocate_data(binname, secoffset, secsize,
                               tgtinjectoffset)
        print "updating section table"
        self.assign_section(newsec, self.get_attributes(origsec).copy())
        self.assign_attribute(newsec, "offset", tgtinjectoffset)
        self.assign_attribute(newsec, "vaddr", tgtinjectvaddr)
        #print self.sectiontable[newsec]

    def insert_new_section(self, secname, datafile, binname=None, perm=None,
                           align=None, tgtsec=None):
        if(perm == None):
            perm = 0x6 #AX
        if(align == None):
            align = 0x1000
        if(tgtsec == None):
            tgtsec = self.get_last_section_in_mem()
        if(binname == None):
            binname = self.filename
        tgtsecoffset = self.sectiontable[tgtsec][self.sectiontab.s_offset]
        tgtsecsize   = self.sectiontable[tgtsec][self.sectiontab.s_size]
        tgtsecvaddr  = self.sectiontable[tgtsec][self.sectiontab.s_vaddr]
        tgtinjectoffset   = self.compute_align(tgtsecoffset + tgtsecsize, align)
        tgtinjectvaddr    = self.compute_align(tgtsecvaddr + tgtsecsize, align)
        self.write_data_from_file(binname, tgtinjectoffset, datafile)
        self.assign_section(secname, self.get_defaults('.default'))
        self.assign_attribute(secname, "offset", tgtinjectoffset)
        self.assign_attribute(secname, "vaddr", tgtinjectvaddr)
        self.assign_attribute(secname, "align", align)
        self.assign_attribute(secname, "flags", perm)
        self.assign_attribute(secname, "size", os.path.getsize(datafile))


    def relocate_section(self, secname, binname=None, align=None, tgtsec=None):
        # Relocate_section() basically can be applied to all sections in
        # section table.  If tgtsec is None, then inject to just after
        # ".bss".  All sections behind ".bss" will be further relocated back.
        # Size of a section should be counted by the size and the align.
        if(align == None):
            align = self.sectiontable[secname][self.sectiontab.s_align]
        if(tgtsec == None):
            tgtsec = self.get_last_section_in_mem()
        if(secname not in self.sectiontable or \
           tgtsec not in self.sectiontable):
            return False
        if(tgtsec == ".bss"):
            align = 0x1000
            #tgtoffset = self.sectiontable[secname][self.sectiontab.s_size]
            #tgtoffset = (tgtoffset + 4096 - 1) &
        secoffset    = self.sectiontable[secname][self.sectiontab.s_offset]
        secvaddr     = self.sectiontable[secname][self.sectiontab.s_vaddr]
        secsize      = self.sectiontable[secname][self.sectiontab.s_size]
        tgtsecoffset = self.sectiontable[tgtsec][self.sectiontab.s_offset]
        tgtsecsize   = self.sectiontable[tgtsec][self.sectiontab.s_size]
        tgtsecvaddr  = self.sectiontable[tgtsec][self.sectiontab.s_vaddr]
        tgtinjectoffset   = self.compute_align(tgtsecoffset + tgtsecsize, align)
        tgtinjectvaddr    = self.compute_align(tgtsecvaddr + tgtsecsize, align)
        print "location to inject 0x%x" % tgtinjectoffset
        if(binname == None):
            print "offset to read: %x" % secoffset
            print "offset to inject: %x" % tgtinjectoffset
            self.relocate_data(self.filename, secoffset, secsize,
                               tgtinjectoffset)
        else:
            self.relocate_data(binname, secoffset, secsize,
                               tgtinjectoffset)
        print "updating section table"
        self.sectiontable[secname][self.sectiontab.s_offset] = tgtinjectoffset
        self.sectiontable[secname][self.sectiontab.s_vaddr]  = tgtinjectvaddr


    def _move_section_back(self, name, size):
        pass

    def init_sections(self):

        self.dsecname2idx['stridx']  = sectiontab.s_str_idx
        self.dsecname2idx['type']    = sectiontab.s_type
        self.dsecname2idx['flags']   = sectiontab.s_flags
        self.dsecname2idx['vaddr']   = sectiontab.s_vaddr
        self.dsecname2idx['offset']  = sectiontab.s_offset
        self.dsecname2idx['size']    = sectiontab.s_size
        self.dsecname2idx['link']    = sectiontab.s_link
        self.dsecname2idx['info']    = sectiontab.s_info
        self.dsecname2idx['align']   = sectiontab.s_align
        self.dsecname2idx['entsize'] = sectiontab.s_entsize
        self.attribute_list = [sectiontab.s_str_idx, sectiontab.s_type,
                               sectiontab.s_flags, sectiontab.s_vaddr,
                               sectiontab.s_offset, sectiontab.s_size,
                               sectiontab.s_link, sectiontab.s_info,
                               sectiontab.s_align, sectiontab.s_entsize]
            # no section, then create a new one
        self.default_sections = dict()
        if(self.ptr_size() == 8):
            self.default_sections['.dynsym']            = [1,0xb,2,0,0,0,0,1,4,0x18]
            self.default_sections['.rela.dyn']          = [1,4,2,0,0,0,5,0,4,0x18]
            self.default_sections['.rela.plt']          = [1,4,2,0,0,0,5,0xc,4,0x18]
        elif(self.ptr_size() == 4):
            self.default_sections['.dynsym']            = [1,0xb,2,0,0,0,0,1,4,0x10]
            self.default_sections['.rela.dyn']          = [1,4,2,0,0,0,5,0,4,8]
            self.default_sections['.rela.plt']          = [1,4,2,0,0,0,5,0xc,4,8]
        else:
            raise
        self.default_sections['.default']           = [1,1,6,0,0,0,0,0,0x10,0]
        self.default_sections['.note.gnu.build-id'] = [1,7,2,0,0,0,0,0,4,0]
        self.default_sections['.note.ABI-tag']      = [1,7,2,0,0,0,0,0,4,0]
        self.default_sections['.note.hwcaps']       = [1,7,2,0,0,0,0,0,4,0]
        self.default_sections['.note.gold-version'] = [1,7,2,0,0,0,0,0,4,0]
        self.default_sections['.shstrtab']          = [1,3,0,0,0,0,0,0,1,0]
        self.default_sections['.data.rel.ro']       = [1,1,3,0,0,0,0,0,4,0]
        self.default_sections['.interp']            = [1,1,2,0,0,0,0,0,1,0]
        self.default_sections['.gnu.hash']          = [1,0x6ffffff6,2,0,0,0,5,0,4,4]
        self.default_sections['.hash']              = [1,5,2,0,0,0,5,0,4,4]
        self.default_sections['.tdata']             = [1,1,0x403,0,0,0,0,0,4,0]
        self.default_sections['.tbss']              = [1,8,0x403,0,0,0,0,0,4,0]
        self.default_sections['.dynstr']            = [1,3,2,0,0,0,0,0,1,0]
        self.default_sections['.gnu.version']       = [1,0x6fffffff,2,0,0,0,0,0,2,2]
        self.default_sections['.gnu.version_r']     = [1,0x6ffffffe,2,0,0,0,6,1,4,0]
        self.default_sections['.gnu.version_d']     = [1,0x6ffffffc,2,0,0,0,6,3,4,0]
        self.default_sections['.rel.dyn']           = [1,9,2,0,0,0,5,0,4,8]
        self.default_sections['.rel.plt']           = [1,9,2,0,0,0,5,0xc,4,8]
        self.default_sections['.init']              = [1,1,6,0,0,0,0,0,4,0]
        self.default_sections['.plt']               = [1,1,6,0,0,0,0,0,0x10,4]
        self.default_sections['.text']              = [1,1,6,0,0,0,0,0,0x10,0]
        self.default_sections['.fini']              = [1,1,6,0,0,0,0,0,4,0]
        self.default_sections['.rodata']            = [1,1,2,0,0,0,0,0,0x20,0]
        self.default_sections['.eh_frame_hdr']      = [1,1,2,0,0,0,0,0,4,0]
        self.default_sections['.eh_frame']          = [1,1,2,0,0,0,0,0,4,0]
        self.default_sections['.gcc_except_table']  = [1,1,2,0,0,0,0,0,4,0]
        self.default_sections['.init_array']        = [1,0xe,3,0,0,0,0,0,self.ptr_size(),0]
        self.default_sections['.fini_array']        = [1,0xf,3,0,0,0,0,0,self.ptr_size(),0]
        self.default_sections['.ctors']             = [1,1,3,0,0,0,0,0,self.ptr_size(),0]
        self.default_sections['.dtors']             = [1,1,3,0,0,0,0,0,self.ptr_size(),0]
        self.default_sections['.jcr']               = [1,1,3,0,0,0,0,0,self.ptr_size(),0]
        self.default_sections['.dynamic']           = [1,6,3,0,0,0,0,0,self.ptr_size(),self.ptr_size()*2]
        self.default_sections['.got']               = [1,1,3,0,0,0,0,0,self.ptr_size(),self.ptr_size()]
        self.default_sections['.got.plt']           = [1,1,3,0,0,0,0,0,self.ptr_size(),self.ptr_size()]
        self.default_sections['.data']              = [1,1,3,0,0,0,0,0,0x20,0]
        self.default_sections['.bss']               = [1,8,3,0,0,0,0,0,0x20,0]
        self.default_sections['.gnu_debuglink']     = [1,1,0,0,0,0,0,0,1,0]
        self.default_sections['.shstrtab']          = [1,3,0,0,self.strtaboffset,0,0,0,1,0]



    def get_defaults(self, secname):
        if(secname in self.default_sections):
            return self.default_sections[secname]
        else:
            return self.default_sections['default']

    def get_attributes(self, secname):
        if(not secname in self.sectiontable):
            print "invalid section name %s" % secname
            return None
        return self.sectiontable[secname]

    def get_attribute(self, secname, field):
        if(not secname in self.sectiontable):
            print "invalid section name %s" % secname
            return None
        if(not field in self.dsecname2idx):
            print "invalid field name %s" % field
            return None
        return self.sectiontable[secname][self.dsecname2idx[field]]

    def get_index(self, secname):
        temptab1 = {k : v for k, v in self.sectiontable.iteritems() if v[sectiontab.s_vaddr] != 0}
        temptab1 = sorted(temptab1.items(), key=lambda x: x[1][sectiontab.s_offset])
        temptab2 = {k : v for k, v in self.sectiontable.iteritems() if v[sectiontab.s_vaddr] == 0}
        temptab2 = sorted(temptab2.items(), key=lambda x: x[1][sectiontab.s_offset])
        temptab1 = temptab1 + temptab2
        secidx = 1
        self.secname2idx["NULL"] = 0
        for item in temptab1:
            if(secname == item[0]):
                return secidx
            secidx += 1
        return None

    def get_next_known_section_location(self, cur_value, loc_type):
        cur_next = sys.maxint
        for index, sec in enumerate(sorted(self.sectiontable.items(),\
                                     key=lambda x: x[1][self.dsecname2idx[loc_type]])):
            cur_loc = sec[1][self.dsecname2idx[loc_type]]
            if(cur_loc > cur_value):
                if(cur_loc < cur_next):
                    cur_next = cur_loc
        return cur_next

    def get_section(self, secname, fieldlist):
        tmp = None
        for name in self.sectiontable:
            sec = self.sectiontable[name]
            if(name == secname):
                tmp = []
                for field in fieldlist:
                    if(field == 'name'):
                        tmp.append(name)
                    else:
                        tmp.append(sec[self.dsecname2idx[field]])
                break
        return tmp

    def get_sections(self, stypes, fieldlist):
        tmplist = []
        for name in self.sectiontable:
            sec = self.sectiontable[name]
            for stype in stypes:
                if(sec[self.dsecname2idx['type']] == stype):
                    tmp = []
                    for field in fieldlist:
                        if(field == 'name'):
                            tmp.append(name)
                        else:
                            tmp.append(sec[self.dsecname2idx[field]])
                    tmplist.append(tmp)
        return tmplist

    def assign_attribute_if_section_exists(self, secname, field, value):
        if(not secname in self.sectiontable):
            return
        self.assign_attribute(secname, field, value)

    def assign_attribute(self, secname, field, value):
        if(not secname in self.sectiontable):
            if(not secname in self.default_sections):
                print "invaid section name: %s" % secname
                return
            self.assign_section(secname, self.get_defaults(secname))
        if(not field in self.dsecname2idx):
            print "invalid field name"
            return
        self.sectiontable[secname][self.dsecname2idx[field]] = value

    def check_section_exist(self, name):
        if(name in self.sectiontable):
            return True
        else:
            return False

    def remove_section(self, name):
        if(name == None or len(name) == 0):
            print "invalid section name"
            return False
        if(not name in self.sectiontable):
            print "section %s is not in section table" % name
            return False
        del self.sectiontable[name]

    def assign_section(self, name, metalist=None):
        if(metalist == None):
            metalist = self.get_defaults(name)
        if(name == None or len(name) == 0):
            print "invalid section name"
            return False
        if(name in self.sectiontable):
            #print "section name %s already exists" % name
            return False
        stridx = self._expand_shstrtab(name)
        #print "idx: %d" % stridx
        if(isinstance(metalist, dict)):
            self.sectiontable[name] = metalist
            self.sectiontable[name][sectiontab.s_str_idx] = stridx
        elif(isinstance(metalist, list)):
            self.sectiontable[name] = dict()
            self.sectiontable[name][sectiontab.s_str_idx] = stridx
            self.sectiontable[name][sectiontab.s_type   ] = metalist[1]
            self.sectiontable[name][sectiontab.s_flags  ] = metalist[2]
            self.sectiontable[name][sectiontab.s_vaddr  ] = metalist[3]
            self.sectiontable[name][sectiontab.s_offset ] = metalist[4]
            self.sectiontable[name][sectiontab.s_size   ] = metalist[5]
            self.sectiontable[name][sectiontab.s_link   ] = metalist[6]
            self.sectiontable[name][sectiontab.s_info   ] = metalist[7]
            self.sectiontable[name][sectiontab.s_align  ] = metalist[8]
            self.sectiontable[name][sectiontab.s_entsize] = metalist[9]
        else:
            raise
        return True

    def get_last_section_in_mem(self):
        temptab = {k : v for k, v in self.sectiontable.iteritems() if v[sectiontab.s_vaddr] != 0}
        temptab = sorted(temptab.items(), key=lambda x: x[1][sectiontab.s_vaddr])
        return temptab[-1][0]

    def get_elf_file_end(self):
        temptab = {k : v for k, v in self.sectiontable.iteritems() if v[sectiontab.s_offset] != 0}
        temptab = sorted(temptab.items(), key=lambda x: x[1][sectiontab.s_offset])
        print "last section name: %s" % temptab[-1][0]
        if(temptab[-1][0] == ".shstrtab"):
            return temptab[-2][1][sectiontab.s_offset] + temptab[-2][1][sectiontab.s_size]
        return temptab[-1][1][sectiontab.s_offset] + temptab[-1][1][sectiontab.s_size]

    def get_updated_section_itemlist(self):
        temptab1 = {k : v for k, v in self.sectiontable.iteritems() if v[sectiontab.s_vaddr] != 0}
        temptab1 = sorted(temptab1.items(), key=lambda x: x[1][sectiontab.s_offset])
        temptab2 = {k : v for k, v in self.sectiontable.iteritems() if v[sectiontab.s_vaddr] == 0}
        temptab2 = sorted(temptab2.items(), key=lambda x: x[1][sectiontab.s_offset])
        temptab1 = temptab1 + temptab2
        secidx = 1
        self.secname2idx["NULL"] = 0
        for item in temptab1:
            secname = item[0]
            self.secname2idx[secname] = secidx
            secidx += 1
        return temptab1

    def write2disk(self, binname=None):
        if(binname == None):
            binname = self.filename
        #write string table
        print self.stringtable
        self.strtaboffset = self.get_elf_file_end()
        for offset in self.stringtable:
            if(offset == 0):
                continue
            self.write_str(binname, self.strtaboffset + offset, self.stringtable[offset])
        print self.stringtable
        #write section table
        self.sectaboffset = self.compute_align(self.strtaboffset + self.stringtable[0], self.sectabentsz)
        print "string table offset: %x" % self.strtaboffset
        print "section table offset: %x" % self.sectaboffset

        offset = self.sectaboffset
        secnum = len(self.sectiontable) + 1
        self.write_single(binname, elfhdr.e_sechdr_ent_cnt, secnum, elfhdr.dsize[elfhdr.e_sechdr_ent_cnt])
        self.write_single(binname, elfhdr.e_sechdr_offset, offset, elfhdr.dsize[elfhdr.e_sechdr_offset])
        secindex    = 1
        #write the first null section
        print "string table offset: %x" % self.strtaboffset
        print "section table offset: %x" % self.sectaboffset
        print "section size: %x" % self.sectabentsz
        print "try to zero out %d" % offset
        print "try to zero out %x" % offset
        self.write_zeros(binname, offset, self.sectabentsz)
        offset += self.sectabentsz
        #write the rest of the sections
        for item in self.get_updated_section_itemlist():
            secname = item[0]
            section = item[1]
            for attribute in section:
                if(attribute == self.sectiontab.s_link and
                   isinstance(section[attribute], basestring)):
                    value = self.secname2idx[section[attribute]]
                else:
                    value = section[attribute]
                self.write_single(binname, offset + attribute, value,  sectiontab.dsize[attribute])
            if(secname == ".shstrtab"):
                self.write_single(binname, offset + sectiontab.s_offset,
                                  self.strtaboffset,
                                  sectiontab.dsize[sectiontab.s_offset])
                self.write_single(binname, offset + sectiontab.s_size,
                                  self.stringtable[0],
                                  sectiontab.dsize[sectiontab.s_size])
                self.write_single(binname, elfhdr.e_sechdr_strtab, secindex,
                                  elfhdr.dsize[elfhdr.e_sechdr_strtab])
            offset += self.sectabentsz
            secindex = secindex + 1
        #update the shstrtab section offset

    def check_if_in_gap(self, addr):
        for secname in self.sectiontable:
            if(secname == '.tbss' or secname == '.bss'):
                continue
            section = self.sectiontable[secname]
            secaddr = section[sectiontab.s_vaddr]
            secsize = section[sectiontab.s_size]
            if(addr >= secaddr and addr < secaddr + secsize):
                print "False:%s %x, %x, %x" % (secname, addr, secaddr, secaddr+secsize)
                return False
        return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, help="file for reading section table",
                        required=True)
    args = parser.parse_args()
    st   = section_table(args.file)
    st.current_file = st.gen_tempfile(st.current_file)
    #st.duplicate_section(".gnu.hash", ".gnu.hash_new")
    #st.relocate_section(".gnu.hash")
    #st.relocate_section(".dynsym")
    #st.relocate_section(".dynstr")
    #print st.current_file
    #st.save_sectiontable()
    st.insert_new_section(".mytext", "/bin/ls", st.current_file)
    st.save_sectiontable()
    print st.current_file
if __name__ == "__main__":
	main()
