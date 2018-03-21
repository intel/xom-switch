#!/usr/bin/python

from base_instrumentor import *
from section_basic import *

# Each instrument_scheduler is responsible for one segment for all sections
# that instrumentors (or base_instrumentors, section_relocators) generate. Each
# instrumentor only generate one section.
class instrument_scheduler(elf_basic):
    def __init__(self):
        self.linstrumentors = []
        self.dinstrumentors = dict()
        self.new_segment = None
    def register_instrumentor(self, instrumentor):
        self.linstrumentors.append(instrumentor)
        self.dinstrumentors[instrumentor.get_name()] =instrumentor

    def perform_instrumentation(self):
        for instrumentor in self.linstrumentors:
            instrumentor.set_new_segment_info(self.new_segment)
            instrumentor.perform_instrumentation()
            self.new_segment = instrumentor.get_new_segment_info()

    def set_current_file(self, binname):
        self.linstrumentors[0].set_current_file(binname)

    def get_current_file(self):
        return self.new_segment['current_file']

    def set_binname(self, binname):
        self.linstrumentors[0].set_binname(binname)

class instrumentor(base_instrumentor):

    INDIRECT_BRANCH = 0
    DIRECT_BRANCH   = 1
    DIRECT_BRANCH_BOTH_EDGE   = 1

    def __init__(self, name, binname, secname, align=0x1000):
        super(instrumentor, self).__init__(binname)
        self.instrumentor_name = name
        self.inject_secname = secname
        self.inject_secalign = align
        self.generate_instrument_files()

    def generate_instrument_files(self):
        self.inject_file = self.get_tempfile()
        self.asm_file = self.inject_file + ".S"
        self.obj_file = self.inject_file + ".o"

    def compile_inject_instrument_file(self, asmfile, objfile, injectfile,
                                       secname, align):
        cmd = "gcc -c %s -o %s " % (asmfile, objfile)
        os.system(cmd)
        self.extract_data(objfile, '.text', injectfile)
        self.add_instrumentation_data(self.get_current_file(), injectfile, secname, align)


    #USER should implement
    def generate_instrumentation(self, filename):
        #sample:
        f = open(filename, "w")
        f.write("nop\n")
        f.write("nop\n")
        f.close()
        pass

    def intercept_code_pointers(self, asmfile, mapping):
        f = open(asmfile, "w")
        for offset in mapping:
            vfstr =  "_ORIGPTR_%x: jmp _ORIGLOC_%x\n_ORIGNEXT_%x:\n" % \
                    (offset, offset, offset)
            f.write(vfstr)
        f.write("nop\n")
        f.close()

    #USER should implement
    def patch_relocation(self, filename, objfile=None):
        pass

    #This is the function that trigger instrumentation
    def perform_instrumentation(self):
        self.generate_instrumentation(self.asm_file)
        self.compile_inject_instrument_file(self.asm_file,
                                            self.obj_file,
                                            self.inject_file,
                                            self.inject_secname,
                                            self.inject_secalign)
        self.patch_relocation(self.obj_file)

    #Utility APIs start from here
    #FIXME: change all segment base to section base
    def patch_forward_edge(self, type, mapping):
        symtab = self.read_obj_symtable(self.obj_file)
        seg_base = self.get_section_info(self.get_current_file(),
                                         self.inject_secname, 'addr')
        if(type == instrumentor.INDIRECT_BRANCH):
            regex = re.compile(r'_ORIGPTR_(\S+)\s*')
            for idx in symtab:
                sym = symtab[idx]
                m = regex.match(sym['name'])
                if(m == None):
                    continue
                offset = int(m.group(1), 16)
                value  = mapping[offset]
                raw_value = self.read_ptr(self.get_current_file(), offset)
                if(raw_value != value):
                    continue
                new_cptr =seg_base + sym['offset']
                print "updating cptr at offset: %x to value: %x" % \
                       (offset, new_cptr)
                self.write_ptr(self.get_current_file(), offset, new_cptr)
        else:
            pass

    def patch_backward_edge(self, type, mapping):
        symtab        = self.read_obj_symtable(self.obj_file)
        reloctable    = self.read_obj_reloctable(self.obj_file)
        newseg_offset = self.get_section_info(self.get_current_file(),
                                              self.inject_secname, 'offset')
        print "new seg offset: %x" % newseg_offset
        print "new seg vaddr : %x" % self.get_new_segment_base()
        if(type == instrumentor.INDIRECT_BRANCH):
            rreloc = re.compile(r'_ORIGLOC_(\S+)')
            rsym   = re.compile(r'_ORIGNEXT_(\S+)')
            for idx in reloctable:
                reloc = reloctable[idx]
                m = rreloc.match(reloc['name'])
                if(m == None):
                    continue
                offset = int(m.group(1), 16)
                ssym = "_ORIGNEXT_%x" % offset
                sym = symtab[ssym]
                vaddr  = mapping[offset]
                if(sym == None):
                    print "cannot find symbol: %s" % sym
                    sys.exit(1)
                value = vaddr - (sym['offset']
                              + self.get_section_info(self.get_current_file(),
                                                      self.inject_secname,
                                                      'addr'))
                print "original value %x\t sym offset %x, new seg base %x" % \
                       (vaddr, sym['offset'], self.get_new_segment_base())
                self.write_int(self.get_current_file(),
                               reloc['offset'] + newseg_offset,
                               value)
        else:
            pass

#relocate section to the bottom of the target ELF
class section_relocator(base_instrumentor):
    def __init__(self, name, binname, secname, align=0x1000, secperm=None):
        super(section_relocator, self).__init__(binname)
        self.instrumentor_name = name
        self.secname           = secname
        self.secalign          = align
        if(secperm==None):
            secperm = self.get_section_info(binname, secname,
                                            sectiontab.s_flags)
        self.new_section_perm  = secperm

    # Reimplement insert_new_section in base_instrumentor
    def insert_new_section(self, binname, secname, filename, align, perm):
        self.new_sections.append(secname)

    def patch_relocation(self, secname):
        base_addr   = self.get_section_info(self.get_current_file(),
                                            self.secname, 'addr')
        print "base addr of section %s is 0x%x" % (secname, base_addr)
        if(secname == '.dynamic'):
            base_offset = self.get_section_info(self.get_current_file(),
                                                self.secname, 'offset')
            self.modify_phdrtab_info(self.get_current_file(), phdr.PT_DYNAMIC,
                                     phdr.p_offset, base_offset)
            self.modify_phdrtab_info(self.get_current_file(), phdr.PT_DYNAMIC,
                                     phdr.p_vaddr, base_addr)
            self.modify_phdrtab_info(self.get_current_file(), phdr.PT_DYNAMIC,
                                     phdr.p_paddr, base_addr)

        elif(secname == '.rel.dyn'):
            print "updating dynamic option DT_REL"
            self.update_dynamic_option(self.get_current_file(),
                                       dynamictab.DT_REL, base_addr)
        elif(secname == '.rela.dyn'):
            print "updating dynamic option .rela.dyn"
            self.update_dynamic_option(self.get_current_file(),
                                       dynamictab.DT_RELA, base_addr)
        else:
            print "updating dynamic option for section %s" % secname
            self.update_dynamic_option(self.get_current_file(),
                                       dynamictab.dreversemap[secname],
                                       base_addr)


    #This is the function that trigger instrumentation
    def perform_instrumentation(self):
        if(self.validate_sectionlist(self.filename, [self.secname]) == False):
            print "sectionlist contain invaid section"
            raise

        sectiontable = section_table(self.get_current_file())
        sectiontable.relocate_section(self.secname)
        sectiontable.write2disk()
        self.patch_relocation(self.secname)
        res = self.add_instrumentation_data(self.get_current_file(),
                                            None,
                                            self.secname,
                                            self.secalign,
                                            self.new_section_perm)
        if(res == None):
            print "inserting instrumentation data failed"
            raise


# Deprecated for now

class section_duplicator(base_instrumentor):
    def __init__(self, name, binname, srcsection, dstsecname, align=0x1000, perm=0x05):
        super(section_duplicator, self).__init__(binname)
        self.instrumentor_name = name
        self.inject_secname = dstsecname
        self.inject_secalign = align
        self.src_section = srcsection
        self.new_section_perm =  perm
        self.generate_instrument_files()

    def generate_instrument_files(self):
        self.inject_file = self.get_tempfile()

    def patch_relocation(self, secname):
        if(secname == '.dynamic'):
            base_addr   = self.get_section_info(self.get_current_file(),
                                                self.inject_secname, 'addr')
            base_offset = self.get_section_info(self.get_current_file(),
                                                self.inject_secname, 'offset')
            self.modify_phdrtab_info(self.get_current_file(), phdr.PT_DYNAMIC,
                                     phdr.p_offset, base_offset)
            self.modify_phdrtab_info(self.get_current_file(), phdr.PT_DYNAMIC,
                                     phdr.p_vaddr, base_addr)
            self.modify_phdrtab_info(self.get_current_file(), phdr.PT_DYNAMIC,
                                     phdr.p_paddr, base_addr)
        elif(secname == '.rel.dyn'):
            base_addr   = self.get_section_info(self.get_current_file(),
                                                self.inject_secname, 'addr')
            print "updateing dynamic option DT_REL"
            print "current file is %s" % self.get_current_file()
            print "base address: %x" % base_addr
            self.update_dynamic_option(self.get_current_file(),
                                       dynamictab.DT_REL, base_addr)
        elif(secname == '.rela.dyn'):
            base_addr   = self.get_section_info(self.get_current_file(),
                                                self.inject_secname, 'addr')
            print "updateing dynamic option"
            self.update_dynamic_option(self.get_current_file(),
                                       dynamictab.DT_RELA, base_addr)
        else:

            base_addr = self.get_section_info(self.get_current_file(),
                                              self.inject_secname, 'addr')
            print "updateing dynamic option"
            self.update_dynamic_option(self.get_current_file(),
                                       dynamictab.dreversemap[secname],
                                       base_addr)
            print "reaching here"
            print "base_addr %x"%base_addr
            #sys.exit(1)


    #This is the function that trigger instrumentation
    def perform_instrumentation(self):
        if(self.validate_sectionlist(self.filename, [self.src_section]) == False):
            print "sectionlist contain invaid section"
            return None
        self.extract_data(self.filename, self.src_section, self.inject_file)
        res = self.add_instrumentation_data(self.get_current_file(),
                                            self.inject_file,
                                            self.inject_secname,
                                            self.inject_secalign,
                                            self.new_section_perm)
        if(res == None):
            raise
            return
        self.patch_relocation(self.src_section)

# Instrument_organizer is responsible to help successfullying injecting
# multiple segments into one ELF file. Since each scheduler is responsible for
# one segment, instrument_organizer observes the ELF binary layout to see if
# relocating critical sections such as .gnu.hash, .dynsym or .dynstr is needed
# to extend PHDR.
class instrument_organizer(base_instrumentor):
    def __init__(self, binname):
        super(instrument_organizer, self).__init__(binname)
        self.lschedulers = []

    def register_scheduler(self, scheduler):
        self.lschedulers.append(scheduler)

    def check_free_space_after_phdr(self):
        gap = self.compute_gap_to_extend_phdr(self.filename)
        phdr_size = self.get_elfhdr_info(self.filename, "Size of program headers:");
        return gap/phdr_size

    def get_sections_to_relocate(self, dynlist, segnum):
        seclist = []
        if(len(dynlist) == 0):
            raise
        if(segnum <=0):
            return seclist

        phdr_size = self.get_elfhdr_info(self.filename, "Size of program headers:");
        size_need = phdr_size * segnum
        for dyn in dynlist:
            if(size_need <= 0):
                break
            secname = dynamictab.dnamemap[dyn[0]]
            if(dynamictab.dtypemap[dyn[0]] != 'data'):
                print "we truly don't have enough space, since we cannot move"\
                      " code for now"
                raise
            seclist.append(secname)
            size = self.get_section_info(self.filename, secname,
                                         sectiontab.s_size)
            size_need -= size
        return seclist

    def extend_phdr_on_number(self, extendnum):
        if(extendnum > 0):
            return self.extend_phdr_on_demand(extendnum)
        return False

    def extend_phdr_on_demand(self, extendnum=0):
        segnum = len(self.lschedulers)
        freeseg = 0
        # Check if there are enough space in PHDR.
        # Step1: skip checking existence of "NOTE" segment.
        if(extendnum == 0):
            segment_offset = self.get_segment_offset_in_phdr(self.filename,
                                                             phdr.PT_NOTE, 0)
            if(segment_offset != None):
                freeseg = 1
            # Step2: check space after phdr.
            freeseg += self.check_free_space_after_phdr()
            print "=== freeseg: %d" % freeseg
            if(freeseg >= segnum):
                return False
            print "=== insufficient space to extend phdr, relocating sections"
            print "=== we need space for %d phdr entries" % (extendnum)
            extendnum = segnum - freeseg

        dynlist = self.get_dynamic_sections_info(self.filename)
        # Step3: get the critical sections.
        # Need space for one extra phdr entry to place relocated sections.
        # That's why we need 'extendnum + 1' number of extra segments.
        seclist = self.get_sections_to_relocate(dynlist, extendnum + 1)
        print "need to relocating these sections:"
        print seclist
        # Step4: relocate this section
        sc = instrument_scheduler()
        for secname in seclist:
            sr = section_relocator("%s_relocator"%secname,
                                   self.filename, secname)
            sc.register_instrumentor(sr)
        sc.perform_instrumentation()
        # Step5: setup the output file for the 1st scheduler and to itself in
        # case if there is no scheduler.
        self.set_current_file(sc.get_current_file())
        if(len(self.lschedulers) > 0):
            self.lschedulers[0].set_current_file(sc.get_current_file())
        print sr.get_current_file()
        return True

    def perform_instrumentation(self):
        self.extend_phdr_on_demand()
        total = len(self.lschedulers)
        for idx, scheduler in enumerate(self.lschedulers):
            scheduler.perform_instrumentation()
            if(idx < total - 1):
                self.lschedulers[idx + 1]\
                    .set_current_file(scheduler.get_current_file())
        if(total > 0):
            self.set_current_file(self.lschedulers[-1].get_current_file())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, help="file to instrument",
                        required=True)
    args = parser.parse_args()

    scheduler = instrument_scheduler()
    scheduler2 = instrument_scheduler()
    scheduler3 = instrument_scheduler()

    organizer = instrument_organizer(args.file)
    organizer.register_scheduler(scheduler)
    organizer.register_scheduler(scheduler2)
    organizer.register_scheduler(scheduler3)

    it1 = instrumentor('mytest1', args.file, '.mytext1')
    it2 = instrumentor('mytest2', args.file, '.mytext2')
    it3 = instrumentor('mytest3', args.file, '.mytext3')
    scheduler.register_instrumentor(it1)
    scheduler.register_instrumentor(it2)
    scheduler.register_instrumentor(it3)

    it4 = instrumentor('mytest4', args.file, '.mytext4')
    it5 = instrumentor('mytest5', args.file, '.mytext5')
    it6 = instrumentor('mytest6', args.file, '.mytext6')
    scheduler2.register_instrumentor(it4)
    scheduler2.register_instrumentor(it5)
    scheduler2.register_instrumentor(it6)

    it7 = instrumentor('mytest7', args.file, '.mytext7')
    it8 = instrumentor('mytest8', args.file, '.mytext8')
    it9 = instrumentor('mytest9', args.file, '.mytext9')
    scheduler3.register_instrumentor(it7)
    scheduler3.register_instrumentor(it8)
    scheduler3.register_instrumentor(it9)

    organizer.perform_instrumentation()
    print organizer.get_current_file()
    #print scheduler2.get_current_file()
if __name__ == "__main__":
	main()
