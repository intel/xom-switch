#!/usr/bin/python
import os,sys,inspect,platform
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
prdir = os.path.dirname(currentdir)
sys.path.insert(0,prdir)

from instrumentor      import *

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, help="file to instrument",
                        required=True)
    parser.add_argument("-o", "--output", type=str, help="output location",
                        required=False)
    args = parser.parse_args()
    organizer = instrument_organizer(args.file)
    (exebegin, exeend) = organizer.get_exec_memory_range(organizer.get_current_file())
    print "exebegin: %d" % exebegin
    print "exeend: %d" % exeend
    segbegin = organizer.get_segment_info(organizer.get_current_file(), "LOAD", 0, 'vaddr')
    segsize  = organizer.get_segment_info(organizer.get_current_file(), "LOAD", 0, 'memsize')
    segend   = organizer.compute_align_up(segbegin + segsize, 4096)
    print "segbegin: %d" % segbegin
    print "segend: %d" % segend

    assert(segbegin < exebegin)
    assert(exeend < segend)
    extendnum = 5
    seglist = []
    ideallist = []
    ideallist.append([segbegin, exebegin, phdr.PF_R])
    ideallist.append([exebegin, exeend, phdr.PF_X])
    ideallist.append([exeend, segend, phdr.PF_R])
    curloc  = ideallist[0][0]
    curperm = ideallist[0][2]
    extendnum = 0
    idx = 0
    print "idealllist: "
    print ideallist
    while(curloc < ideallist[-1][1]):
        if(curloc == ideallist[idx][0]):
            end = organizer.compute_align_down(ideallist[idx][1], 4096)
            if(end > curloc):
                seglist.append([ideallist[idx][0], end, ideallist[idx][2]])
                curloc = end
                curperm = ideallist[idx][2]
            else:
                seglist.append([ideallist[idx][0], ideallist[idx][0] + 4096, ideallist[idx][2]|ideallist[idx +1][2]])
                curloc = ideallist[idx][0] + 4096
                curperm = ideallist[idx +1][2]
        elif(curloc < ideallist[idx][0]):
            end = organizer.compute_align_up(ideallist[idx][0], 4096)
            seglist.append([curloc, end, curperm|ideallist[idx][2]])
            curloc = end
        elif(curloc > ideallist[idx][0] and curloc < ideallist[idx][1]):
            curperm = ideallist[idx][2]
            end = organizer.compute_align_down(ideallist[idx][1], 4096)
            print "==end: %d" %end
            print "==curloc: %d" %curloc
            print "==idx: %d" %idx
            print "==%d" % ideallist[idx][1]
            if(end > curloc):
                seglist.append([curloc, end, ideallist[idx][2]])
                curloc = end
                curperm = ideallist[idx][2]
            else:
                print "end: %d" %end
                print "curloc: %d" %curloc
                print "idx: %d" %idx
                seglist.append([curloc, curloc + 4096, ideallist[idx][2]|ideallist[idx+1][2]])
                curloc = curloc + 4096
                curperm = -1
        if(curloc >= ideallist[idx][1]):
            idx += 1
        print seglist
    print seglist
    if(len(seglist) <= 1):
        print "The binary is too small in size or everything is tightly together"
        print "In this situation, we cannot do anything for MPK enabling"
        return
    extendnum = len(seglist) + 1
    # check the size of metadata
    # Split the code segment into three segments
    organizer.extend_phdr_on_demand(extendnum)

    #f = organizer.get_current_file()
    #vr = seglist[0][0]
    #pr = vr
    #off = organizer.convert_vma_to_offset2(f, vr)
    #fsz = seglist[0][1] - seglist[0][0]
    #msz = fsz
    #organizer.modify_phdrtab_info(f, phdr.PT_LOAD, phdr.p_vaddr, vr, 0)
    #organizer.modify_phdrtab_info(f, phdr.PT_LOAD, phdr.p_paddr, pr, 0)
    #organizer.modify_phdrtab_info(f, phdr.PT_LOAD, phdr.p_offset, off, 0)
    #organizer.modify_phdrtab_info(f, phdr.PT_LOAD, phdr.p_filesz, fsz, 0)
    #organizer.modify_phdrtab_info(f, phdr.PT_LOAD, phdr.p_memsz, msz, 0)
    #organizer.modify_phdrtab_info(f, phdr.PT_LOAD, phdr.p_flags, seglist[0][2], 0)
    #for seg in seglist[1:]:
    for seg in seglist:
        vr = seg[0]
        pr = vr
        off = organizer.convert_vma_to_offset2(organizer.get_current_file(), vr)
        fsz = seg[1] - seg[0]
        msz = fsz
        organizer.insert_new_phdr_entry(organizer.get_current_file(),
                                        offset = off,
                                        vaddr  = vr,
                                        paddr  = pr,
                                        fsize  = fsz,
                                        msize = msz,
                                        flags = seg[2]
                                        )

    print seglist
    print organizer.get_current_file()
    if(args.output == None):
        return
    bname = os.path.basename(args.file)
    if(os.path.isdir(args.output)):
        os.system("mv %s %s" % (organizer.get_current_file(),
                                os.path.join(args.output, bname)))
    else:
        os.system("mv %s %s" % (organizer.get_current_file(), args.output))

if __name__ == "__main__":
	main()
