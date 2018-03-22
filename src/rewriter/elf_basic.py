#!/usr/bin/python
from __future__ import with_statement
from struct import *
from operator import itemgetter
#from __future__ import with_statement
import re
import os
import sys
import math
import random
import string
import ctypes
import argparse
from elf_helper import *

translate_dynsym=1
#elf options
ET_NONE=0
ET_REL=1
ET_EXEC=2
ET_DYN=3
ET_CORE=4
#elf link options:
DYNAMIC_LINKED=0;
STATIC_LINKED=1;
#option in dynamic section
DT_NULL=0
DT_NEEDED=1
DT_PLTRELSZ=2
DT_PLTGOT=3
DT_HASH=4
DT_STRTAB=5
DT_SYMTAB=6
DT_RELA=7
DT_RELASZ=8
DT_RELAENT=9
DT_STRSZ=10
DT_SYMENT=11
DT_INIT=12
DT_FINI=13
DT_SONAME=14
DT_RPATH=15
DT_SYMBOLIC=16
DT_REL=17
DT_RELSZ=18
DT_RELENT=19
DT_PLTREL=20
DT_DEBUG=21
DT_TEXTREL=22
DT_JMPREL=23
DT_BIND_NOW=24
DT_INIT_ARRAY=25
DT_FINI_ARRAY=26
DT_INIT_ARRAYSZ=27
DT_FINI_ARRAYSZ=28
DT_RUNPATH=29
DT_FLAGS=30
DT_ENCODING=32
DT_PREINIT_ARRAY=32
DT_PREINIT_ARRAYSZ=33
DT_NUM=34
DT_LOOS=0x6000000d
DT_HIOS=0x6ffff000
DT_LOPROC=0x70000000
DT_HIPROC=0x7fffffff
DT_GNU_HASH=0x6ffffef5
DT_VERSYM=0x6ffffff0
DT_VERDEF=0x6ffffffc
DT_VERNEED=0x6ffffffe
DT_VERNEEDNUM=0x6fffffff

class arch(object):
        INT_SIZE   = 4
        PTR_SIZE   = 4
        SHORT_SIZE = 2
        CHAR_SIZE  = 1
        def __init__(self):
            arch.INT_SIZE   = 4
            arch.PTR_SIZE   = 4
            arch.SHORT_SIZE = 2
            arch.CHAR_SIZE  = 1


class dtflags(object):
    DF_ORIGIN	  = 0x00000001
    DF_SYMBOLIC	  = 0x00000002
    DF_TEXTREL	  = 0x00000004
    DF_BIND_NOW	  = 0x00000008
    DF_STATIC_TLS =	0x00000010

class dynamictab(object):
    DT_NULL=0
    DT_NEEDED=1
    DT_PLTRELSZ=2
    DT_PLTGOT=3
    DT_HASH=4
    DT_STRTAB=5
    DT_SYMTAB=6
    DT_RELA=7
    DT_RELASZ=8
    DT_RELAENT=9
    DT_STRSZ=10
    DT_SYMENT=11
    DT_INIT=12
    DT_FINI=13
    DT_SONAME=14
    DT_RPATH=15
    DT_SYMBOLIC=16
    DT_REL=17
    DT_RELSZ=18
    DT_RELENT=19
    DT_PLTREL=20
    DT_DEBUG=21
    DT_TEXTREL=22
    DT_JMPREL=23
    DT_BIND_NOW=24
    DT_INIT_ARRAY=25
    DT_FINI_ARRAY=26
    DT_INIT_ARRAYSZ=27
    DT_FINI_ARRAYSZ=28
    DT_RUNPATH=29
    DT_FLAGS=30
    DT_ENCODING=32
    DT_PREINIT_ARRAY=32
    DT_PREINIT_ARRAYSZ=33
    DT_NUM=34
    DT_LOOS=0x6000000d
    DT_HIOS=0x6ffff000
    DT_LOPROC=0x70000000
    DT_HIPROC=0x7fffffff
    DT_GNU_HASH=0x6ffffef5
    DT_VERSYM =0x6ffffff0
    DT_VERDEF =0x6ffffffc
    DT_VERNEED=0x6ffffffe
    DT_VERNEEDNUM=0x6fffffff
    dvaluemap   = dict()
    dnamemap    = dict()
    dtypemap    = dict()
    dreversemap = dict()
    def __init__(self):
        dynamictab.dvaluemap[dynamictab.DT_PLTGOT]        = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_HASH]          = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_STRTAB]        = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_SYMTAB]        = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_RELA]          = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_INIT]          = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_FINI]          = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_REL]           = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_DEBUG]         = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_TEXTREL]       = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_JMPREL]        = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_INIT_ARRAY]    = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_FINI_ARRAY]    = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_RUNPATH]       = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_PREINIT_ARRAY] = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_GNU_HASH]      = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_VERSYM ]       = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_VERDEF ]       = 'addr'
        dynamictab.dvaluemap[dynamictab.DT_VERNEED]       = 'addr'

        dynamictab.dnamemap[dynamictab.DT_PLTGOT]        = '.got.plt'
        dynamictab.dnamemap[dynamictab.DT_HASH]          = '.hash'
        dynamictab.dnamemap[dynamictab.DT_STRTAB]        = '.dynstr'
        dynamictab.dnamemap[dynamictab.DT_SYMTAB]        = '.dynsym'
        dynamictab.dnamemap[dynamictab.DT_RELA]          = '.rela.dyn'
        dynamictab.dnamemap[dynamictab.DT_INIT]          = '.init'
        dynamictab.dnamemap[dynamictab.DT_FINI]          = '.fini'
        dynamictab.dnamemap[dynamictab.DT_REL]           = '.rel.dyn'
        dynamictab.dnamemap[dynamictab.DT_JMPREL]        = '.rel.plt' #may be .rela.plt, depends on DT_PLTREL
        dynamictab.dnamemap[dynamictab.DT_INIT_ARRAY]    = '.init_array'
        dynamictab.dnamemap[dynamictab.DT_FINI_ARRAY]    = '.fini_array'
        dynamictab.dnamemap[dynamictab.DT_PREINIT_ARRAY] = '.preinit_array'
        dynamictab.dnamemap[dynamictab.DT_GNU_HASH]      = '.gnu.hash'
        dynamictab.dnamemap[dynamictab.DT_VERSYM ]       = '.gnu.version'
        dynamictab.dnamemap[dynamictab.DT_VERDEF ]       = '.gnu.version_d'
        dynamictab.dnamemap[dynamictab.DT_VERNEED]       = '.gnu.version_r'
        dynamictab.dnamemap[dynamictab.DT_RUNPATH]       = ''
        dynamictab.dnamemap[dynamictab.DT_DEBUG]         = ''
        dynamictab.dnamemap[dynamictab.DT_TEXTREL]       = '.rel.text'

        dynamictab.dtypemap[dynamictab.DT_PLTGOT]        = 'data'
        dynamictab.dtypemap[dynamictab.DT_HASH]          = 'data'
        dynamictab.dtypemap[dynamictab.DT_STRTAB]        = 'data'
        dynamictab.dtypemap[dynamictab.DT_SYMTAB]        = 'data'
        dynamictab.dtypemap[dynamictab.DT_RELA]          = 'data'
        dynamictab.dtypemap[dynamictab.DT_INIT]          = 'code'
        dynamictab.dtypemap[dynamictab.DT_FINI]          = 'code'
        dynamictab.dtypemap[dynamictab.DT_REL]           = 'data'
        dynamictab.dtypemap[dynamictab.DT_JMPREL]        = 'data' #may be .rela.plt, depends on DT_PLTREL
        dynamictab.dtypemap[dynamictab.DT_INIT_ARRAY]    = 'data'
        dynamictab.dtypemap[dynamictab.DT_FINI_ARRAY]    = 'data'
        dynamictab.dtypemap[dynamictab.DT_PREINIT_ARRAY] = 'data'
        dynamictab.dtypemap[dynamictab.DT_GNU_HASH]      = 'data'
        dynamictab.dtypemap[dynamictab.DT_VERSYM ]       = 'data'
        dynamictab.dtypemap[dynamictab.DT_VERDEF ]       = 'data'
        dynamictab.dtypemap[dynamictab.DT_VERNEED]       = 'data'
        dynamictab.dtypemap[dynamictab.DT_RUNPATH]       = 'data'
        dynamictab.dtypemap[dynamictab.DT_DEBUG]         = 'data'
        dynamictab.dtypemap[dynamictab.DT_TEXTREL]       = 'data'



        dynamictab.dreversemap['.got.plt']               = dynamictab.DT_PLTGOT
        dynamictab.dreversemap['.hash']                  = dynamictab.DT_HASH
        dynamictab.dreversemap['.dynstr']                = dynamictab.DT_STRTAB
        dynamictab.dreversemap['.dynsym']                = dynamictab.DT_SYMTAB
        dynamictab.dreversemap['.rela.dyn']              = dynamictab.DT_RELA
        dynamictab.dreversemap['.init']                  = dynamictab.DT_INIT
        dynamictab.dreversemap['.fini']                  = dynamictab.DT_FINI
        dynamictab.dreversemap['.rel.dyn']               = dynamictab.DT_REL
        dynamictab.dreversemap['.rel.plt' ]              = dynamictab.DT_JMPREL
        dynamictab.dreversemap['.rela.plt' ]             = dynamictab.DT_JMPREL
        dynamictab.dreversemap['.init_array']            = dynamictab.DT_INIT_ARRAY
        dynamictab.dreversemap['.fini_array']            = dynamictab.DT_FINI_ARRAY
        dynamictab.dreversemap['.preinit_array']         = dynamictab.DT_PREINIT_ARRAY
        dynamictab.dreversemap['.gnu.hash']              = dynamictab.DT_GNU_HASH
        dynamictab.dreversemap['.gnu.version']           = dynamictab.DT_VERSYM
        dynamictab.dreversemap['.gnu.version_d']         = dynamictab.DT_VERDEF
        dynamictab.dreversemap['.gnu.version_r']         = dynamictab.DT_VERNEED

    @classmethod
    def isdata(dynkey):
        if(dynamictab.dtypemap[dynkey] == 'data'):
            return True
        return False

    @classmethod
    def isaddr(cls, dt):
        if(dt in dynamictab.dvaluemap and dynamictab.dvaluemap[dt] == 'addr'):
            return True
        else:
            return False
"""
    ELF Header Format:
        Field             Size        Offset
        magic:           16bytes        0
        type:            2 bytes        16
        machine:         2 bytes        18
        version:         4 bytes        20
        entry:           4 bytes        24
        phdr_offset:     4 bytes        28
        sechdr_offset:   4 bytes        32
        flags:           4 bytes        36
        elfhdr_size:     2 bytes        40
        phdr_ent_size:   2 bytes        42
        phdr_ent_cnt:    2 bytes        44
        sechdr_ent_size: 2 bytes        46
        sechdr_ent_cnt:  2 bytes        48
        sechdr_strtab:   2 bytes        50
"""
class elfhdr(object):
    e_magic           = 0
    e_class           = 0 # within the magic info
    e_type            = 0
    e_machine         = 0
    e_version         = 0
    e_entry           = 0
    e_phdr_offset     = 0
    e_sechdr_offset   = 0
    e_flags           = 0
    e_elfhdr_size     = 0
    e_phdr_ent_size   = 0
    e_phdr_ent_cnt    = 0
    e_sechdr_ent_size = 0
    e_sechdr_ent_cnt  = 0
    e_sechdr_strtab   = 0
    dsize             = dict()
    def __init__(self, ptrsize=4):
        elfhdr.e_magic           =  0
        elfhdr.e_class           =  4
        elfhdr.e_type            =  16
        elfhdr.e_machine         =  18
        elfhdr.e_version         =  20
        elfhdr.e_entry           =  24
        elfhdr.e_phdr_offset     =  elfhdr.e_entry + ptrsize
        elfhdr.e_sechdr_offset   =  elfhdr.e_phdr_offset +  ptrsize
        elfhdr.e_flags           =  elfhdr.e_sechdr_offset + ptrsize
        elfhdr.e_elfhdr_size     =  elfhdr.e_flags + 4
        elfhdr.e_phdr_ent_size   =  elfhdr.e_elfhdr_size + 2
        elfhdr.e_phdr_ent_cnt    =  elfhdr.e_phdr_ent_size + 2
        elfhdr.e_sechdr_ent_size =  elfhdr.e_phdr_ent_cnt + 2
        elfhdr.e_sechdr_ent_cnt  =  elfhdr.e_sechdr_ent_size + 2
        elfhdr.e_sechdr_strtab   =  elfhdr.e_sechdr_ent_cnt + 2

        elfhdr.dsize[elfhdr.e_magic          ] = 16
        elfhdr.dsize[elfhdr.e_type           ] = 2
        elfhdr.dsize[elfhdr.e_class          ] = 1
        elfhdr.dsize[elfhdr.e_machine        ] = 2
        elfhdr.dsize[elfhdr.e_version        ] = 4
        elfhdr.dsize[elfhdr.e_entry          ] = ptrsize
        elfhdr.dsize[elfhdr.e_phdr_offset    ] = ptrsize
        elfhdr.dsize[elfhdr.e_sechdr_offset  ] = ptrsize
        elfhdr.dsize[elfhdr.e_flags          ] = 4
        elfhdr.dsize[elfhdr.e_elfhdr_size    ] = 2
        elfhdr.dsize[elfhdr.e_phdr_ent_size  ] = 2
        elfhdr.dsize[elfhdr.e_phdr_ent_cnt   ] = 2
        elfhdr.dsize[elfhdr.e_sechdr_ent_size] = 2
        elfhdr.dsize[elfhdr.e_sechdr_ent_cnt ] = 2
        elfhdr.dsize[elfhdr.e_sechdr_strtab  ] = 2

#.eh_frame_hdr
class ehfrmhdr(object):
    enc   = 0 #encoding
    ptr   = 0 #ptr to .eh_frame
    nfde  = 0
    tab   = 0
    dsize = dict()
    def __init__(self):
        ehfrmhdr.enc                  = 1
        ehfrmhdr.ptr                  = 4
        ehfrmhdr.nfde                 = 8
        ehfrmhdr.tab                  = 12
        ehfrmhdr.dsize[ehfrmhdr.enc ] = 1
        ehfrmhdr.dsize[ehfrmhdr.ptr ] = 4
        ehfrmhdr.dsize[ehfrmhdr.nfde] = 4
        ehfrmhdr.dsize[ehfrmhdr.tab ] = 4

class notehdr(object):
    n_namesz  = 0
    n_descsz  = 0
    n_type    = 0
    n_namestr = 0
    n_desc    = 0
    NT_GNU_ABI_TAG      = 1
    NT_GNU_HWCAP         = 2
    NT_GNU_BUILD_ID     = 3
    NT_GNU_GOLD_VERSION = 4
    NT_GNU_END          = 5
    dnamemap  = dict()
    dsize     = dict()
    def __init__(self):
        notehdr.n_namesz                              = 0
        notehdr.n_descsz                              = arch.INT_SIZE
        notehdr.n_type                                = notehdr.n_descsz\
                                                        + arch.INT_SIZE
        notehdr.dsize[notehdr.n_namesz]               = arch.INT_SIZE
        notehdr.dsize[notehdr.n_descsz]               = arch.INT_SIZE
        notehdr.dsize[notehdr.n_type  ]               = arch.INT_SIZE
        notehdr.dnamemap[notehdr.NT_GNU_ABI_TAG     ] = ".note.ABI-tag"
        notehdr.dnamemap[notehdr.NT_GNU_HWCAP       ] = ".note.gnu.hwcaps"
        notehdr.dnamemap[notehdr.NT_GNU_BUILD_ID    ] = ".note.gnu.build-id"
        notehdr.dnamemap[notehdr.NT_GNU_GOLD_VERSION] = ".note.gnu.gold-version"



class sectiontab(object):
    SHT_NULL           = 0
    SHT_PROGBITS       = 1
    SHT_SYMTAB         = 2
    SHT_STRTAB         = 3
    SHT_RELA           = 4
    SHT_HASH           = 5
    SHT_DYNAMIC        = 6
    SHT_NOTE           = 7
    SHT_NOBITS         = 8
    SHT_REL            = 9
    SHT_SHLIB          = 10
    SHT_DYNSYM         = 11
    SHT_INIT_ARRAY     = 14
    SHT_FINI_ARRAY     = 15
    SHT_PREINIT_ARRAY  = 16
    SHT_GROUP          = 17
    SHT_SYMTAB_SHNDX   = 18
    SHT_NUM            = 19
    SHT_LOOS           = 0x60000000
    SHT_GNU_ATTRIBUTES = 0x6ffffff
    SHT_GNU_HASH       = 0x6ffffff6
    SHT_GNU_LIBLIST    = 0x6ffffff7
    SHT_CHECKSUM       = 0x6ffffff8
    SHT_LOSUNW         = 0x6ffffffa
    SHT_SUNW_move      = 0x6ffffffa
    SHT_SUNW_COMDAT    = 0x6ffffffb
    SHT_SUNW_syminfo   = 0x6ffffffc
    SHT_GNU_verdef     = 0x6ffffffd
    SHT_GNU_verneed    = 0x6ffffffe
    SHT_GNU_versym     = 0x6fffffff
    SHT_HISUNW         = 0x6fffffff
    SHT_HIOS           = 0x6fffffff
    SHT_LOPROC         = 0x70000000
    SHT_HIPROC         = 0x7fffffff
    SHT_LOUSER         = 0x80000000
    SHT_HIUSER         = 0x8fffffff

    SHF_WRITE          = 0x1
    SHF_ALLOC          = 0x2
    SHF_EXECINSTR      = 0x4

    s_str_idx = 0
    s_type    = 0
    s_flags   = 0
    s_vaddr   = 0
    s_offset  = 0
    s_size    = 0
    s_link    = 0
    s_info    = 0
    s_align   = 0
    s_entsize = 0
    dsize     = dict()
    def __init__(self, ptrsize):
        sectiontab.s_str_idx = 0
        sectiontab.s_type    = sectiontab.s_str_idx + arch.INT_SIZE
        sectiontab.s_flags   = sectiontab.s_type    + arch.INT_SIZE
        sectiontab.s_vaddr   = sectiontab.s_flags   + ptrsize
        sectiontab.s_offset  = sectiontab.s_vaddr   + ptrsize
        sectiontab.s_size    = sectiontab.s_offset  + ptrsize
        sectiontab.s_link    = sectiontab.s_size    + ptrsize
        sectiontab.s_info    = sectiontab.s_link    + arch.INT_SIZE
        sectiontab.s_align   = sectiontab.s_info    + arch.INT_SIZE
        sectiontab.s_entsize = sectiontab.s_align   + ptrsize

        sectiontab.dsize[sectiontab.s_str_idx] = arch.INT_SIZE
        sectiontab.dsize[sectiontab.s_type   ] = arch.INT_SIZE
        sectiontab.dsize[sectiontab.s_flags  ] = ptrsize
        sectiontab.dsize[sectiontab.s_vaddr  ] = ptrsize
        sectiontab.dsize[sectiontab.s_offset ] = ptrsize
        sectiontab.dsize[sectiontab.s_size   ] = ptrsize
        sectiontab.dsize[sectiontab.s_link   ] = arch.INT_SIZE
        sectiontab.dsize[sectiontab.s_info   ] = arch.INT_SIZE
        sectiontab.dsize[sectiontab.s_align  ] = ptrsize
        sectiontab.dsize[sectiontab.s_entsize] = ptrsize


class reltab(object):
    r_offset = 0
    r_info   = 0
    r_sym    = 0
    r_type   = 0
    r_addend = 0
    dsize    = dict()
    entsize  = dict()
    def __init__(self):
        reltab.r_offset = 0
        reltab.r_info   = arch.PTR_SIZE
        reltab.r_addend = reltab.r_info + arch.PTR_SIZE
        reltab.r_type   = reltab.r_info
        if(arch.PTR_SIZE == 4):
            reltab.r_sym = reltab.r_info + 1
        else:
            reltab.r_sym = reltab.r_info + 4
        if(arch.PTR_SIZE == 4):
            reltab.dsize[reltab.r_offset  ] =  arch.PTR_SIZE
            reltab.dsize[reltab.r_info    ] =  arch.PTR_SIZE
            reltab.dsize[reltab.r_addend  ] =  arch.PTR_SIZE
            reltab.dsize[reltab.r_type    ] =  1
            reltab.dsize[reltab.r_sym     ] =  3
        elif(arch.PTR_SIZE == 8):
            reltab.dsize[reltab.r_offset  ] =  arch.PTR_SIZE
            reltab.dsize[reltab.r_info    ] =  arch.PTR_SIZE
            reltab.dsize[reltab.r_addend  ] =  arch.PTR_SIZE
            reltab.dsize[reltab.r_type    ] =  4
            reltab.dsize[reltab.r_sym     ] =  4

        reltab.entsize[dynamictab.DT_REL  ] = 2 * arch.PTR_SIZE
        reltab.entsize[dynamictab.DT_RELA ] = 3 * arch.PTR_SIZE
        reltab.entsize[sectiontab.SHT_REL ] = 2 * arch.PTR_SIZE
        reltab.entsize[sectiontab.SHT_RELA] = 3 * arch.PTR_SIZE


class phdr(object):
    PT_NULL         = 0
    PT_LOAD         = 1
    PT_DYNAMIC      = 2
    PT_INTERP       = 3
    PT_NOTE         = 4
    PT_SHLIB        = 5
    PT_PHDR         = 6
    PT_TLS          = 7
    PT_NUM          = 8
    PT_LOOS         = 0x60000000
    PT_GNU_EH_FRAME = 0x6474e550
    PT_GNU_STACK    = 0x6474e551
    PT_GNU_RELRO    = 0x6474e552
    PT_LOSUNW       = 0x6ffffffa
    PT_SUNWBSS      = 0x6ffffffa
    PT_SUNWSTACK    = 0x6ffffffb
    PT_HISUNW       = 0x6fffffff
    PT_HIOS         = 0x6fffffff
    PT_LOPROC       = 0x70000000
    PT_HIPROC       = 0x7fffffff

    PF_X           = 1
    PF_W           = 2
    PF_R           = 4

    #offset of fields in a PHDR entry
    p_type         = 0
    p_flags        = 0
    p_offset       = 0
    p_vaddr        = 0
    p_paddr        = 0
    p_filesz       = 0
    p_memsz        = 0
    p_align        = 0
    dname          = dict()
    rdname          = dict()
    def __init__(self, intsize=4, ptrsize=4):
        arch.INT_SIZE = intsize
        arch.PTR_SIZE = ptrsize
        print "ptr size: %x" % arch.PTR_SIZE
        phdr.dname['NOTE']                = phdr.PT_NOTE
        phdr.dname['LOAD']                = phdr.PT_LOAD
        phdr.dname['INTERP']              = phdr.PT_INTERP
        phdr.dname['DYNAMIC']             = phdr.PT_DYNAMIC
        phdr.dname['GNU_EH_FRAME']        = phdr.PT_GNU_EH_FRAME
        phdr.dname['PHDR']                = phdr.PT_PHDR
        phdr.dname['GNU_STACK']           = phdr.PT_GNU_STACK
        phdr.dname['GNU_RELRO']           = phdr.PT_GNU_RELRO
        phdr.dname['NULL']                = phdr.PT_NULL
        phdr.dname['TLS']                 = phdr.PT_TLS

        phdr.rdname[phdr.PT_NOTE]         = 'NOTE'
        phdr.rdname[phdr.PT_LOAD]         = 'LOAD'
        phdr.rdname[phdr.PT_INTERP]       = 'INTERP'
        phdr.rdname[phdr.PT_DYNAMIC]      = 'DYNAMIC'
        phdr.rdname[phdr.PT_GNU_EH_FRAME] = 'GNU_EH_FRAME'
        phdr.rdname[phdr.PT_PHDR]         = 'PHDR'
        phdr.rdname[phdr.PT_GNU_STACK]    = 'GNU_STACK'
        phdr.rdname[phdr.PT_GNU_RELRO]    = 'GNU_RELRO'
        phdr.rdname[phdr.PT_NULL]         = 'NULL'
        phdr.rdname[phdr.PT_TLS]          = 'TLS'

        if(ptrsize == 8):
            phdr.p_type         = 0
            phdr.p_flags        = arch.INT_SIZE + phdr.p_type
            phdr.p_offset       = arch.INT_SIZE + phdr.p_flags
            phdr.p_vaddr        = arch.PTR_SIZE + phdr.p_offset
            phdr.p_paddr        = arch.PTR_SIZE + phdr.p_vaddr
            phdr.p_filesz       = arch.PTR_SIZE + phdr.p_paddr
            phdr.p_memsz        = arch.PTR_SIZE + phdr.p_filesz
            phdr.p_align        = arch.PTR_SIZE + phdr.p_memsz
            phdr.p_type_size    = arch.INT_SIZE
            phdr.p_flags_size   = arch.INT_SIZE
            phdr.p_offset_size  = arch.PTR_SIZE
            phdr.p_vaddr_size   = arch.PTR_SIZE
            phdr.p_paddr_size   = arch.PTR_SIZE
            phdr.p_filesz_size  = arch.PTR_SIZE
            phdr.p_memsz_size   = arch.PTR_SIZE
            phdr.p_align_size   = arch.PTR_SIZE
        else:
            phdr.p_type         = 0
            phdr.p_offset       = arch.INT_SIZE + phdr.p_type
            phdr.p_vaddr        = arch.PTR_SIZE + phdr.p_offset
            phdr.p_paddr        = arch.PTR_SIZE + phdr.p_vaddr
            phdr.p_filesz       = arch.PTR_SIZE + phdr.p_paddr
            phdr.p_memsz        = arch.PTR_SIZE + phdr.p_filesz
            phdr.p_flags        = arch.INT_SIZE + phdr.p_memsz
            phdr.p_align        = arch.PTR_SIZE + phdr.p_flags
            phdr.p_type_size    = arch.INT_SIZE
            phdr.p_flags_size   = arch.INT_SIZE
            phdr.p_offset_size  = arch.PTR_SIZE
            phdr.p_vaddr_size   = arch.PTR_SIZE
            phdr.p_paddr_size   = arch.PTR_SIZE
            phdr.p_filesz_size  = arch.PTR_SIZE
            phdr.p_memsz_size   = arch.PTR_SIZE
            phdr.p_align_size   = arch.PTR_SIZE

class dynsymtab(elf_helper):
    st_name        = 0
    st_info        = 0
    st_other       = 0
    st_shndx       = 0
    st_value       = 0
    st_size        = 0
    symentry_size  = 0
    dsize = dict()

    def __init__(self):
        if(arch.PTR_SIZE == 8):
            dynsymtab.st_name                   = 0
            dynsymtab.st_info                   = arch.INT_SIZE
            dynsymtab.st_other                  = dynsymtab.st_info  + arch.CHAR_SIZE
            dynsymtab.st_shndx                  = dynsymtab.st_other + arch.CHAR_SIZE
            dynsymtab.st_value                  = dynsymtab.st_shndx + arch.SHORT_SIZE
            dynsymtab.st_size                   = dynsymtab.st_value + arch.PTR_SIZE
            dynsymtab.symentry_size             = dynsymtab.st_size  + arch.PTR_SIZE
            dynsymtab.dsize[dynsymtab.st_name ] = arch.INT_SIZE
            dynsymtab.dsize[dynsymtab.st_info ] = arch.CHAR_SIZE
            dynsymtab.dsize[dynsymtab.st_other] = arch.CHAR_SIZE
            dynsymtab.dsize[dynsymtab.st_shndx] = arch.SHORT_SIZE
            dynsymtab.dsize[dynsymtab.st_value] = arch.PTR_SIZE
            dynsymtab.dsize[dynsymtab.st_size ] = arch.PTR_SIZE
        else:
            dynsymtab.st_name                   = 0
            dynsymtab.st_value                  = dynsymtab.st_name  + arch.INT_SIZE
            dynsymtab.st_size                   = dynsymtab.st_value + arch.PTR_SIZE
            dynsymtab.st_info                   = dynsymtab.st_size  + arch.PTR_SIZE
            dynsymtab.st_other                  = dynsymtab.st_info  + arch.CHAR_SIZE
            dynsymtab.st_shndx                  = dynsymtab.st_other + arch.CHAR_SIZE
            dynsymtab.symentry_size             = dynsymtab.st_shndx + arch.SHORT_SIZE
            dynsymtab.dsize[dynsymtab.st_name ] = arch.INT_SIZE
            dynsymtab.dsize[dynsymtab.st_value] = arch.PTR_SIZE
            dynsymtab.dsize[dynsymtab.st_size ] = arch.INT_SIZE
            dynsymtab.dsize[dynsymtab.st_info ] = arch.CHAR_SIZE
            dynsymtab.dsize[dynsymtab.st_other] = arch.CHAR_SIZE
            dynsymtab.dsize[dynsymtab.st_shndx] = arch.SHORT_SIZE

class dynsym_entry(dynsymtab):
    def __init__(self, name=None, info=None, other=None, secid=None,
                 value=None, size=None, entry_offset=None):
        self.name  = name
        self.info  = info
        self.other = other
        self.secid = secid
        self.value = value
        self.size  = size
        self.entry_offset = entry_offset

class verdef(object):
    vd_version = 0
    vd_flags   = 2
    vd_ndx     = 4
    vd_cnt     = 6
    vd_hash    = 8
    vd_aux     = 12
    vd_next    = 16
    vd_size    = 20 # non-ELF standard

class verdaux(object):
    vda_name = 0
    vda_next = 4
    vda_size = 8 # non-ELF standard

class verneed(object):
    vn_version = 0
    vn_cnt     = 2
    vn_file    = 4
    vn_aux     = 8
    vn_next    = 12
    vn_size    = 16

class vernaux(object):
    vna_hash  = 0
    vna_flags = 4
    vna_other = 6
    vna_name  = 8
    vna_next  = 12
    vna_size  = 16 #non ELF standard

class  elf_basic(elf_helper):
    ABSOLUTE=0x0
    RELATIVE=0x1
    instance = None;

    @classmethod
    def getELFobject(cls):
        if(cls.instance !=None):
            return cls.instance;
        else:
            cls.instance = elf_basic()
            return cls.instance

    def set_binname(self,name):
        self.binname = name;
        self.filename = name

    def __init__(self, filename):
        elf_helper.__init__(self, filename)
        self.current_file   = self.get_tempfile()
        self.filewritable   = False
        self.offset_dynamic = -1
        elf_basic.instance  = self;
        self.arch           = arch()
        self.binname        = filename;
        self.filename       = filename
        self.phdr           = phdr(self.int_size(), self.ptr_size())
        self.elfhdr         = elfhdr(self.ptr_size())
        self.dynsymtab      = dynsymtab()
        self.dynamictab     = dynamictab()
        self.sectiontab     = sectiontab(self.ptr_size())
        self.notehdr        = notehdr()
        self.reltab         = reltab()
        self.ehfrmhdr       = ehfrmhdr()
    def get_binname(self):
        return self.filename

    def get_tempfile(self):
        temp_name = next(tempfile._get_candidate_names())
        return "/tmp/"+temp_name

    def gen_tempfile(self, temp_name):
        cmd = "cp %s %s" % (self.get_binname(), temp_name)
        print "generating tempfile %s" % temp_name
        os.system(cmd)
        cmd = "chmod u+w %s" % temp_name
        os.system(cmd)
        return temp_name

    def get_current_file(self):
        return self.current_file

    def set_current_file(self, filename):
        self.current_file = filename
        if(self.filewritable == True):
            self.filename = filename

    def switch_to_writable(self):
        if(self.filewritable == False):
            self.filename_orig = self.filename
            self.filename = self.current_file
            self.filewritable = True

    def switch_to_original(self):
        if(self.filewritable == True):
            self.filename = self.filename_orig
            self.filewritable = False


    def myprint(self):
        print "this is a test of elf_basic"

    def isPIC(self, binname):
        cmd = "readelf -h " + binname + "|grep Type|awk '{print $2}'"
        with os.popen(cmd) as file:
            for line in file:
                line = line.rstrip()
                if(line == "DYN"):
                    return True
                else:
                    return False
        return False

    def get_elfhdr_info(self, binpath, attribute):
        if(isinstance(attribute, basestring)):
            return self.get_elfhdr_info_str(binpath, attribute)
        return self.read_single(binpath, attribute, elfhdr.dsize[attribute])

    def get_elfhdr_info_str(self, binpath, attribute):
        elfhdr_pa = re.compile(r'[^:]:\s*[^\n]$');

        cmd = "readelf -h ";
        cmd += binpath;
        with os.popen(cmd) as file:
            for line in file:
                line = line.rstrip()
                if attribute in line:
                    str = line.split(':');
                    str = str[1].strip();
                    str = str.split(' ');
                    if(attribute == "Entry point address:"):
                        info = str[0];
                    elif(attribute == "Type:"):
                        info = str[0];
                    else:
                        info = str[0];
                        info = int(str[0],10);
                    #print "%s: %d" % (attribute, info);
        return info

    @static_var("initialized", False)
    @static_var("lines", [])
    def convert_offset_to_vma(self, binname, offset):
        if(isinstance(offset, basestring)):
            print "convert basestring: %s" % offset
            offset = int(offset, 16)
        if((not isinstance(offset, int)) and (not isinstance(offset, long))):
            print "offset not int type, return"
            return None
        regex = re.compile(r"^\s*LOAD\s+(?P<offset>\S+)\s+"
                   "(?P<virtual>\S+)\s+"
                   "(?P<physical>\S+)\s+"
                   "(?P<fsize>\S+)\s+"
                   "(?P<msize>\S+)\s+"
                   "(?P<flag>[^0]+)\s+"
                   "(?P<align>\S+)\s*$")
        if(not self.convert_offset_to_vma.initialized):
            cmd = "readelf -l -W " + binname
            with os.popen(cmd) as file:
                for line in file:
                    line = line.rstrip()
                    self.convert_offset_to_vma.lines.append(line)
        for line in self.convert_offset_to_vma.lines:
            m = regex.match(line)
            if(m != None):
                start = int(m.group('offset'), 16)
                fsize = int(m.group('fsize'), 16)
                #print "start: %x\tfsize: %x" % (start, fsize)
                if((start <= offset) and (offset <= (start + fsize))):
                    vbase = int(m.group('virtual'), 16)
                    return vbase + offset - start
        return None
    #Convert offset to virtal address when section table is not available
    @static_var("segments", dict())
    def convert_offset_to_vma2(self, binname, offset):
        if(not binname in self.convert_offset_to_vma2.segments):
            self.convert_offset_to_vma2.segments[binname] = \
                sorted(self.get_load_segments_info(binname),\
                    key=itemgetter('offset'))

        segments = self.convert_offset_to_vma2.segments[binname]
        for seg in segments:
            seg_vaddr  = seg['vaddr']
            seg_offset = seg['offset']
            seg_fsize  = seg['fsize']
            if(offset < seg_offset):
                return seg_vaddr - (seg_offset - offset)
            elif(offset >= seg_offset and offset < (seg_offset + seg_fsize)):
                return seg_vaddr + (offset - seg_offset)
        raise

    #Convert virtual address to offset when section table is not available
    @static_var("segments", dict())
    def convert_vma_to_offset2(self, binname, vma):
        if(not binname in self.convert_vma_to_offset2.segments):
            self.convert_vma_to_offset2.segments[binname] =\
                self.get_load_segments_info(binname)
        segments = self.convert_vma_to_offset2.segments[binname]
        for seg in segments:
            seg_vaddr  = seg['vaddr']
            seg_offset = seg['offset']
            seg_msize  = seg['memsize']
            seg_fsize  = seg['fsize']
            if(vma < seg_vaddr):
                return seg_offset - (seg_vaddr - vma)
            elif(vma >= seg_vaddr and vma < (seg_vaddr + seg_msize)):
                if(vma >= (seg_vaddr + seg_fsize)):
                    return seg_offset + seg_fsize - 1
                else:
                    return seg_offset + (vma - seg_vaddr)
        raise

    @static_var("initialized", False)
    @static_var("lines", [])
    def convert_vma_to_offset(self, binname, vma):
        if(isinstance(vma, basestring)):
            vma = int(vma, 16)
        num = self.get_elfhdr_info(binname, "Number of section headers:")
        pattern = re.compile(r"\s*\[\s*(?P<num>[\d]{1,2})\]\s*"
                    "(?P<name>[\S]+)\s*"
                    "(?P<type>[\S]+)\s*"
                    "(?P<addr>[\S]+)\s*"
                    "(?P<offset>[\S]+)\s*"
                    "(?P<size>[\S]+)\s*"
                    "[^\n]*$")

        if(not self.convert_vma_to_offset.initialized):
            cmd = "readelf -W -S " + binname;
            with os.popen(cmd) as file:
                for line in file:
                    line = line.strip();
                    self.convert_vma_to_offset.lines.append(line)
            #self.convert_vma_to_offset.initialized = True

        for line in self.convert_vma_to_offset.lines:
                m=pattern.match(line);
                if(m != None):
                    vma_start = int(m.group('addr'),16)
                    size = int(m.group('size'),16)
                    if(((vma_start+size) <= vma) or (vma < vma_start)):
                        continue
                    else:
                        if(m.group('name') == '.bss'):
                            return int(m.group('offset'),16)
                        else:
                            offset_start = int(m.group('offset'), 16)
                            offset = offset_start + (vma - vma_start)
                            return offset
        return 0

    def get_regions(self, regions):
        dregions = dict()
        for region in regions:
            offset = self.get_section_info(self.get_binname(), region, 'offset')
            size = self.get_section_info(self.get_binname(), region, 'size')
            if(offset == None or size == None):
                continue
            dregions[region] = [offset, offset+size]
        return dregions

    def get_sectionlist(self, binname):
        sectionlist = []
        cmd = "readelf -WS "+ binname +"| sed 's/\[//g'|grep '^\s*[0-9]'|awk '{print $2}'|grep -v NULL"
        with os.popen(cmd) as file:
            for line in file:
                line = line.strip()
                sectionlist.append(line)
        return sectionlist

    def trans_sec2seg_perm(self, secperm):
        segperm = 0x0
        if(secperm & self.sectiontab.SHF_ALLOC):
            segperm |= self.phdr.PF_R
        if(secperm & self.sectiontab.SHF_WRITE):
            segperm |= self.phdr.PF_W
        if(secperm & self.sectiontab.SHF_EXECINSTR):
            segperm |= self.phdr.PF_X
        print "segperm is %x" % segperm
        return segperm

    def trans_seg2sec_perm(self, segperm):
        secperm = 0x0
        if(segperm & self.phdr.PF_R):
            secperm |= self.sectiontab.SHF_ALLOC
        if(segperm & self.phdr.PF_W):
            secperm |= self.sectiontab.SHF_WRITE
        if(segperm & self.phdr.PF_X):
            secperm |= self.sectiontab.SHF_EXECINSTR
        return secperm


    def get_load_segments_info(self, binname):
        lloadsegments= []
        regex = re.compile(r"^\s*LOAD\s+"
                           "0x(?P<offset>\S+)\s+"
                           "0x(?P<vaddr>\S+)\s+"
                           "0x(?P<paddr>\S+)\s+"
                           "0x(?P<fsize>\S+)\s+"
                           "0x(?P<memsize>\S+)\s+"
                           "(?P<flag>[RWE ]+)\s+"
                           "0x(?P<align>\S+)\s*$")
        cmd = "readelf -l -W " + binname
        with os.popen(cmd) as file:
            for line in file:
                line = line.strip();
                m=regex.match(line);
                if(m != None):
                    segment = dict()
                    segment['offset'] = int(m.group('offset'), 16)
                    segment['vaddr'] = int(m.group('vaddr'), 16)
                    segment['paddr'] = int(m.group('paddr'), 16)
                    segment['fsize'] = int(m.group('fsize'), 16)
                    segment['memsize'] = int(m.group('memsize'), 16)
                    segment['flag'] = m.group('flag')
                    segment['align'] = int(m.group('align'), 16)
                    lloadsegments.append(segment)
        lloadsegments.sort(key = lambda x : x['vaddr'])
        return lloadsegments

    def get_segment_info(self, binname, segtype, idx, info):
        pattern = re.compile(r"^\s*(?P<type>\S+)\s+"
                             "0x(?P<offset>\S+)\s+"
                             "0x(?P<vaddr>\S+)\s+"
                             "0x(?P<paddr>\S+)\s+"
                             "0x(?P<fsize>\S+)\s+"
                             "0x(?P<memsize>\S+)\s+"
                             "(?P<flag>[RWE ]+)\s+"
                             "0x(?P<align>\S+)\s*$")
        cmd = "readelf -l -W " + binname;
        #assume only PT_LOAD has multiple entries
        load_idx = -1
        with os.popen(cmd) as file:
            for line in file:
                line = line.strip();
                m=pattern.match(line);
                if(m != None):
                    if(m.group('type') == "LOAD"):
                        load_idx += 1
                    if(segtype == m.group('type')):
                        if(segtype == "LOAD" and idx != load_idx):
                            continue
                        if(info == 'flag' or info == 'type'):
                            return m.group(info)
                        else:
                            return int(m.group(info), 16)
        return None

    def get_section_info(self, binname, secname, info):
        if(isinstance(info, basestring)):
            if(info != 'align'):
                return self.get_section_info_str(binname, secname, info)
            else:
                info = sectiontab.s_align
        #FIXME: remove the dependency to get_section_info_str()
        section_idx   = self.get_section_info_str(binname, secname, "num")
        if(section_idx == None):
            return None
        #print "idx: %d" % section_idx
        sectab_start  = self.get_elfhdr_info(binname, elfhdr.e_sechdr_offset)
        #print "sectab_start: %d" % sectab_start
        sectab_ent_sz = self.get_elfhdr_info(binname, elfhdr.e_sechdr_ent_size)
        offset        = sectab_start + section_idx * sectab_ent_sz
        return self.read_single(binname, offset + info, sectiontab.dsize[info])

    def get_section_info_str(self, binname, secname, info):
        pattern = re.compile(r"\s*\[\s*(?P<num>[\d]{1,2})\]\s*"
                             "(?P<name>[\S]+)\s*"
                             "(?P<type>[\S]+)\s*"
                             "(?P<addr>[\S]+)\s*"
                             "(?P<offset>[\S]+)\s*"
                             "(?P<size>[\S]+)\s*"
                             "[^\n]*$")
        cmd = "readelf -W -S " + binname;
        with os.popen(cmd) as file:
            for line in file:
                line = line.strip();
                m=pattern.match(line);
                if((m != None) and (m.group('name') == secname)):
                    if(info == 'num'):
                        return int(m.group(info),10)
                    if((info == 'addr') or
                    (info == 'offset') or
                    (info == 'size')
                    ):
                        return int(m.group(info),16)
                    else:
                        return m.group(info)
                    return m.group(info)
        return None

    """
    ELF Header Format:
        Field        Size        Offset
        magic:        16bytes        0
        type:        2 bytes        16
        machine:    2 bytes        18
        version:    4 bytes        20
        entry:        4 bytes        24
        phdr_offset:    4 bytes        28
        sechdr_offset:    4 bytes        32
        flags:        4 bytes        36
        elfhdr_size:    2 bytes        40
        phdr_ent_size:    2 bytes        42
        phdr_ent_cnt:    2 bytes        44
        sechdr_ent_size:2 bytes        46
        sechdr_ent_cnt:    2 bytes        48
        sechdr_strtab:    2 bytes        50

    total byte: 0x34 bytes( should be)
    """
    def modify_elfhdr_info(self, binpath, attribute, value):
        if(isinstance(attribute, basestring)):
            self.modify_elfhdr_info_str(binpath, attribute, value)
        else:
            self.write_single(binpath, attribute, value, elfhdr.dsize[attribute])

    def modify_elfhdr_info_str(self, binpath, attribute, value):
        fd = os.open(binpath, os.O_RDWR);
        if(attribute == "entrypoint"):
            os.lseek(fd, 24, os.SEEK_SET);
            value = pack("<i",value);
            os.write(fd, value);
            value = unpack('<i',value)
            print "modify entry point to %lx\n"%value;
        os.close(fd);

    def get_segment_offset_in_phdr(self, binname, seg_type, segidx=0):
        phdr_num = self.get_elfhdr_info(binname, "Number of program headers:");
        phdr_size = self.get_elfhdr_info(binname,"Size of program headers:");
        phdr_start = self.get_elfhdr_info(binname,"Start of program headers:");

        fd = os.open(binname, os.O_RDONLY);
        os.lseek(fd, phdr_start, os.SEEK_SET)
        load_idx = -1
        for idx in xrange(0, phdr_num):
            stype = unpack('<i',os.read(fd,4))[0];
            #if phdr_type == 0x00000003: #phdr entry type: interp
            os.lseek(fd, -arch.INT_SIZE, os.SEEK_CUR)
            #print "index:%d, type:%x"%(idx, stype);
            if(stype == phdr.PT_LOAD):
                load_idx += 1
            if(stype == seg_type):
                if(seg_type == phdr.PT_LOAD and segidx != load_idx):
                    os.lseek(fd, phdr_size, os.SEEK_CUR)
                    continue
                offset = os.lseek(fd, 0, os.SEEK_CUR)
                os.close(fd)
                return offset
            os.lseek(fd, phdr_size, os.SEEK_CUR)
        os.close(fd)
        return None

    def modify_phdrtab_info(self, binname, seg_type, attribute, value, segidx=0):
        phdr_num = self.get_elfhdr_info(binname, "Number of program headers:");
        phdr_size = self.get_elfhdr_info(binname,"Size of program headers:");
        phdr_start = self.get_elfhdr_info(binname,"Start of program headers:");

        fd = os.open(binname, os.O_RDWR);
        os.lseek(fd, phdr_start, os.SEEK_SET)
        load_idx = -1
        for idx in xrange(0, phdr_num):
            stype = unpack('<i',os.read(fd,4))[0];
            #if phdr_type == 0x00000003: #phdr entry type: interp
            os.lseek(fd, - self.int_size(), os.SEEK_CUR)
            #print "index:%d, type:%x"%(idx, stype);
            if(stype == phdr.PT_LOAD):
                load_idx += 1
            if(stype == seg_type):
                if(seg_type == phdr.PT_LOAD and segidx != load_idx):
                    os.lseek(fd, phdr_size, os.SEEK_CUR)
                    continue
                offset = os.lseek(fd, attribute, os.SEEK_CUR)
                if(attribute == phdr.p_type or attribute == phdr.p_flags):
                    self.write_int(binname, offset, value)
                else:
                    self.write_ptr(binname, offset, value)
                break
            os.lseek(fd, phdr_size, os.SEEK_CUR)
        os.close(fd)

    #deprecated: for usage of modify_elf.py
    def modify_phdr_info(self, binname, offset, seg_type, attribute, value):
        global arch;
        phdr_num = self.get_elfhdr_info(binname, "Number of program headers:");
        phdr_size = self.get_elfhdr_info(binname,"Size of program headers:");
        phdr_start = self.get_elfhdr_info(binname,"Start of program headers:");
        fd = os.open(binname, os.O_RDWR);
        os.lseek(fd, phdr_start, os.SEEK_SET)

        for idx in xrange(0, phdr_num):
            stype = unpack('<i',os.read(fd,4))[0];
            #if phdr_type == 0x00000003: #phdr entry type: interp
            os.lseek(fd, -arch.INT_SIZE, os.SEEK_CUR)
            print "index:%d, type:%x"%(idx, stype);
            if(stype == seg_type):
                if(stype == phdr.PT_LOAD):
                    os.lseek(fd, phdr.p_offset, os.SEEK_CUR)
                    p_offset = unpack('<i',os.read(fd,4))[0];
                    if(p_offset == offset):
                        os.lseek(fd, -(phdr.p_offset+4), os.SEEK_CUR)
                        #print "match  segement";
                        break;
                    else:
                        os.lseek(fd, -(phdr.p_offset+4), os.SEEK_CUR)
                        os.lseek(fd, phdr_size, os.SEEK_CUR)
                        continue;
                else:
                    #print "match  segement";
                    break;
            os.lseek(fd, phdr_size, os.SEEK_CUR)

        os.lseek(fd, attribute, os.SEEK_CUR)
        os.write(fd, pack('<i',value));
        pass

    def modify_sectiontab_info(self, binpath, secname, attribute,value):
        print "filename: %s, binpath: %s" % (binpath, binpath)
        secnum = self.get_section_info(binpath, secname, "num")
        if(secnum == None):
            print "section %s does not exists\n"%secname;
            return
        print "section num: %d"%secnum
        sectable_start = self.get_elfhdr_info(binpath, "Start of section headers:")
        print "section table start:%x"%sectable_start
        section_size = self.get_elfhdr_info(binpath, "Size of section headers:")
        print "section entry size:%d"%section_size
        section_offset = sectable_start +secnum * section_size
        print "final offset %x" % (section_offset + attribute)
        if(attribute == sectiontab.s_str_idx or \
            attribute == sectiontab.s_type   or \
            attribute == sectiontab.s_align  or \
            attribute == sectiontab.s_entsize):
            self.write_int(binpath, section_offset + attribute, value)
        else:
            self.write_ptr(binpath, section_offset + attribute, value)

    #deprecated: for usage of modify_elf.py. Valid only for x86-32
    def modify_section_info(self, binpath, secname, attribute,value):
        secnum = self.get_section_info(binpath, secname, "num")
        if(secnum == None):
            print "section %s does not exists\n"%secname;
            return
        print "section num: %d"%secnum
        sectable_start = self.get_elfhdr_info(binpath, "Start of section headers:")
        print "section table start:%x"%sectable_start
        section_size = self.get_elfhdr_info(binpath, "Size of section headers:")
        print "section entry size:%d"%section_size
        interp_offset = sectable_start +secnum * section_size
        if(attribute == "index"):
            interp_offset = interp_offset + 0
        elif(attribute == "type"):
            interp_offset = interp_offset + 4;
        elif(attribute == "flags"):
            interp_offset = interp_offset + 8;
        elif(attribute == "addr"):
            interp_offset = interp_offset + 12;
        elif(attribute == "offset"):
            interp_offset = interp_offset + 16;
        elif(attribute == "size"):
            interp_offset = interp_offset + 20;
        elif(attribute == "link"):
            interp_offset = interp_offset + 24;
        elif(attribute == "info"):
            interp_offset = interp_offset + 28;
        elif(attribute == "align"):
            interp_offset = interp_offset + 32;
        elif(attribute == "entsize"):
            interp_offset = interp_offset + 36;
        fd = os.open(binpath, os.O_RDWR);
        os.lseek(fd, interp_offset, os.SEEK_SET);
        os.write(fd, pack('<i',value));
        fd = os.close(fd);

    def insert_new_section(self, binname, secname, file, align=None):
        tempfile = self.get_tempfile()
        cmd = "objcopy --add-section %s=%s %s %s" % (secname, file, binname, tempfile)
        os.system(cmd)
        print cmd
        if(align != None):
            self.modify_sectiontab_info(tempfile, secname, sectiontab.s_align, align)
            self.regen_binary(tempfile, binname)

    def regen_binary(self, filename, binname):
        cmd = "objcopy %s %s" % (filename, binname)
        os.system(cmd)

    def relocate_sectiontab(self, binname, offset, option):
        nsectab_offset = 0
        nsectab_size   = 0
        sectab_offset  = self.get_elfhdr_info(binname,
                "Start of section headers:")

        if(option == elf_basic.RELATIVE):
            nsectab_offset = sectab_offset + offset
            print "old section offset: %x" % sectab_offset
        else:
            nsectab_offset = offset
        entry_nm = self.get_elfhdr_info(binname, "Number of section headers:")
        entry_sz = self.get_elfhdr_info(binname, "Size of section headers:")
        nsectab_size = entry_sz * entry_nm
        print "new section size  : %x" % nsectab_size
        print "new section offset: %x" % nsectab_offset
        tmpfile     = self.get_tempfile()
        self._extract_data(binname, sectab_offset, nsectab_size, tmpfile)
        self.write_data_from_file(binname, nsectab_offset, tmpfile)
        self.modify_elfhdr_info(binname, elfhdr.e_sechdr_offset, nsectab_offset)

    def get_dynamic_sections_info(self, binname):
        dynoptlist    = self.read_all_dynamic_options(binname)
        codestart     = self.get_segment_info(binname, "LOAD", 0, 'vaddr')
        codeend       = codestart + self.get_segment_info(binname, "LOAD", 0, 'fsize')
        datastart     = self.get_segment_info(binname, "LOAD", 1, 'vaddr')
        dataend       = datastart + self.get_segment_info(binname, "LOAD", 1, 'fsize')
        filtered_list = []
        for dyn in dynoptlist:
           if(self.check_range(codestart, dataend, dyn[1])):
               if(dynamictab.isaddr(dyn[0])):
                   filtered_list.append(dyn)
        filtered_list.sort(key = lambda x : x[1])
        return filtered_list

    def add_dynamic_option(self, binname,option, value):
        #now get the PHDR information
        phdr_num = self.get_elfhdr_info(binname, "Number of program headers:");
        phdr_size = self.get_elfhdr_info(binname,"Size of program headers:");
        phdr_start = self.get_elfhdr_info(binname,"Start of program headers:");

        dyn_offset = 0;
        dyn_infile_size = 0;

        #enlarge the dynamic segment by 8 bytes
        offset_begin = phdr_start
        fd_phdr = os.open(binname, os.O_RDWR);
        os.lseek(fd_phdr, offset_begin, os.SEEK_SET)
        print "phdr_num:%lx"%phdr_num
        for size in xrange(0, phdr_num):
            os.lseek(fd_phdr, phdr_size, os.SEEK_CUR)
            phdr_type = unpack('<i',os.read(fd_phdr,4))[0];
            os.lseek(fd_phdr,-4,os.SEEK_CUR);
            print "phdr_type: %lx"%phdr_type
            if phdr_type == 0x00000002: #phdr entry type: dynamic
                os.lseek(fd_phdr,4,os.SEEK_CUR);
                dyn_offset = unpack('<i',os.read(fd_phdr,4))[0];
                print "offset of dynamic segment: %lx"%dyn_offset
                os.lseek(fd_phdr,8,os.SEEK_CUR);
                dyn_infile_size = unpack('<i',os.read(fd_phdr,4))[0]
                os.lseek(fd_phdr,-4,os.SEEK_CUR);

        print "offset of dynamic segment: %lx"%dyn_offset
        print "size of dynamic segment: %lx"%dyn_infile_size
        #os.close(fd_phdr);

        fd = os.open(binname,os.O_RDWR);
        os.lseek(fd, dyn_offset, os.SEEK_SET);
        #os.lseek(fd, dyn_offset + dyn_infile_size - 8, os.SEEK_SET);
        print "move to beginning of dynamic segment: %lx"%(dyn_offset )

        dyn_start = dyn_offset;
        dyn_end = dyn_offset + dyn_infile_size - 8;
        enlarge_dynamic = 1;
        while (dyn_start < dyn_end):
            dyn_option = unpack('<i', os.read(fd,4))[0];
            dyn_content = unpack('<i', os.read(fd,4))[0];
            if(dyn_option ==0 and dyn_content ==0):
            #reach the end of dynamic segment
                enlarge_dynamic = 0;
                os.lseek(fd, -8, os.SEEK_CUR);
                os.write(fd,pack('<i',option));#0x18 means BIND_NOW
                os.write(fd,pack('<i',value));
                break;
            dyn_start+=8;


        if(enlarge_dynamic ==1):
            os.write(fd,pack('<i',option));#0x18 means BIND_NOW
            os.write(fd,pack('<i',value));
            os.write(fd,pack('<i',0x00000000));
            os.write(fd,pack('<i',0x00000000));
            os.write(fd_phdr,pack('<i',dyn_infile_size+8))
            os.write(fd_phdr,pack('<i',dyn_infile_size+8))

    def get_dynamic_offset(self,binname):
        phdr_num = self.get_elfhdr_info(binname, "Number of program headers:");
        phdr_size = self.get_elfhdr_info(binname,"Size of program headers:");
        phdr_start = self.get_elfhdr_info(binname,"Start of program headers:");

        dyn_offset = 0;
        dyn_infile_size = 0;

        offset_begin = phdr_start
        fd_phdr = os.open(binname, os.O_RDONLY);
        os.lseek(fd_phdr, offset_begin, os.SEEK_SET)
        print "phdr_num:%lx"%phdr_num
        for size in xrange(0, phdr_num):
            os.lseek(fd_phdr, phdr_size, os.SEEK_CUR)
            phdr_type = self.bytestoint(os.read(fd_phdr, self.int_size()));
            os.lseek(fd_phdr,- self.int_size(),os.SEEK_CUR);
            #print "phdr_type: %lx"%phdr_type
            if phdr_type == 0x00000002: #phdr entry type: dynamic
                os.lseek(fd_phdr, self.ptr_size(), os.SEEK_CUR);
                self.offset_dynamic = self.bytestoptr(os.read(fd_phdr,self.ptr_size()))
                os.close(fd_phdr);
                return self.offset_dynamic;
        os.close(fd_phdr);
        return -1

    def read_all_dynamic_options(self, binname):
        self.offset_dynamic=self.get_dynamic_offset(binname);
        if(self.offset_dynamic == -1):
            print "cannot find dynamic segment, abort";
            return []
        dynoptlist = []
        fd = os.open(binname,os.O_RDONLY);
        os.lseek(fd, self.offset_dynamic, os.SEEK_SET);
        dyn_opt = self.bytestoptr(os.read(fd, self.ptr_size()));
        while(dyn_opt != 0):
            #print "dynamic option type: %d"%dyn_opt
            dyn_value = self.bytestoptr(os.read(fd,self.ptr_size()))
            dynoptlist.append((dyn_opt, dyn_value))
            dyn_opt = self.bytestoptr(os.read(fd, self.ptr_size()));
        return dynoptlist

    def get_relent_size(self, binname):
        relent = self.read_dynamic_option(binname, dynamictab.DT_RELENT)
        if(relent != None):
            return relent
        return self.read_dynamic_option(binname, dynamictab.DT_RELAENT)

    def read_dynamic_option(self, binname, option):
        self.offset_dynamic=self.get_dynamic_offset(binname);
        if(self.offset_dynamic == -1):
            print "cannot find dynamic segment, abort";
            exit(1);
        fd = os.open(binname,os.O_RDONLY);
        os.lseek(fd, self.offset_dynamic, os.SEEK_SET);
        dyn_opt = self.bytestoptr(os.read(fd, self.ptr_size()));
        while(dyn_opt != 0):
            #print "dynamic option type: %d"%dyn_opt
            dyn_value = self.bytestoptr(os.read(fd,self.ptr_size()))
            if(dyn_opt == option):
                os.close(fd);
                return dyn_value
            dyn_opt = self.bytestoptr(os.read(fd, self.ptr_size()));
        return None

    def update_dynamic_option(self, binname, option,new_value):
        self.offset_dynamic=self.get_dynamic_offset(binname);
        if(self.offset_dynamic == -1):
            print "cannot find dynamic segment, abort";
            exit(1);
        offset = self.offset_dynamic
        dyn_opt = self.read_ptr(binname, offset)
        while(dyn_opt != 0):
            #print "dynamic option type: %d"%dyn_opt
            offset += self.ptr_size()
            if(dyn_opt == option):
                self.write_ptr(binname, offset, new_value)
                return 1;
            offset += self.ptr_size()
            dyn_opt = self.read_ptr(binname, offset)
        return None

    #TODO: Need to handle ELF with multiple executable ranges
    def get_exec_memory_range(self, binpath):
        #step 1: get code memory range
        cmd="readelf -W -S "+binpath+'| sed \'s/\[\s*//g\'|grep \' AX \'| awk \'{print $4 \" \" $5 \" \" $6}\''
        pattern = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)");
        exec_begin = 0x7fffffff;
        exec_end = 0x0;
        exec_end_size = 0;
        with os.popen(cmd) as file:
            for line in file:
                line = line.strip()
                m = pattern.match(line);
                if(m != None):
                    #print line
                    #print m.group(1);
                    addr = int(m.group(1), 16);
                    size = int(m.group(3), 16);
                    if(addr < exec_begin):
                        exec_begin = addr
                    if(addr > exec_end):
                        exec_end = addr
                        exec_end_size = size;
            exec_end += exec_end_size;
            #print "exec_begin %x"%exec_begin
            #print "exec_end %x"%exec_end
            #print "%x %x"%(exec_begin, exec_end);
        return (exec_begin, exec_end)

    def _extract_data(self, binname, offset, size, output, padalignpage=False,
                      padbyte='\0'):
        fd = os.open(binname,os.O_RDONLY);
        os.lseek(fd, offset, os.SEEK_SET);
        buf = os.read(fd, size);
        os.close(fd);
        #fd2 = os.open(output, os.O_CREAT|os.O_TRUNC|os.O_RDWR, 0644)
        #os.write(fd2,buf);
        #os.close(fd2);
        padlen = 0
        with open(output, 'w') as fd2:
            if(padalignpage == True and (offset & 0xfff) != 0):
                padlen = offset % 0x1000
                fd2.write(padbyte * padlen)
            fd2.write(buf)
        print "text offset %lx"%offset
        print "text size %lx"% (size + padlen)

    def extract_data(self, binname, secname, output, padalignpage=False,
                     padbyte='\0'):
        gen_asm_offset = self.get_section_info(binname, secname, "offset");
        gen_asm_size = self.get_section_info(binname, secname, "size");
        if(gen_asm_offset == None):
            print "extract_data: "+binname+" file does not exist";
            return;
        self._extract_data(binname, gen_asm_offset, gen_asm_size, output,
                           padalignpage, padbyte)

    def relocate_data(self, binname, offset, size, new_offset):
        tmpfile = self.get_tempfile()
        self._extract_data(binname, offset, size, tmpfile)
        self.write_data_from_file(binname, new_offset, tmpfile)
        os.remove(tmpfile)

    def compile_inject_data(self, htables, binname):
        for h in htables:
            base = os.path.basename(h.output_data)
            raw = base.split('.')[0] #eliminate the extention name
            cmd = "gcc -c "+base
            os.system(cmd)
            obj = raw+".o"
            sec = h.get_secname();

            self.extract_data(obj,".text",raw)

            cmd = "objcopy --add-section "+sec+"="+raw +" "+binname + " " + binname
            print "%s"%cmd
            os.system(cmd)
            self.modify_section_info(binname,sec,"align",0x00001000)

    def read_all_dynsyms(self, binname):
        dynoptlist = self.read_all_dynamic_options(binname)
        dynsymbase = None
        dynsymend = None
        for dynopt in dynoptlist:
            if(dynopt[0] == dynamictab.DT_SYMTAB):
                dynsymbase = dynopt[1]
            if(dynopt[0] == dynamictab.DT_STRTAB):
                dynsymend = dynopt[1]
        if(dynsymbase == None or dynsymend == None):
            return None
        dynlist = []
        dynsymbase = self.convert_vma_to_offset(binname, dynsymbase)
        dynsymend  = self.convert_vma_to_offset(binname, dynsymend)
        print "dynsym base: %x"%dynsymbase
        print "dynsym end:  %x"%dynsymend
        offset = dynsymbase
        while(offset < dynsymend):
            entry = dynsym_entry()
            entry.name  = self.bytestoint(
                          self.read_data_raw(binname, offset +
                                            dynsymtab.st_name,
                                            dynsymtab.dsize[dynsymtab.st_name]
                                           ))
            entry.value = self.bytestoptr(
                          self.read_data_raw(binname, offset +
                                            dynsymtab.st_value,
                                            dynsymtab.dsize[dynsymtab.st_value]
                                           ))
            entry.size  = self.bytestoptr(
                          self.read_data_raw(binname, offset +
                                            dynsymtab.st_size,
                                            dynsymtab.dsize[dynsymtab.st_size]
                                           ))
            entry.info  = self.bytestounsignedchar(
                          self.read_data_raw(binname, offset +
                                            dynsymtab.st_info,
                                            dynsymtab.dsize[dynsymtab.st_info]
                                           ))
            entry.other = self.bytestounsignedchar(
                          self.read_data_raw(binname, offset +
                                            dynsymtab.st_other,
                                            dynsymtab.dsize[dynsymtab.st_other]
                                           ))
            entry.shndx = self.bytestoshort(
                          self.read_data_raw(binname, offset +
                                            dynsymtab.st_shndx,
                                            dynsymtab.dsize[dynsymtab.st_shndx]
                                           ))
            entry.entry_offset = offset
            dynlist.append(entry)
            #print "entryname: %x" % entry.name
            #print "entryvalue: %x" % entry.value
            #print "entrysize: %x" % entry.size
            #print "entryinfo: %x" % entry.info
            #print "entryother: %x" % entry.other
            #print "entryshndx: %x" % entry.shndx
            #print "entry entry size: %x" % dynsymtab.symentry_size
            #print "=="
            offset += dynsymtab.symentry_size

        return dynlist

    def modify_dynsym_info(self, binname, idx, attribute, value):
        #step1: get dynamic info and find dynsym base and size
        dynoptlist = self.read_all_dynamic_options(binname)
        dynsymbase = None
        dynsymend  = None
        for dynopt in dynoptlist:
            if(dynopt[0] == dynamictab.DT_SYMTAB):
                dynsymbase = dynopt[1]
            if(dynopt[0] == dynamictab.DT_STRTAB):
                dynsymend = dynopt[1]
        if(dynsymbase == None or dynsymend == None):
            return None
        dynlist = []
        dynsymbase = self.convert_vma_to_offset(binname, dynsymbase)
        dynsymend  = self.convert_vma_to_offset(binname, dynsymend)
        print "dynsym base: %x"%dynsymbase
        print "dynsym end:  %x"%dynsymend

        #step2: find idx and write value
        offset = dynsymbase + idx * dynsymtab.symentry_size + attribute
        self.write_single(binname, offset, value, dynsymtab.dsize[attribute])

    def read_obj_symtable(self, objfile):
        rsym = re.compile(r'^(\S+)\s+(\S+)\s+(\S+)\s*$')
        cmdsym = "nm %s" % objfile
        sym_table = dict()
        with os.popen(cmdsym) as file:
            for line in file:
                line = line.strip()
                m = rsym.match(line)
                if(m != None):
                    sym = dict()
                    sym['offset'] = int(m.group(1), 16)
                    sym['type'] = m.group(2)
                    sym['name'] = m.group(3)
                    sym_table[sym['name']] = sym
        return sym_table

    def read_obj_reloctable(self, objfile):
        rreloc = re.compile(r'^\s*([0-9a-fA-F]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)')
        cmdreloc = "readelf -r -W %s" % objfile
        reloc_table = dict()
        with os.popen(cmdreloc) as file:
            for line in file:
                line = line.strip()
                m = rreloc.match(line)
                if(m != None):
                    sym = dict()
                    sym['offset'] = int(m.group(1), 16)
                    sym['info'] = m.group(2)
                    sym['type'] = m.group(3)
                    sym['value'] = m.group(4)
                    sym['name'] = m.group(5)
                    reloc_table[sym['offset']] = sym
        print "relocation table len: %d\n" % len(reloc_table)
        return reloc_table

    def read_reloc_entry(self, stype, binname, offset):
        rel = dict()
        rel[reltab.r_offset] = self.read_single(binname, offset + reltab.r_offset,
                                                reltab.dsize[reltab.r_offset])
        rel[reltab.r_info]   = self.read_single(binname, offset + reltab.r_info,
                                                reltab.dsize[reltab.r_info])
        rel[reltab.r_sym]    = self.read_single(binname, offset + reltab.r_sym,
                                                reltab.dsize[reltab.r_sym])
        rel[reltab.r_type]    = self.read_single(binname, offset + reltab.r_type,
                                                reltab.dsize[reltab.r_type])

        if(stype == sectiontab.SHT_RELA or stype == dynamictab.DT_RELA):
            rel[reltab.r_addend] = self.read_single(binname, offset + reltab.r_addend,
                                                    reltab.dsize[reltab.r_addend])
        return rel


    def read_relocs(self, binname, secoffset, sectionsz, stype):
        relocations = []
        relocentsz  = reltab.entsize[stype]
        relcount    = sectionsz / relocentsz
        #print "relocation count: %d" % relcount
        #print "relocation section offset: %d" % secoffset
        #print "relocation section size: %d" % sectionsz
        for i in range(0, relcount):
            rel = self.read_reloc_entry(stype, binname, secoffset + i*relocentsz)
            relocations.append(rel)
        return relocations

    def read_reloc_section(self, binname, secname):
        stype = self.get_section_info(binname, secname, sectiontab.s_type)
        if(stype != sectiontab.SHT_REL and stype != sectiontab.SHT_RELA):
            print "no relocation found in section %s" % secname
            return None
        sectionsz   = self.get_section_info(binname, secname, 'size')
        secoffset   = self.get_section_info(binname, secname, 'offset')
        return self.read_relocs(binname, secoffset, sectionsz, stype)

@static_var("initialized", False)
def translate_orig_addr_to_offset(binname, address):
    if(translate_orig_addr_to_offset.initialized == False):
        #os.chdir("./target_elf/"+binname)
        value = get_mapping_offset(address)
        #os.chdir("../..")
        return value
    else:
        return get_mapping_offset(address)

#from the original address to get the offset in generated binary
#address: string type representing an address
@static_var("initialized", False)
@static_var("file_nm", None)
@static_var("htable", dict)
def get_mapping_offset(address):
    addr = int(address, 16);
    p = re.compile(r"^([0-9a-fA-Fx]+)\s+([\S]+)\s+_([0-9a-fA-F]+)$");
    cmd = "nm generated_asm.o >static_symbols"
    file_begin = int("0",10);
    #address = address.lstrip('0x');
    file_nm = None;
    if(get_mapping_offset.initialized == False):
        print "inside"
        os.system(cmd);
        get_mapping_offset.file_nm = open("./static_symbols",'r');
        get_mapping_offset.initialized = True;
        get_mapping_offset.htable = dict();
        get_mapping_offset.htable[addr] = None;
        for line in get_mapping_offset.file_nm:
            line = line.strip()
            m = p.match(line);
            if(m != None):
                get_mapping_offset.htable[int(m.group(3),16)] = m.group(1);

    return get_mapping_offset.htable.get(addr, None);


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binfile', nargs='?');
    parser.add_argument('-exec_range', action="store_true")
    args = parser.parse_args()

    binname = args.binfile;
    eb = elf_basic();

    if(args.exec_range):
        eb.get_exec_memory_range(binname);


if __name__ == "__main__":
    main()
