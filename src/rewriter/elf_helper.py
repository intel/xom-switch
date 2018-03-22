#!/usr/bin/python

import sys
import re
import os
import tempfile
import struct
from struct import *

def static_var(varname, value):
    def decorate(func):
        setattr(func, varname, value)
        return func
    return decorate

class const(object):
    arch32="80386"
    arch64="X86-64"

class elf_helper(const):
    def __init__(self, file):
        self.filename = file
        self.ispic = None
        self.ptrsize = None
        self.cached_cmd = dict()
        self.set_arch()
        self.set_ptr_size()

    def set_ptr_size(self):
        cmd = "readelf -h " + self.filename + "|grep Class:"
        ll = self.get_matched_lines(cmd);
        if((not ll) or (not ll[0])):
            self.ptrsize = None
            raise
        else:
            if(ll[0][-1] == "ELF64"):
                self.ptrsize = 8
            elif(ll[0][-1] == "ELF32"):
                self.ptrsize = 4
            else:
                raise

    def set_arch(self):
        cmd = "readelf -h " + self.filename + "|grep Machine"
        ll = self.get_matched_lines(cmd);
        if((not ll) or (not ll[0])):
            self.archname = "unknown"
            raise
        else:
            self.archname = ll[0][-1]
            print self.archname
            #32bit: 80386
            #64bit: X86-64

    def isx86_32(self):
        if(self.archname == const.arch32):
            return True
        else:
            return False

    def isx86_64(self):
        if(self.archname == const.arch64):
            return True
        else:
            return False

    def is_pic(self):
        if(self.ispic != None):
            return self.ispic
        cmd = "readelf -h " + self.filename + "|grep Type|awk '{print $2}'"
        with os.popen(cmd) as file:
            for line in file:
                line = line.rstrip()
                if(line == "DYN"):
                    self.ispic = True
                    return True
                else:
                    self.ispic = False
                    return False

    def char_size(self):
        return 1

    def short_size(self):
        return 2

    def int_size(self):
        return 4

    def ptr_size(self):
        return self.ptrsize

    def longlong_size(self):
        return 8

    def padding(self, v, l):
        if(len(v) == l):
            return v
        if(len(v) < l):
            pad = '\x00' *(l - len(v))
            newv = v + pad
            return newv
        else:
            raise

    def bytestoint(self, i):
        return unpack('<i', self.padding(i, struct.calcsize('<i')))[0]

    def bytestoshort(self, s):
        return unpack('<h', self.padding(s, struct.calcsize('<h')))[0]

    def bytestounsignedchar(self, uc):
        return unpack('<B', self.padding(uc, struct.calcsize('<B')))[0]

    def bytestolonglong(self, ll):
        return unpack('<q', self.padding(ll, struct.calcsize('<q')))[0]

    def bytestoptr(self, s):
        try:
            if(self.ptr_size() == 4):
                return self.bytestoint(s)
            elif(self.ptr_size() == 8):
                return self.bytestolonglong(s)
        except:
            return 0

    def chartobyte(self, s):
        return pack('<B', s)

    def shorttobytes(self, s):
        return pack('<h', s)

    def inttobytes(self, i):
        return pack('<i', i)

    def ptrtobytes(self, ptr):
        try:
            if(self.isx86_32()):
                return pack('<i', ptr)
            elif(self.isx86_64()):
                return pack('<q', ptr)
        except:
            return None

    def tofixedhexstr(self, s, len=None):
        if(len == None):
            if(self.isx86_32()):
                return "%08x" % s
            elif(self.isx86_64()):
                return "%016x" % s
            else:
                return None
        else:
            if(len == 8):
                return "%016x" % s
            elif(len == 4):
                return "%08x" % s
            else:
                return None

    def tohexstr(self,s):
        if(self.isx86_32()):
            return "%x" % s
        elif(self.isx86_64()):
            return "%x" % s
        else:
            return None

    def get_result_lines(self, cmd):
        if(not (cmd in self.cached_cmd)):
            lres = []
            with os.popen(cmd) as file:
                for line in file:
                    line = line.strip()
                    lres.append(line)
            self.cached_cmd[cmd] = lres
        return self.cached_cmd[cmd]

    def get_matched_lines(self, cmd, separator = None):
        if(not (cmd in self.cached_cmd)):
            lres = []
            with os.popen(cmd) as file:
                for line in file:
                    line = line.strip()
                    ltmp = line.split(separator)
                    lres.append(ltmp)
            self.cached_cmd[cmd] = lres
            #print "get matched lines: "
            #print lres
        return self.cached_cmd[cmd]

    def check_range(self, start, end, value):
        if(start < value and value < end):
            return True
        else:
            return False

    def adjust_value(self, v, offset):
        newv = int(v, 16) + offset;
        newv = self.tofixedhexstr(newv)
        return newv

    def adjust_values(self, d, offset):
        newd = dict()
        for key in d:
            newkey = int(key, 16) + offset;
            newkey = self.tofixedhexstr(newkey)
            #print newkey
            newd[newkey] = d[key]
        return newd

    def match_and_add(self, regex, str, value, d):
        m = regex.match(str)
        if(m != None):
            d[value] = 1

    def dereference(self, ref):
        f = os.open(self.filename, os.O_RDONLY)
        os.lseek(f, ref, os.SEEK_SET)
        value = os.read(f,self.ptr_size())
        os.close(f)
        return self.bytestoptr(value)

    def read_data(self, filename, offset, len):
        f = os.open(filename, os.O_RDONLY)
        os.lseek(f, offset, os.SEEK_SET)
        data = os.read(f, len)
        os.close(f)
        return ''.join(data)

    def read_data_raw(self, filename, offset, len):
        f = os.open(filename, os.O_RDONLY)
        os.lseek(f, offset, os.SEEK_SET)
        data = os.read(f, len)
        os.close(f)
        return data

    def read_char(self, filename, offset):
        return self.bytestounsignedchar((self.read_data_raw(filename, offset,
                                                           self.char_size())))
    def read_short(self, filename, offset):
        return self.bytestoshort(self.read_data_raw(filename, offset, self.short_size()))

    def read_int(self, filename, offset, reallen=None):
        if(reallen != None):
            return self.bytestoint(self.read_data_raw(filename, offset, reallen))
        else:
            return self.bytestoint(self.read_data_raw(filename, offset, self.int_size()))

    def read_ptr(self, filename, offset, reallen=None):
        if(reallen != None):
            return self.bytestoptr(self.read_data_raw(filename, offset, reallen))
        else:
            return self.bytestoptr(self.read_data_raw(filename, offset, self.ptr_size()))

    def write_data_from_file(self, filename, offset, datafile):
        with open(datafile, "r") as file:
            data = file.read()
            self.write_data(filename, offset, data)

    def write_zeros(self, filename, offset, size):
        array = bytearray(size)
        self.write_data(filename, offset, array)

    def write_data(self, filename, offset, data):
        f = os.open(filename, os.O_RDWR|os.O_CREAT)
        os.lseek(f, offset, os.SEEK_SET)
        os.write(f, data)
        os.close(f)

    def write_str(self, filename, offset, data):
        f = os.open(filename, os.O_RDWR|os.O_CREAT)
        os.lseek(f, offset, os.SEEK_SET)
        os.write(f, data)
        os.write(f, '\0')
        os.close(f)

    def write_char(self, filename, offset, c):
        data = self.chartobyte(c)
        f = os.open(filename, os.O_RDWR)
        os.lseek(f, offset, os.SEEK_SET)
        os.write(f, data)
        os.close(f)

    def write_short(self, filename, offset, i):
        data = self.shorttobytes(i)
        f = os.open(filename, os.O_RDWR)
        os.lseek(f, offset, os.SEEK_SET)
        os.write(f, data)
        os.close(f)

    def write_int(self, filename, offset, i):
        data = self.inttobytes(i)
        f = os.open(filename, os.O_RDWR)
        os.lseek(f, offset, os.SEEK_SET)
        os.write(f, data)
        os.close(f)

    def write_ptr(self, filename, offset, ptr):
        data = self.ptrtobytes(ptr)
        f = os.open(filename, os.O_RDWR)
        os.lseek(f, offset, os.SEEK_SET)
        os.write(f, data)
        os.close(f)

    def write_single(self, filename, offset, num, len):
        if(len == self.ptr_size()):
            self.write_ptr(filename, offset, num)
        elif(len == self.int_size()):
            self.write_int(filename, offset, num)
        elif(len == self.short_size()):
            self.write_short(filename, offset, num)
        elif(len == self.char_size()):
            self.write_char(filename, offset, num)
        else:
            print "unknown data type of length: %d" % len
            raise

    def read_single(self, filename, offset, len):
        if(len > self.ptr_size()):
            print "data type '%d' is too long for a single read" % len
        elif(len > self.int_size() and len <= self.ptr_size()):
            return self.read_ptr(filename, offset, len)
        elif(len > self.short_size() and len <= self.int_size()):
            return self.read_int(filename, offset, len)
        elif(len > self.char_size() and len <= self.short_size()):
            return self.read_short(filename, offset)
        elif(len == self.char_size()):
            return self.read_char(filename, offset)
        else:
            print "ptr_size: %d" % self.ptr_size()
            print "unknown data type of length: %d" % len
            raise

    def readstr(self, offset):
        f = os.open(self.filename, os.O_RDONLY)
        os.lseek(f, offset, os.SEEK_SET)
        res = ""
        c = unpack('<c', os.read(f, 1))[0]
        while(c != '\0'):
            res += c
            c = unpack('<c', os.read(f, 1))[0]
        os.close(f)
        return res

    def speculative_read(self, ref):
        value = self.dereference(ref)
        if(value != 0):
            return value
        return self.search_exported_symbol(ref)

    def search_exported_symbol(self, ref):
        print "ref: %x" % ref
        vaddr = self.convert_offset_to_vma(self.filename, ref)
        print "vaddr: %x" % vaddr
        vaddr = self.tohexstr(vaddr)
        cmd = "readelf -r -W " + self.filename +\
                   "|grep " + vaddr
        ll = self.get_matched_lines(cmd)
        if((not ll) or (not ll[0])):
            return 0
        symbolname = ll[0][4]
        cmd = "readelf --dyn-syms -W " + self.filename +\
                   "|grep " + symbolname
        ll = self.get_matched_lines(cmd)
        if((not ll) or (not ll[0])):
            return 0
        value = int(ll[0][1], 16)
        return value

    def convert_offset_to_vma(self, offset):
        if(isinstance(offset, basestring)):
            offset = int(offset, 16)
        if((not isinstance(offset, int)) and (not isinstance(offset, long))):
            print "offset not int or long type, return"
            return None
        regex = re.compile(r"^\s*LOAD\s+(?P<offset>\S+)\s+"
                   "(?P<virtual>\S+)\s+"
                   "(?P<physical>\S+)\s+"
                   "(?P<fsize>\S+)\s+"
                   "(?P<msize>\S+)\s+"
                   "(?P<flag>[^0]+)\s+"
                   "(?P<align>\S+)\s*$")
        cmd = "readelf -l -W " + self.filename
        with os.popen(cmd) as file:
            for line in file:
                line = line.rstrip()
                m = regex.match(line)
                if(m != None):
                    start = int(m.group('offset'), 16)
                    fsize = int(m.group('fsize'), 16)
                    #print "start: %x\tfsize: %x" % (start, fsize)
                    if((start <= offset) and (offset <= (start + fsize))):
                        vbase = int(m.group('virtual'), 16)
                        return vbase + offset - start
        return None

    def convert_vma_to_offset(self, vma):
        if(isinstance(vma, basestring)):
            vma = int(vma, 16)
        num = self.get_elfhdr_info(self.filename, "Number of section headers:")
        pattern = re.compile(r"\s*\[\s*(?P<num>[\d]{1,2})\]\s*"
                    "(?P<name>[\S]+)\s*"
                    "(?P<type>[\S]+)\s*"
                    "(?P<addr>[\S]+)\s*"
                    "(?P<offset>[\S]+)\s*"
                    "(?P<size>[\S]+)\s*"
                    "[^\n]*$")

        cmd = "readelf -W -S " + self.filename;
        with os.popen(cmd) as file:
            for line in file:
                line = line.strip();
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

    def compute_align_up(self, value, align):
        return self.compute_align(value, align)

    def compute_align_down(self, value, align):
        if(value % align == 0):
            return value
        return self.compute_align(value, align) - 4096

    def compute_align(self, value, align):
        residue = value % align
        if(residue == 0):
            return value
        return value - residue + align
