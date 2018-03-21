#!/usr/bin/python
import re
import sys
import argparse
import elf_basic
from elf_helper import *
class hex_match(object):
    def __init__(self, filename, pattern):
        self.filename = filename
        self.vh = elf_helper(filename)
        self.f = open(filename, 'rb')
        self.data = self.f.read()
        self.pattern = pattern

    def reorder_hex(self, hexstr):
        hexlen=len(hexstr)
        byte="([0-9a-fA-F]{2})"
        if(hexlen == 8):
            pattern = "{0}{1}{2}{3}".format(byte,byte,byte,byte)
            regex = re.compile(pattern)
            m = regex.match(hexstr)
            if(m != None):
                return "\\x{0}\\x{1}\\x{2}\\x{3}".format(m.group(4),
                                                     m.group(3),
                                                     m.group(2),
                                                     m.group(1))
        elif(hexlen == 16):
            pattern = "{0}{1}{2}{3}{4}{5}{6}{7}".format(byte,byte,byte,byte,
                                                        byte,byte,byte,byte)
            regex = re.compile(pattern)
            m = regex.match(hexstr)
            if(m != None):
                return "\\x{0}\\x{1}\\x{2}\\x{3}\\x{4}\\x{5}\\x{6}\\x{7}".\
                        format(m.group(8),
                               m.group(7),
                               m.group(6),
                               m.group(5),
                               m.group(4),
                               m.group(3),
                               m.group(2),
                               m.group(1))
            else:
                print "regex does not match"
                return None
        else:
            return None


# convert hex integer sequence to hex string pattern. e.g.
# '0x00100020 0xaf080009' => '\x20\x00\x10\x00\x09\x00\x08\xaf'
    def convert_hexints_to_hexpattern(self, strhexints):
        if(self.vh.isx86_32()):
            phexint = "([0-9a-fA-F]{8})"    
            phexints = "[0-9a-fA-F]{8}( [0-9a-fA-F]{8})*$"
        else:
            phexint = "([0-9a-fA-F]{16})"    
            phexints = "[0-9a-fA-F]{16}( [0-9a-fA-F]{16})*$"

        rhexints = re.compile(phexints)
        #print "phexints: {}".format(phexints)
        #FIXME: avoid partial match of rhexints
        m = re.match(phexints, strhexints)
        if(m != None):
            True #print "input pattern matched"
        else:
            print "input pattern not matched, check your syntax"
            return None
        rhexint = re.compile(phexint)
        pattern=""
        for match in rhexint.finditer(strhexints):
            pattern += self.reorder_hex(match.group(1))
        return pattern

    def search_all_hexpattern(self, pattern=None):
        if(pattern == None):
            pattern = self.pattern
        hexpattern = self.convert_hexints_to_hexpattern(pattern)
        if(hexpattern == None):
            return None
        regex = re.compile(hexpattern)
        listLoc = []
        for match_obj in regex.finditer(self.data):
            offset = match_obj.start()
            #print "offset: {0}\t{1}".format(hex(offset), hexpattern)
            listLoc.append(offset)
        #print listLoc
        return listLoc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, help="file to search",
                        required=True)
    parser.add_argument("-p", "--pattern", type=str, help="pattern to search",
                        required=True)
    args = parser.parse_args()
    hpmatch = hex_match(args.file, args.pattern)
    hpmatch.search_all_hexpattern(args.pattern)


if __name__ == "__main__":
	main()
