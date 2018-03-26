#!/usr/bin/python
import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from instrumentor import *

class code_injector(instrumentor):
    def __init__(self, name, filename, secname, objfile):
        super(code_injector, self).__init__(name, filename, secname)
        self.obj_file = objfile
        self.inject_file = self.get_tempfile()
        self.mapping = dict()

    def generate_instrumentation(self, asmfile):
        pass

    def compile_inject_instrument_file(self, asmfile, objfile, injectfile,
                                       secname, align):
        self.extract_data(objfile, '.text', injectfile, padalignpage=False)
        self.add_instrumentation_data(self.get_current_file(), injectfile,
                                      secname, align)
    def patch_relocation(self, binname):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, help="ELF file to instrument",
                        required=True)
    parser.add_argument("-i", "--inject", type=str, help="ELF file to be injected",
                        required=True)
    parser.add_argument("-o", "--output", type=str, help="Output ELF file location",
                        required=False)
    args = parser.parse_args()
    scheduler = instrument_scheduler()
    codeinjector = code_injector('instrumented_code', args.file,
                               '.instrumented_code', args.inject)
    scheduler.register_instrumentor(codeinjector)
    scheduler.perform_instrumentation()
    print scheduler.get_current_file()
    if(args.output == None):
        return
    bname = os.path.basename(args.file)
    if(os.path.isdir(args.output)):
        os.system("mv %s %s" % (scheduler.get_current_file(),
                                os.path.join(args.output, bname)))
    else:
        os.system("mv %s %s" % (scheduler.get_current_file(), args.output))

if __name__ == "__main__":
	main()
