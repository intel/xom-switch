## Rewriter
This is a baseline binary instrumentation tool for x86 ELF binaries on Linux. It works on both 64-bit and 32-bit ELF files and it works properly on Position-Independent Executable (PIE) and non-PIE and shared libaries. To use 

## Background
Binary instrumentation often requires inserting new code or data into an existing binary. However, ELF files compiled by modern compilers (gcc and llvm) do not have sufficient space to put extra code or data. This is because that compilers would generate binaries in a compact form for smaller memory footprint.

This tools helps solving the space issue for binary instrumentation. It works by extending an existing ELF file with extra loadable (PT_LOAD) segments, following the specification of program loader. This ensures that the generated ELF files functions well.

## Getting Started
To get started, check out files in examples directory.

### Writing your code in ASM and inject your code.
To write your code in assembly, you need to put your code in a ".s" file and use assembler to generated an object file. For instance, you may write the following assembly code in a file called test.s:
```
.global _start
_start:
  xorq %rax,%rax
```
After finish code development, assemble it into an object file:
```
gcc -c test.s
```
Now inject your code into an existing file.
```
./example/inject_only_code_segment.py -f /bin/ls -i test.o -o myls
```
Note:
 - "/bin/ls" is the file you want to instrument;
 - only the ".text" section of test.o will be injected into /bin/ls
 
### Writing your code in C (limited support) and inject your code.

TO BE ADDED...
