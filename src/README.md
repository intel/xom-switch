[OverView]

xom-switch is the eXecutable-Only-Memory (XOM) enabling tool for x86 Linux
system. It aims to mitigate code disclosure guided ROP attacks by using Intel
Protection Keys feature in recent Intel CPU models. xom-switch protects all
code modules in the runtime including executable and dependent libraries
without requiring source code or heavyweight binary translation/rewriting.
xom-switch protects programs in non-intrusive way by patching only program
loader (ld.so).

Clarification: This code is for demo purpose only and the status of code is
"alpha".


[Dependency]

xom-switch requires two tools:
  -- python 2.7.
  -- radare2, static binary analyzer, which could be found here:
     https://github.com/radare/radare2.git

[Components]

xom-switch consists of three modules:
 -- vino: static binary rewriter
 -- patch: C code piece that will be patched into program loader
 -- analyzer: analyzer of the program loader using radare2

[Getting Started]

 -- install python 2.7 and radare2
 -- patch your loader: src/analyzer/patch_loader.sh /lib64/ld-linux-x86-64.so.2 /your/new/ld.so
 -- copy your loader to system dir: mv /your/new/ld.so /lib64/ld-xom.so
 -- run your program: /lib64/ld-xom.so /path/to/your/program

[LICENSE]
This code is published under GPLv2 or later version.

