#******************************************************************************
# @file             Makefile.wat
#******************************************************************************
SRCDIR              ?=  $(CURDIR)
VPATH               :=  $(SRCDIR)

SRC                 :=  aout.c axe.c coff.c dx.c elf.c elks.c hashtab.c ld.c lib.c link.c ll.c macho.c map.c mz.c omf.c pe.c report.c section.c symbol.c vector.c write7x.c

all: slink.exe

slink.exe: $(SRC)

	wcl -ml -fe=$@ $^

clean:

	for /r %%f in (*.obj) do ( if exist %%f ( del /q %%f ) )
	if exist slink.exe ( del /q slink.exe )
