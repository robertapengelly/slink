#******************************************************************************
# @file             Makefile.wat
#******************************************************************************
SRCDIR              ?=  $(CURDIR)
VPATH               :=  $(SRCDIR)

SRC                 :=  aout.c coff.c elks.c hashtab.c ld.c lib.c link.c map.c mz.c omf.c pe.c report.c section.c symbol.c vector.c write7x.c

all: slink.exe

slink.exe: $(SRC)

	wcl -fe=$@ $^

clean:

	for /r %%f in (*.obj) do ( if exist %%f ( del /q %%f ) )
	if exist slink.exe ( del /q slink.exe )
