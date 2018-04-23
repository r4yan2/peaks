#
#   This file is part of SKS.  SKS is free software; you can
#   redistribute it and/or modify it under the terms of the GNU General
#   Public License as published by the Free Software Foundation; either
#   version 2 of the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
#   USA
#
CINCLUDES=-I`ocamlc -where`
CFLAGS+=-O3 -Werror-implicit-function-declaration $(CINCLUDES) -I .
CXXFLAGS+=-O3 $(CINCLUDES) -I .

ifndef OCAMLC
	OCAMLC=ocamlfind ocamlc
endif
ifndef OCAMLOPT
	OCAMLOPT=ocamlfind ocamlopt
endif
ifndef CAMLP4O
	CAMLP4O=camlp4o
endif

export OCAMLC
export OCAMLOPT
export CAMLP4O

include Makefile.local

ifndef PREFIX
	PREFIX=/usr/local
endif
ifeq ($(BDBLIB),)
	OCAMLLIB=
else
	OCAMLLIB= -ccopt $(BDBLIB)
endif

CAMLLDFLAGS=$(foreach x, $(LDFLAGS), -ccopt $(x))

SKSVS=$(shell grep 'version_suffix = "+"' common.ml)
ifeq ($(strip $(SKSVS)),)
WARNERR=
else
WARNERR=-warn-error A
endif

CAMLP4=-pp $(CAMLP4O)
CAMLINCLUDE= -package cryptokit,unix,str,bigarray,num,mysql,batteries,base64,pcre -I lib -I bdb
COMMONCAMLFLAGS=$(CAMLINCLUDE) $(OCAMLLIB) $(CAMLLDFLAGS) -ccopt -Lbdb -dtypes $(WARNERR)
OCAMLDEP=ocamldep $(CAMLP4)
CAMLLIBS=bdb.cma
OCAMLFLAGS=$(COMMONCAMLFLAGS) -linkpkg -g $(CAMLLIBS)
OCAMLOPTFLAGS=$(COMMONCAMLFLAGS) -linkpkg -g -inline 40 $(CAMLLIBS:.cma=.cmxa)

EXE=sks
ALL=$(EXE) sks.8.gz
ALL.bc=$(EXE:=.bc) sks.8.gz

all: cleanall dep $(ALL)
all.bc: $(ALL.bc)

COBJS=crc.o

MOBJS.bc= pSet.cmo pMap.cmo utils.cmo heap.cmo mList.cmo \
       mTimer.cmo mArray.cmo

MOBJS=$(MOBJS.bc:.cmo=.cmx)

ROBJS.bc= settings.cmo db_settings.cmo pstyle.cmo getfileopts.cmo \
	common.cmo channel.cmo eventloop.cmo ehandlers.cmo \
	bitstring.cmo meteredChannel.cmo \
	number.cmo prime.cmo zZp.cmo rMisc.cmo \
	linearAlg.cmo poly.cmo decode.cmo \
	prefixTree.cmo msgContainer.cmo \
	nbMsgContainer.cmo cMarshal.cmo reconMessages.cmo \
	server.cmo client.cmo reconCS.cmo \
	Unique_time.cmo version.cmo
ROBJS=$(ROBJS.bc:.cmo=.cmx)

OBJS.bc=packet.cmo parsePGP.cmo sStream.cmo \
	key.cmo keyHash.cmo keyMerge.cmo \
	fingerprint.cmo wserver.cmo keydb.cmo \
	dbMessages.cmo membership.cmo \
	pTreeDB.cmo \
	reconComm.cmo recoverList.cmo \
	catchup.cmo reconserver.cmo pbuild.cmo

OBJS=$(OBJS.bc:.cmo=.cmx)

RSERVOBJS.bc=reconComm.cmo recoverList.cmo catchup.cmo reconserver.cmo
RSERVOBJS=$(RSERVOBJS.bc:.cmo=.cmx)

ALLOBJS.bc=$(COBJS) $(MOBJS.bc) $(ROBJS.bc) $(OBJS.bc)
ALLOBJS=$(ALLOBJS.bc:.cmo=.cmx)

EXEOBJS.bc=$(RSERVOBJS.bc) pdiskTest.cmo

LIBS.bc= bdb/bdb.cma
LIBS=$(LIBS.bc:.cma=.cmxa)

VERSION := $(shell cat VERSION)
VERSIONPREFIX = sks-$(VERSION)
COMMA_VERSION := $(shell cat VERSION | sed y/./,/)
FILES := $(shell sed s/.*/$(VERSIONPREFIX)\\/\&/ FILES)

# Special case make rules for functions which require preprocessor directives

common.cmx: common.ml VERSION
	$(OCAMLOPT) $(OCAMLOPTFLAGS) \
	-pp "sed s/__VERSION__/$(COMMA_VERSION)/" -c $<

common.cmo: common.ml VERSION
	$(OCAMLC) $(OCAMLFLAGS) -pp "sed s/__VERSION__/$(COMMA_VERSION)/" -c $<

keyMerge.cmo: keyMerge.ml
	$(OCAMLC) $(OCAMLFLAGS) $(CAMLP4) -c $<

keyMerge.cmx: keyMerge.ml
	$(OCAMLOPT) $(OCAMLOPTFLAGS) $(CAMLP4) -c $<

# Special targets

install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install sks $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	install sks.8.gz $(DESTDIR)$(MANDIR)/man8

install.bc:
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install sks.bc $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	install sks.8.gz $(DESTDIR)$(MANDIR)/man8


Makefile.local:
	@if [ ! -e Makefile.local ]; then echo "Makefile.local has to be defined before building. See Makefile.local.unused"; exit 1; fi;

src:
	if [ ! -x $(VERSIONPREFIX) ]; then ln -s . $(VERSIONPREFIX); fi
	tar cfz $(VERSIONPREFIX).tgz $(FILES)
	rm $(VERSIONPREFIX)

# Ordinary targets

sks.8.gz: sks.8
	gzip -9nf sks.8

sks.8: sks.pod
	pod2man -c "SKS OpenPGP Key server" --section 8 -r 0.1 -name sks sks.pod sks.8

spider: $(LIBS) $(ALLOBJS) spider.cmx
	$(OCAMLOPT) -o spider $(OCAMLOPTFLAGS) $(ALLOBJS) spider.cmx

spider.bc: $(LIBS.bc) $(ALLOBJS.bc) spider.cmo
	$(OCAMLC) -o spider.bc $(OCAMLFLAGS) $(ALLOBJS.bc) spider.cmo

sks: $(LIBS) $(ALLOBJS) sks.cmx
	$(OCAMLOPT) -o sks $(OCAMLOPTFLAGS) $(ALLOBJS) sks.cmx

sks.bc: $(LIBS.bc) $(ALLOBJS.bc) sks.cmo
	$(OCAMLC) -o sks.bc $(OCAMLFLAGS) $(ALLOBJS.bc) sks.cmo

nbtest.bc: $(LIBS.bc) $(ALLOBJS.bc) nbtest.cmo
	$(OCAMLC) -o nbtest.bc $(OCAMLFLAGS) $(ALLOBJS.bc) nbtest.cmo

ptest: $(LIBS) $(ALLOBJS) ptest.cmx
	$(OCAMLOPT) -o ptest $(OCAMLOPTFLAGS) $(ALLOBJS) \
	ptest.cmx

ocamldoc.out: $(ALLOBJS) $(EXEOBJS)
	ocamldoc -hide Pervasives,UnixLabels,MoreLabels \
	-dot $(CAMLP4O) -d doc -I lib -I bdb *.mli *.ml

modules.dot: ocamldoc.out
	./recolor.py < ocamldoc.out > modules.dot

modules.ps: modules.dot
	dot -Nfontsize=200 modules.dot -Tps -o modules.ps

doc: $(ALLOBJS) $(EXEOBJS)
	mkdir -p doc
	ocamldoc -hide Pervasives,UnixLabels,MoreLabels \
	-html $(CAMLP4O) -d doc -I lib -I bdb *.mli *.ml

##################################
# LIBS
##################################

bdb/bdb.cmxa: bdb/bdb_stubs.c bdb/bdb_stubs.h
	cd bdb && $(MAKE) bdb.cmxa

bdb/bdb.cma: bdb/bdb_stubs.c bdb/bdb_stubs.h
	cd bdb && $(MAKE) bdb.cma

bdbclean:
	cd bdb && $(MAKE) clean

##################################


prepared:
	mkdir -p lib
	mkdir -p tmp/bin
	mkdir -p tmp/include
	touch prepared


################################
# old stuff
################################
prefix_test: $(ALLOBJS) prefix_test.cmx
	$(OCAMLOPT) -o prefix_test $(OCAMLOPTFLAGS) $(ALLOBJS) prefix_test.cmx

prefix_test.opt: $(ROBJS.opt) prefix_test.cmx
	$(OCAMLOPT) -o prefix_test.opt $(OCAMLOPTFLAGS) $(ROBJS.opt) \
	prefix_test.cmx

pdiskTest: $(LIBS) $(MOBJS) $(ROBJS) pdiskTest.cmo
	$(OCAMLC) -o pdiskTest $(OCAMLFLAGS) $(MOBJS) $(ROBJS) pdiskTest.cmo

pdiskTest.opt: $(LIBS.opt) $(MOBJS.opt) $(ROBJS.opt) pdiskTest.cmx
	$(OCAMLOPT) -o pdiskTest.opt $(OCAMLOPTFLAGS) \
	$(MOBJS.opt) $(ROBJS.opt) pdiskTest.cmx

pdtcaml: $(LIBS) $(ROBJS) pdiskTest.cmo
	ocamlmktop -o pdtcaml -custom $(CAMLLIBS) $(CAMLINCLUDE) \
	$(ROBJS) pdiskTest.cmo

dumbloop: $(LIBS) $(ALLOBJS) dumbloop.cmo
	$(OCAMLC) -o dumbloop $(OCAMLFLAGS) $(ALLOBJS) dumbloop.cmo

scan: $(OBJS) cryptokit dblib scan.ml
	$(OCAMLC) -o scan $(OCAMLFLAGS) $(OBJS) scan.ml

printids: $(OBJS:.cmo=.cmx) cryptokit printids.ml
	$(OCAMLOPT) -o printids $(OCAMLOPTFLAGS) $(OBJS:.cmo=.cmx) printids.ml

printids.bc: $(OBJS) cryptokit printids.ml
	$(OCAMLC) -o printids $(OCAMLFLAGS) $(OBJS) printids.ml

rcaml: $(LIBS.bc) $(ALLOBJS.bc)
	ocamlmktop -o rcaml -custom $(CAMLLIBS) $(CAMLINCLUDE) \
	$(ALLOBJS.bc) $(OCAMLLIB)



# Common rules
.SUFFIXES: .mli .ml .cmo .cmi .cmx

.ml.o:
	$(OCAMLOPT) -output-obj $(OCAMLOPTFLAGS) $<

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $<

.c.o:
	$(CC) $(CFLAGS) -c $<

.c.obj:
	$(CC) $(CFLAGS) /c $<

.ml.cmo:
	$(OCAMLC) $(OCAMLFLAGS) -c $<

.mli.cmi:
	$(OCAMLC) $(OCAMLFLAGS) -c $<

.ml.cmx:
	$(OCAMLOPT) $(OCAMLOPTFLAGS) -c $<


# Clean up
mlclean:
	rm -f *.cm[iox]
	rm -f *.annot
	rm -f *.opt
	rm -f *.bc
	rm -rf spider sksclient
	rm -f $(ALL) $(ALL.bc)

clean: mlclean
	rm -f *.o
	rm -f prepared
	rm -f sks.8.gz

cleanall: clean bdbclean
	rm -f lib/*

distclean: cleanall
	rm -rf Makefile.local
	rm -rf .depend tmp lib

# Dependencies

dep:
	$(OCAMLDEP) $(INCLUDES) *.mli *.ml > .depend

-include .depend

# DO NOT DELETE
# Verificare se ok assenza wserver e htmlTemplate