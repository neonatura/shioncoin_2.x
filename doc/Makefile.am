AM_CFLAGS = -DDATADIR=\"$(datadir)\"

htmldir = html 

dist_docdir = $(datadir)/@PACKAGE@

if HAVE_DOXYGEN
dist_doc_DATA = shcoin_html.tar.xz
endif


if HAVE_HELP2MAN
dist_man_MANS = \
	man/man1/shcoin.1 \
	man/man1/shcoind.1

man/man1/shcoin.1: helpfile.stamp
man/man1/shcoind.1: helpfile.stamp

helpfile.stamp:
	mkdir -p man/man1
	$(HELP2MAN) --output=man/man1/shcoin.1 --name='share-coin command-line tool' $(top_builddir)/src/share-coin/shcoin
	$(HELP2MAN) --output=man/man1/shcoind.1 --name='share-coin daemon' $(top_builddir)/src/share-coin/shcoind
	echo Timestamp > helpfile.stamp
endif


if HAVE_DOXYGEN

$(htmldir): doxyfile.stamp

doxyfile.stamp:
	mkdir -p html man
	$(DOXYGEN) doxygen.conf
	echo Timestamp > doxyfile.stamp

shcoin_html.tar.xz: doxyfile.stamp
	rm -f shcoin_html.tar.xz
	tar -cpf shcoin_html.tar $(htmldir)
	xz shcoin_html.tar
	rm -f shcoin_html.tar

else

doxyfile.stamp:
	mkdir -p man
	echo Timestamp > doxyfile.stamp

endif

CLEANFILES = helpfile.stamp doxyfile.stamp

EXTRA_DIST = $(htmldir)

all-local: doxyfile.stamp helpfile.stamp
clean-local:
	rm -f doxyfile.stamp helpfile.stamp
	rm -rf $(top_builddir)/doc/man
	rm -rf $(top_builddir)/doc/$(htmldir)

