

noinst_PROGRAMS = shc shcoind .notice

if USDE_SERVICE
noinst_PROGRAMS += usde

usde:
	ln -sf $(top_builddir)/src/coin-console/usde
endif

if EMC2_SERVICE
noinst_PROGRAMS += emc2

emc2:
	ln -sf $(top_builddir)/src/coin-console/emc2
endif

shcoind: docs
	ln -sf $(top_builddir)/src/share-coin/shcoind

shc:
	ln -sf $(top_builddir)/src/coin-console/shc

docs:
	ln -sf $(top_builddir)/doc/html/ docs


.notice:
	@echo > .notice
	@echo ""
	@echo "It is now safe to perform a 'make install'."
	@echo ""
	@echo "Documentation can be found at: file://$(PWD)/docs/index.html"
	@echo ""

