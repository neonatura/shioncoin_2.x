

noinst_PROGRAMS = shc shcoind .notice

if USDE_SERVICE
noinst_PROGRAMS += usde

usde:
	ln -sf $(top_builddir)/src/share-coin/usde
endif

shcoind:
	ln -sf $(top_builddir)/src/share-coin/shcoind

shc:
	ln -sf $(top_builddir)/src/share-coin/shc


.notice:
	@echo > .notice
	@echo ""
	@echo "It is now safe to perform a 'make install'."
	@echo ""
	@echo "Documentation can be found at: file://$(PWD)/docs/index.html"
	@echo ""

