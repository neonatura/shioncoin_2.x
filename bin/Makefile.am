

noinst_PROGRAMS = usde shc shcoind .notice

shcoind:
	ln -sf $(top_builddir)/src/share-coin/shcoind

shc:
	ln -sf $(top_builddir)/src/share-coin/shc

usde:
	ln -sf $(top_builddir)/src/share-coin/usde


.notice:
	@echo > .notice
	@echo ""
	@echo "It is now safe to perform a 'make install'."
	@echo ""
	@echo "Documentation can be found at: file://$(PWD)/docs/index.html"
	@echo ""

