

noinst_PROGRAMS = shcoin shcoind .notice

shcoind:
	ln -sf $(top_builddir)/src/share-coin/shcoind

shcoin:
	ln -sf $(top_builddir)/src/share-coin/shcoin

.notice:
	@echo > .notice
	@echo ""
	@echo "It is now safe to perform a 'make install'."
	@echo ""
	@echo "Documentation can be found at: file://$(PWD)/docs/index.html"
	@echo ""

