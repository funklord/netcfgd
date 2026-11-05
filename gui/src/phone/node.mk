# The phone's node, linked as fuzznet links fuzznetd. Read after fuzznet's own
# Makefile (`make -C fuzznet -f Makefile -f ../gui/src/phone/node.mk`), so the
# object list and the flags are fuzznet's, asked for rather than copied:
# FUZZNETD_LINK is everything fuzznetd is but its main.
NCFG_NODE_OBJS = $(BUILD_DIR)/ncfg_node_main.o $(BUILD_DIR)/ncfg_user_node.o

$(BUILD_DIR)/ncfg_node_main.o: ../gui/src/phone/node_main.c ../c/include/ncfg/node.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -I../c/include -I../client -c $< -o $@

$(BUILD_DIR)/ncfg_user_node.o: ../c/src/node/user_node.c ../c/include/ncfg/node.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -I. -Iwire/generated -I../c/include -I../client -c $< -o $@

$(NCFG_NODE_OUT): $(NCFG_NODE_OBJS) $(FUZZNETD_LINK)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS_GC) $^ -o $@ $(if $(LOG_PACK_ON),$(ZSTD_LIBS))
