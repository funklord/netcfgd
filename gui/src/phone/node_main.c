/*
 * node_main.c -- the program the app carries as `libncfgnode.so`: `ncfg node`'s
 * core with nothing around it, the daemon's being no use on a phone (10.734).
 */
#include "ncfg/node.h"

int main(int argc, char **argv)
{
	return ncfg_node_user_main(argc, argv, 0);
}
