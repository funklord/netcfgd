/*
 * scope.h -- how far a configuration key travels.
 *
 * WHY SCOPES AND NOT A BOOLEAN
 *   project.md 10.322. netcfgd serves a machine that will only ever be one
 *   machine and an estate of thousands, both in full, and the strength is in
 *   merging them without custom scripting. A local/network boolean cannot
 *   express the case that breaks it: **a fact about one host that the estate
 *   should nonetheless see**, which is what an interface's address is.
 *
 * THE SCOPE VOCABULARY IS FUZZNET'S, AND THIS ENUM IS A PLACEHOLDER
 *   **Settled by the copyright holder 2026-09-29: the scopes are a general
 *   feature of fuzznet, not netcfgd's.** Every consumer of a shared estate
 *   needs the same four-or-more answers about how far a value travels, and a
 *   second vocabulary here is how two trees come to disagree about one
 *   concept.
 *
 *   So `ncfg_scope_t` exists only until fuzznet carries it, and it is named
 *   and shaped to be replaced rather than reconciled: when that type lands,
 *   this enum goes and the table in `compile/scope.c` is retyped onto it. What
 *   stays netcfgd's is the **table**, because which scope `prefix` belongs to
 *   is a fact about netcfgd's language that no other consumer can know.
 *
 *   Signalled to fuzznet rather than assumed -- project.md 10.323.
 *
 * A SCOPE IS A CELL'S SUBJECT, WHICH IS WHY THE SET CAN GROW
 *   fuzznet's `state/` is `(issuer, subject, kind) -> value`. Estate-wide is a
 *   cell whose subject is the estate, group-wide one whose subject is that
 *   group, host-scoped one whose subject is the host. **Adding a scope is
 *   adding a kind of subject, not a mechanism**, so the holder's "probably
 *   more than these" costs a value here and nothing structural.
 *
 *   `HOST_PRIVATE` is the scope with no cell at all. It never enters the
 *   shared database, which is what keeps constraint 2 true: a machine that
 *   never joins an estate has no subject, no cells, and the file on its disk
 *   exactly as today.
 */
#ifndef NCFG_SCOPE_H
#define NCFG_SCOPE_H

typedef enum {
	/*
	 * **Zero, and the direction matters more here than the value.** A key
	 * nobody classified must not be replicated: widening a scope publishes
	 * configuration the author never offered to anyone, and narrowing it only
	 * fails to share something. The safe default is therefore the narrowest,
	 * and it sits at zero so an omission and the test that catches omissions
	 * point the same way -- the arrangement `NCFG_TIER_OBSERVE` does not have
	 * and `NCFG_ORDER_AT_MOST_ONCE` does.
	 */
	NCFG_SCOPE_HOST_PRIVATE = 0,
	/* About this host, and replicated so the estate can see and manage it.
	 * An interface's address is the case this exists for. */
	NCFG_SCOPE_HOST,
	/*
	 * Less than the estate: a zone, a building, a VLAN domain.
	 *
	 * **The name is provisional.** The holder said "less-than-estate-wide"
	 * and did not name it; `group` is a placeholder and renaming it is a
	 * spelling change here and in the table, not a design one.
	 */
	NCFG_SCOPE_GROUP,
	/* The whole estate. */
	NCFG_SCOPE_ESTATE,
	NCFG_SCOPE_COUNT
} ncfg_scope_t;

/* The language's top-level blocks, as `lower.c` dispatches on them. */
typedef enum {
	NCFG_BLOCK_GLOBAL = 0,
	NCFG_BLOCK_DEVICE,
	NCFG_BLOCK_INTERFACE,
	NCFG_BLOCK_NETWORK,
	NCFG_BLOCK_ACCESS_POINT,
	NCFG_BLOCK_BLUETOOTH,
	NCFG_BLOCK_RULE,
	NCFG_BLOCK_LINKSET,
	NCFG_BLOCK_COUNT
} ncfg_block_t;

/* The block of that name, or 0 for one this build does not know. */
int ncfg_block_from_name(const char *name, ncfg_block_t *out);

/* Its spelling in the language. */
const char *ncfg_block_name(ncfg_block_t block);

/*
 * HOW FAR A KEY TRAVELS
 *
 * **A block default and a short exception list, not a table of every key.**
 * The language has around a hundred and ninety key strings across five
 * lowering files, and the holder's instruction is to merge the two worlds
 * *without too many special cases* -- which a hundred and ninety judgements
 * falsifies however carefully each is made.
 *
 * So the rule does the work and the exceptions are the design: **a key is
 * host-private when its value names something only this machine can see, and
 * wider when it describes the network and two machines could hold it
 * identically.** `network` and `access_point` are estate-wide entire;
 * `device` is host-private entire; `interface` is the only genuinely mixed
 * block and carries most of the exceptions.
 *
 * `key` of NULL asks for the block's default.
 */
ncfg_scope_t ncfg_scope_of(ncfg_block_t block, const char *key);

/* What the block would answer with no exception, for a caller that wants to
 * know whether a key was one. */
ncfg_scope_t ncfg_block_default_scope(ncfg_block_t block);

/*
 * THE KIND REGISTRY
 *
 * A configuration key that travels is carried as a record, and a record's
 * `kind` is a `uint32_t` **on the wire, inside records other hosts hold and
 * have signed**. So a number assigned to a key cannot move: every estate
 * holding records under it keeps them, and a renumbering makes a host read
 * somebody's `mtu` as their `dns_mode` while every signature still verifies.
 * `record/store.h`'s MISPLACED guards the adjacent fault and says why the
 * class is dangerous -- such a record "may be perfectly well signed, which is
 * why a signature check further up would not have caught this".
 *
 * **This is a protocol registry, not an enum.** Three rules follow:
 *
 *   - **Numbers are explicit, never ordinals.** An enum's order is something
 *     somebody reorders while tidying; a wire value is not.
 *   - **Assigned once and never reused**, including for a key that is removed.
 *     A retired number stays retired, because records under it outlive the key
 *     -- see `RETIRED` in `compile/scope.c`.
 *   - **Only a key that travels gets one.** A host-private key never becomes a
 *     record, so it needs no wire number and must not have one.
 *
 * **Zero is not a kind.** A key with no number returns 0, which means "cannot
 * be represented as a record yet" rather than a kind whose number happens to
 * be low -- so a zeroed field is never a valid lookup, and an unregistered key
 * fails loudly at the point of writing instead of quietly acquiring a
 * neighbour's meaning.
 *
 * **THE REGISTRY IS INCOMPLETE AND CANNOT BE GATED, WHICH IS RECORDED RATHER
 * THAN GLOSSED.** The language recognises keys through chains of `strcmp` in
 * `compile/lower_*.c` and nothing enumerates them, so no test can assert that
 * every travelling key has a number -- the exhaustiveness used for request
 * kinds and for blocks has no analogue here. What makes the gap safe rather
 * than dangerous is the zero above: a missing key cannot be written wrongly,
 * only not at all. project.md 10.325 records what would close it.
 */
#define NCFG_KIND_NONE 0u

/* The number this key travels under, or `NCFG_KIND_NONE`. */
unsigned ncfg_kind_of(ncfg_block_t block, const char *key);

/* Whether a number has ever been assigned, including to a retired key. For a
 * test, and for whoever allocates the next one. */
int ncfg_kind_is_taken(unsigned kind);

#endif /* NCFG_SCOPE_H */
