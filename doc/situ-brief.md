# What netcfgd would need from situ

**Audience: whoever authors `situ`.** Written 2026-09-06, on being asked
whether situ could describe the format a separated config compiler would use.

**Status: netcfgd's requirements and netcfgd's measurements, not situ's
design.** Everything said about situ below is cited to a section of its own
`project.md` and is that project's to correct; everything said about netcfgd is
measured here and is checkable. Where the two are compared, the comparison is
mine.

The short version is that situ is the right tool for one thing netcfgd already
plans and the wrong tool for the thing it was just asked about, and the reason
is a single requirement rather than a missing feature.

---

## 1. The one-line answer

**netcfgd's document must be greppable JSON, and situ describes binary
layouts.** That is not a gap to close with a keyword; it is the premise of each
project pointing the other way, and it decides every use below.

Where a binary frame crossing a trust boundary is what is wanted, situ is
already netcfgd's plan and has been since before this was asked --
`doc/socket-protocol.md` 3.2 names "a `situ`-described frame with Monocypher as
the codec" for the remote path. That use is unaffected by anything here.

---

## 2. What would have to cross the boundary

The question was whether a config compiler could run in a process with no
privileges, returning its result over a pipe. What it would return, measured
across `crates/netcfgd-model/src`:

| | count |
|---|---|
| structs | 78 |
| enums | 42 |
| enum variants carrying a payload | ~43 |
| fields that are `Option<..>` | 177 |
| fields that are `Vec<..>` | 58 |
| fields that are `String` | 41 |
| fields that are a fixed-width scalar | 65 |
| fields that are another model type | 64 |

**Not recursive, and measured properly rather than by absence of `Box<..>`.**
The model's field types form a graph of 117 nodes: **no type names itself, there
are no cycles at all, and the nesting depth from `Document` is 7.**

That number was got wrong first. A count over every capitalised token in each
type's body reported 14 cycles and a depth of 14 -- it was matching enum variant
names and doc-comment words as if they were field types. A model with a genuine
cycle and no `Box<..>` would not compile, which is what made the answer worth
disbelieving. The corrected walk reads field types only.

**276 of 405 fields are optional, repeated, or unbounded text.** A document for
twenty interfaces is 10,484 bytes of JSON; the frozen maximal witness is
115,004.

---

## 3. What fits, in situ's own terms

More than a first reading suggests, and it is worth saying before the parts
that do not:

- **Both backends netcfgd needs are done.** Section 20.1 lists C, C++, Python
  and Rust as done. netcfgd is Rust today and may become C
  (`doc/c-transition.md`), so the two that matter are both there.
- **Variable-length repetition exists.** Section 8.5's `T x[expr]` takes its
  length from a prior field and `T x[remaining]` runs to the end of the frame.
  netcfgd's 58 `Vec` fields have a spelling.
- **Tagged unions exist.** Section 9.6 `variant`, for the ~43 payload-carrying
  variants.
- **TLV exists** (9.5), which is how the 177 optional fields would be carried.
- **Text is checked rather than assumed.** Section 8.6 has no string type --
  text is `u8 name[N]` with `[encoding = ascii | utf8]`, validated strictly in
  the sense RFC 3629 requires, an overlong form or a surrogate half refused.
  netcfgd validates none of its own `String` fields for encoding; situ would
  be stricter than what it replaced, which is the right direction.

So the shapes are expressible. The difficulty is elsewhere.

---

## 4. Why the document does not fit, and it is one reason

**situ has no text format**, and netcfgd's document has to be one.

Measured in situ's `project.md`: ten occurrences of "json", every one about
situ's own tooling -- `--diagnostics=json`, `situc lsp` speaking JSON-RPC. The
codec families in section 13 are `table` (Manchester, 4b5b, base64),
`polynomial` (CRC, Reed-Solomon), `permutation` (interleavers) and `stuffing`
(HDLC, COBS). Line codes, not structured text.

**And JSON is not a netcfgd preference, it is constraint 7.** Runtime state
under `/run` is greppable JSON so that a machine being debugged over a network
it is in the middle of reconfiguring can be read with `cat`. The two schema
witnesses are JSON. `doc/shared-protocol-brief.md` 4 puts it as: not being a
black box is the product, a shell script with `jq` is a legitimate client, and
diagnosis without a decoder is the case that matters.

So a situ-described compiler pipe would mean **two encodings of one model** --
situ's binary on the pipe, JSON on disk and in the witnesses. Two encodings of
one thing is two things that must agree, which is the failure class netcfgd's
own decision records 0081, 0082 and 0083 are about.

---

## 5. The question worth more than the one that was asked

The compiler pipe is a small format. The interesting question is the model
itself, and it is worth putting because it is where situ would actually pay.

**serde is 508,084 bytes of netcfgd's 2,783,768-byte binary -- 18.3%.**
Measured two ways that agree within 5% (symbol attribution over the release
binary, and a link differential over four scratch builds). The split:

    serde and serde_json themselves          232,562
    netcfgd's own derived codecs             267,993
    itoa, memchr, zmij                         7,529

`netcfgd-model` is 168,328 bytes of derived codec against 53,037 bytes of
everything else: **three quarters of that crate is serialization.** A C port
would hand-write those codecs, and hand-written codecs are far smaller than
monomorphised generic ones -- which is most of the size argument for the C
transition.

**A schema compiler generating them is exactly the answer to that**, and situ
is the schema compiler this workspace already has. It would generate Rust now
and C after the transition, from one description, which is the thing that stops
the codecs being written twice.

It runs into section 4 immediately: those codecs encode the model, and the
model is what has to be JSON.

---

## 6. So what would situ have to gain

In the order netcfgd would value them, with netcfgd's numbers attached so the
size of each is visible rather than asserted:

1. **A structured-text codec family.** This is the whole of it. Not "add JSON"
   -- a family in section 13's sense whose members are text encodings, where
   the schema keeps describing the model and the codec decides the spelling.
   It collides with "byte-exact data layouts" as the premise and with the
   non-goal "not a serialization library for language-native objects", so it
   may be correctly out of scope. **If it is out of scope, say so and this
   brief is finished** -- everything below only matters if this is not.

   **Situ's author reports that the v0 ban on recursive types is being lifted,
   so that every format is describable, and that JSON needs it.** That is
   right about JSON's grammar -- a value contains values -- and it is worth
   separating from what netcfgd needs, because the two are different sizes.

   - **Describing arbitrary JSON needs recursion in the schema.** Depth is
     whatever the input has.
   - **Describing netcfgd's document, spelled as JSON, does not.** The schema
     is acyclic and 7 deep, measured above. The recursion lives in the
     *codec*, not in the type being described.

   The distinction has a consequence for situ's own invariants rather than for
   netcfgd. Section 20.1 promises the C backend "no recursion, bounded stack";
   section 2 gives non-terminating size and capability computation as the
   reason recursion was banned. **A decoder for a schema of known depth keeps
   both** -- an explicit stack of 7 is a compile-time constant, exactly as an
   array's `max` is. A decoder for arbitrary JSON keeps neither, because
   nothing bounds the depth.

   So if the lift is to serve both, the shape that seems to fit situ's existing
   grain is **a declared depth bound on a recursive type, the same mechanism
   `max` already is for arrays**: bounded recursion stays inside invariant 4
   and stays decidable, unbounded recursion is the case that needs the
   allocator question of decision 0031. That is a suggestion from outside and
   situ's author is better placed to say whether it holds.

2. **A first-class optional.** 177 of 405 fields. TLV carries it, but the
   schema author then makes 177 TLV decisions to say something the source
   language says with one word, and the generated accessor is "was the tag
   there" rather than a presence type. This is bounded and actionable
   independent of item 1.

3. **A declared-UTF-8 string reaching the backend as text.** 41 fields.
   Section 8.6 validates the encoding, which is more than netcfgd does today;
   what would help is the Rust backend handing back `&str` where
   `[encoding = utf8]` is declared rather than `&[u8]`, so the boundary does
   not re-validate what the codec already checked.

4. **A question rather than a request: does `situc` have a schema this size in
   its own tests?** 78 structs, 42 enums, 405 fields, nested five deep. netcfgd
   does not know, and a compiler that is fast on a 40-field frame may not be on
   this. Worth knowing before either project plans around it.

5. **Speculative, and marked as such.** With 58 dynamically-sized repetitions,
   every enclosing frame in this schema is dynamic, so the capability lattice
   would report `sequential` and non-addressable for essentially everything. If
   situ ever wants this class of user, the advisor saying that once about the
   schema would be worth more than saying it per field. netcfgd has not run
   `situc` on anything, so this is a prediction from section 8.5's rules and
   not an observation.

---

## 6a. The outstanding list, and it is one question with six symptoms

Section 6 was written by stopping at the first blocker. With recursion being
lifted and a text codec therefore conceivable, the rest deserves the survey it
did not get -- and the authoritative list is not what netcfgd noticed, it is
what netcfgd's model **already asks of serde**. Every attribute in use is a
feature any replacement has to express. Counted across `netcfgd-model` and
`netcfgd-proto`:

| what the model asks for | uses | situ today |
|---|---|---|
| a structured-text codec at all | -- | none; section 13's families are line codes |
| `default` -- absent on decode means this value | 295 | none; `default` in situ is enum unknown-value handling (8.7), a different thing wearing the same word |
| `skip_serializing_if` -- omit on encode when a predicate holds | 226 | none |
| `deny_unknown_fields` -- an unknown member is an error | 89 | **already agreed**, and strongly: section 2 and 14.5 make never preserving unknown fields a security position |
| `rename_all` and `rename` -- the external name differs from the identifier | 51 | none; "external name" and "wire name" appear zero times in the specification |
| `tag` -- the discriminant is a member of the same object | 7 | 9.6 requires the discriminant parsed **strictly before** the variant in layout order |
| recursive types | 0 for this schema | being lifted; needed for arbitrary JSON, not for this document |

**Five of those six are the same fact.** situ describes positional binary
layouts, where a field's identity is its offset and its order is structural.
A text format has the opposite properties: **fields are identified by name and
have no order.** So the missing pieces are not six features, they are one
design question -- *what is a member's external identity, and what may be
absent* -- asked six ways.

That is worth saying because a feature list invites six separate additions,
and the shape of the answer is probably one addition. It also predicts which
of situ's existing rules would need re-examining rather than extending: 9.6's
"strictly before in layout order" is not a restriction that can be relaxed for
text, it is a statement about a world where order exists.

**The one that is already right is worth as much as the gaps.** netcfgd's 89
`deny_unknown_fields` and situ's refusal to preserve unknown fields are the
same position reached separately, and it is the position most serialisers get
wrong in the other direction.

**This section is to be redone once recursion lands**, at the copyright
holder's instruction, and the numbers above are the baseline to redo it
against.

## 7. What netcfgd is not asking for, and one thing against itself

**Not the capability lattice.** In-place mutability, addressability and
authentication coverage are situ's core (section 0 rule 1) and are worth
nothing to a pipe between a process and its own child. netcfgd would be using
situ for codegen and schema diffing alone, which is a thin slice of what the
project is for. That is a reason for situ to weigh the request rather than a
reason to grant it.

**And netcfgd's own record argues against generated bindings**, which is worth
relaying because it is evidence rather than an opinion.
`doc/shared-protocol-brief.md` 4: `client/` is a C implementation of netcfgd's
socket protocol written in a separate workspace against the *witness* rather
than against the Rust types, and building it found **three defects in the
protocol itself** -- a request the daemon accepted that no client could send
(0081), and one operation carrying two different names depending on which
message it appeared in (0082, 0083). That document says in as many words that
generated bindings would not have produced them, because the second
implementation would have come from the same source as the first.

So if netcfgd ever generates both ends from one schema, it loses the
independent second reading that has already paid out three times. That is not
an argument against situ; it is the cost that would have to be paid knowingly,
and probably paid back by keeping one hand-written implementation somewhere as
a control.
