# KTx guard-elision certificate and checker contract

The current `.elide` v1 sidecar is an optimization hint from a trusted
analyzer. The loader checks its magic, version, exact size, program/map counts,
flag vocabulary, completeness discipline, and Boolean map facts; malformed or
incomplete inputs fail closed to guarded execution. `tx-audit` executes every
claimed guard and counts a false fact. These checks prevent parser confusion but
do not make an untrusted producer sound.

The kernel-facing design therefore uses a v2 proof certificate. Its fixed
header contains: magic/version, SHA-256 of the complete bytecode and map
descriptor image, instruction and map counts, checker-semantics version, and
offset/length pairs for the following tables. All integers are little-endian;
every region must be non-overlapping and contained in the file.

For each control-flow block the certificate carries one abstract input state:
the 11 register type tags and signed interval endpoints, 64 stack-granule type
tags/initialization bits, and the block's successor list. For each proposed
elision it carries the instruction slot, access width, required permission, and
the region plus interval fact that proves the access contained. A fuel claim
carries a natural-number ranking variable and a strictly decreasing bound for
every back edge. A read-only-map claim carries the map index and a complete
list of reachable helper/store sites; absence is never inferred from a Bloom
filter or summary hash.

The load-time checker is deliberately simpler than the producer. It decodes the
bytecode independently, reconstructs the CFG and map relocations, verifies the
image hash, applies the documented transfer function to each block state once,
and requires every successor state to subsume the computed output. It then
checks each elision locally against the certified input state, every loop edge
against its ranking proof, and every read-only map against all reachable
effects. Unknown opcodes, helpers, types, table tags, arithmetic overflow,
missing predecessor facts, or resource-limit excess reject the certificate and
select fully guarded/fueled execution. Complexity is linear in bytecode plus
CFG edges times the fixed abstract-state size; the checker allocates from a
load-time bounded arena and executes no certificate-supplied code.

The v1 artifact remains useful for measuring the optimization and for runtime
auditing, but v1 must not be presented as an untrusted proof-carrying
interface. A kernel implementation must ship the v2 checker (or treat the
producer as part of the trusted computing base) before enabling elision.
