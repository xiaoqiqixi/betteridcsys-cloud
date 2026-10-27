# Observed Internet NAT readback fixtures

These two JSON files are complete `nft -j -n list ruleset` outputs from the
isolated `TestNativeNATInternetEgressAndRevocation` GitHub Actions gate:

- Run: <https://github.com/xiaoqiqixi/betteridcsys/actions/runs/40060108300>
- Ubuntu 22.04: nftables 1.0.2, `Lester Gooch`.
- Ubuntu 24.04: nftables 1.0.9, `Old Doc Yak #3`.

Only the GitHub log prefix (`job`, `step`, timestamp, test source location and
`native rules: <nil>`) was stripped. The actual JSON, metainfo, chain/rule
handles, order and expressions are unchanged. The public-syntax addresses were
assigned only inside temporary isolated namespaces; they were not contacted on
the Internet. No credentials or machine-specific namespace identity is included.

The first run correctly failed strict readback before releasing forwarding.
These outputs established the compiler's exact native representation:

- `/32` addresses are JSON strings, not `prefix` objects.
- A protocol-specific ICMP payload includes its L4 dependency; nft omits a
  redundant explicit `meta l4proto 1` match.
- The `new | established` conntrack bitmask is emitted as `[2, 8]`, not `10`.

The compiler now generates that representation. `normalizeNFT` is not relaxed:
it still retains every expression, bitmask, address match, chain and rule order.
`TestNATInternetCompilerMatchesObservedNativeReadback` compares the entire
normalized fixture to compiler output, then independently removes or corrupts
conntrack guards, source-NAT status, a protected-address rule, an ordinary chain,
and the ICMP payload protocol to prove those changes remain detectable.
