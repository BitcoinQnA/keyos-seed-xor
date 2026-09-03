# Seed XOR

A KeyOS SDK app for Passport Prime. It splits one BIP39 seed into parts that are
each a valid seed in their own right, and puts a set of parts back together.

The scheme is Seed XOR, an open standard that invites other implementations.
This is one.

## What it does

**Split.** Load a seed, choose two, three or four parts, and get that many seeds
back. Any of them can be written down as words or transcribed as a SeedQR,
because each one is an ordinary BIP39 seed.

**Combine.** Say how many parts you have, load them in any order, and get the
original back.

**Make a new wallet.** Combining is not only for reassembly. XOR seeds you
already hold and you get a new seed derived from all of them, with nothing about
the originals changed. Same screens, different intent.

## The one thing to understand

**It is N of N.** Every part is required, there is no threshold, and there is no
spare.

The dangerous part is what happens when a part goes missing. Combining a subset
does not fail. It produces a different valid seed, opening a real wallet that is
simply empty, and nothing on screen distinguishes that from success. So the app
says this three times before it will generate anything, and there is a test
asserting that every proper subset of a split lands somewhere other than the
original.

Entering the same part twice is refused, with the reason. A value XOR-ed with
itself is zero, so a duplicate cancels both copies out; two identical parts
produce all-zero entropy, which is the `abandon abandon … art` wallet. Handing
back a live, long-swept address with no error at all is worse than a refusal.

## The algorithm

XOR the entropy byte arrays. That is the whole thing.

```
combine(parts) = Mnemonic::from_entropy(parts[0].to_entropy() ^ parts[1].to_entropy() ^ …)
```

The specification describes XOR-ing 11-bit word indices while excluding the
checksum bits. That is the same operation said differently: `to_entropy()`
returns exactly the non-checksum bits, and `from_entropy()` recomputes the
checksum, which is what the spec asks for. Doing it in bytes means there is no
bit shuffling to get wrong.

Splitting generates N-1 parts and sets the last one to
`original ^ part[0] ^ … ^ part[N-2]`.

## Two things the app tells you about

**The checksum word** is offered on the parts screen, not shown by default. The
spec suggests recording the original's last word alongside the parts so you can
confirm you have the right set. It also gives away three bits of the real seed,
and tells anyone holding a correct set that they hold one. The trade is stated
where the choice is made.

**Random, not deterministic.** The spec has two generation modes. Only random is
implemented: draw entropy from the TRNG, then double SHA-256 it. Deterministic
mode would let an attacker holding all N parts confirm they were split by a
compatible tool, which random mode does not, so random is the better
default anyway. See "Not implemented" below for the other reason.

## 12 and 24 words only

The spec covers 12, 18 and 24. `seed-core` handles all three and is tested on all
three. The app is 12 and 24.

The blocker is the SDK, not the maths: `security::Seed::from_bytes` matches only
16 or 32 bytes and panics on anything else, so a 24-byte entropy would take the
app down. 18-word values therefore stay inside `seed-core`, where no
`security::Seed` is ever constructed, and `transcribe-view` checks the word count
one last time before building one.

## Permissions

The signed `manifest.json` grants:

- **read-only `os/fs`**: no `WriteFile`, `CreateDirMessage`, `Flush` or `Remove`
- **`os/gui-server`**: the `gui-app` template, including `ShowModal` for the
  system QR scanner
- **theme-only `os/settings`**
- **`os/security` restricted to `GetRandom`**: random bytes for the generated
  parts, nothing else

`GetRandom` sits in the `device-secrets.general-status` group and is
auto-allowed, so a third-party-signed app can hold it. It cannot read seeds:
that is `GetSeed`, which is Foundation-only and deliberately absent. Verified
against the built `manifest.json` rather than assumed.

The alternative was `getrandom`, whose KeyOS patch talks to `trng-server` by raw
connect and so needs no permission at all. It was rejected because there is no
`trng-server` in the hosted simulator, which would have made the whole split flow
untestable anywhere but hardware.

The app never touches the camera. Scanning goes through the system QR Scanner as
a fullscreen modal (`open_qr_scanner`), which needs only `ShowModal`, and that is
enforced at compile time: a successful build proves the permission is present.

## Nothing is stored

Seeds and parts live in memory for one session. There is no filesystem write
permission, so the app cannot persist them even by mistake. `bip39` is built with
its `zeroize` feature, so every `Mnemonic` scrubs itself on drop; `security::Seed`
does the same; and `AppState::clear` scrubs the typed words explicitly.

An SDK app cannot read the device master key or seeds held by other apps, so this
cannot split the seed in Seed Vault. The seed has to come in from outside, by
scan or by typing.

## Build

For Beta 3 installation, validate the packed archive before copying it:

```bash
foundation pack --release --out target/keyos/seed-xor-sdk.app
python3 scripts/pack-beta3.py target/keyos/seed-xor-sdk.app target/keyos/seed-xor-install.app
```

The older SDK CLI can omit `minKeyosVersion` despite `min-keyos-version` being
configured. Beta 3 rejects that archive as invalid. The check restores the
configured minimum when needed and re-signs only the manifest with the existing
publisher identity. It verifies both signatures, the app identity/version and
all file hashes; the application binary is unchanged. Use a fresh output path.

Everything runs inside the SDK Nix shell:

```bash
cd ~/Documents/AI/keyos-seed-xor && nix develop ~/.foundation/sdk/foundation-sdk-1.0.0-aarch64-apple-darwin --command foundation pack --release
```

Signed with the `qna-dev` identity, a self-signed development key, not a
production Foundation signing certificate. Publisher fingerprint:

```text
1fc590a13d547db696e0d3cd12d07a4d7b119e957b301aedd1299b10a1852971
```

Outputs land in `target/keyos/`:

- `keyos-seed-xor.app`, one archive, install from **Settings > Apps > Install App**
- `keyos-seed-xor/`, the loose bundle, for `foundation sideload`

Built and verified against **SDK 1.0.0**. The repo pins no SDK version:
`Cargo.toml` points into `.foundation-sdk/current`, which is a gitignored symlink
to `~/.foundation/sdk/current`. On a machine where that points somewhere else,
the build silently uses that bundle instead, and later SDKs renumber message ids,
so a mismatch shows up as behaviour that makes no sense rather than a clean
error. Run `foundation doctor` first and check the SDK root it prints.

## Layout

| Path | What |
|---|---|
| `crates/seed-core/src/xor.rs` | Seed XOR. All the correctness risk, and all the tests. |
| `crates/seed-core/src/seedqr.rs` | SeedQR grid geometry and block maths. |
| `ui/globals.slint` | `SeedState` (values Rust pushes) and `Actions` (callbacks Rust implements) |
| `ui/pages/` | One directory per route, each with `props.slint` and `page.slint` |
| `ui/gen/` | Router, generated by the build script. Not edited by hand. |
| `src/seedqr.rs` | SDK payload encoding and image rendering |
| `src/app.rs` | App state and callback wiring |

`seed-core` has no KeyOS or Slint dependency, so it builds and tests on the host.
That is the whole reason the XOR lives there: it is the only code in the project
a test can reach.

Navigation stays in Slint. Callbacks that can fail return a bool so the page only
moves on success. Split and combine share their pages; Rust picks the onward
route through a single `after-load` value, so no page has to work out which flow
it is in.

## Routes

```
/                welcome
/count           two, three or four parts
/warn            all-parts and wrong-wallet warnings, split only
/warn-confirm    backup precautions and split confirmation
/load            scan a SeedQR or type words: the source, or one part
  /entry           word entry with BIP39 autocomplete
  /review          check the words before committing
/parts           the generated parts, and the checksum word offer
/words           one seed on screen: a part, or the combined result
/format          Standard or Compact SeedQR
/overview        the whole code, for orientation
/transcribe      the code walked in 7x7 blocks
/verify          scan the copy back
/result          match, mismatch, or not checked
```

## Tests

```bash
cargo test -p seed-core
```

After an SDK build/check has generated the router and theme files, render both
split warning screens with the bundled viewer:

```bash
bash tests/check-warning-ui.sh
```

The previews in `target/warning-previews/` cover two, three and four parts,
the split/combine count picker, light/dark colours, both 480x800 and 480x760
windows, and split errors. They use the real pages and SDK fonts without
loading a seed or calling the RNG.

23 tests. The ones that matter:

- **Both published acceptance vectors**, 24 words and 12 words, three parts
  each, reproduced exactly. A subtly wrong XOR still produces a valid-looking
  mnemonic and nothing looks broken, so these were written before any other code.
- **Order independence** across all six permutations of a three-part set.
- **Round trip** for every word count (12, 18, 24) crossed with every part count
  (2, 3, 4).
- **Every part re-parses** as a real mnemonic of the right length, so the
  checksums are right and not just the byte counts.
- **Every proper subset gives a different seed.** This is the off-by-one that
  would otherwise drop a part in silence.
- **Mixed word counts, out-of-range part counts and wrong-length entropy** are
  refused rather than truncated.
- **Duplicate parts are refused**, plus a test pinning down what that refusal
  prevents: all-zero entropy really is `abandon abandon … art`.
- Nine more over the SeedQR grid geometry, using SeedSigner's own vectors.

## Not verified

- **Nothing on hardware.** Split, combine, scan, verify, word entry and block
  navigation have never run against a real camera or touchscreen.
- **`get_random` has never returned a byte.** The permission resolves correctly
  in the signed manifest and the call compiles, which proves the grant exists,
  not that the call succeeds.
- **No screen has been looked at.** The simulator has no scriptable screenshot
  and its window is not reachable by the tooling here, so nothing confirms the
  pages render as intended.
- **No UI or integration tests.** The app crate builds only for
  `armv7a-unknown-xous-elf`, so nothing in `src/` is covered by a test. The
  callbacks in `src/app.rs` have never been executed.
- **Strings are hardcoded English.** No `i18n/` and `include_translations:
  false`, matching the SDK template.

## Not implemented

**Deterministic split.** The spec's second generation mode hashes a fixed string
with the master secret and the part index. The document does not pin down the
exact byte serialisation, and getting it wrong produces parts other
implementations will not reproduce, silently, because they are still valid
seeds. It is gated on reading a reference implementation's source and adding a
vector generated by real hardware, not on inference from the prose.

## Licence

GPL-3.0-or-later, matching Foundation's own Passport Prime apps.

This is not a free choice. The app links `security`, `server` and
`slint-keyos-platform` from the Foundation SDK, all of which are
GPL-3.0-or-later, so the built binary carries those terms. The SDK's templates
and documentation are MIT, and the scaffolded files started that way; they were
relicensed here to match what the linked runtime requires.
