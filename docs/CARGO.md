# Hardening a Rust crate — `cargo rustcloak`

`tools/cargo-rustcloak` makes hardening a crate a single command instead of a manual per-file
`opt` run. It installs itself as cargo's `RUSTC_WRAPPER` and injects the plugin into the **primary
package's** crates only; dependencies, build scripts and proc-macros build untouched. rustc performs
the final link, so the output binary/library runs normally.

## Quick start

```sh
# build the plugin once (LLVM 18 dev headers required)
cmake -S . -B build -G Ninja -DLLVM_DIR="$(llvm-config-18 --cmakedir)" && cmake --build build

# put the wrapper on PATH as a cargo subcommand (optional)
ln -s "$PWD/tools/cargo-rustcloak" ~/.local/bin/cargo-rustcloak

# harden your crate
cd /path/to/your/crate
RUSTCLOAK_VM=1 cargo rustcloak build --release
# or without the symlink:
RUSTCLOAK_HARDEN=1 /path/to/rustcloak/tools/cargo-rustcloak build --release
```

Any build-time flag the plugin reads is a plain environment variable, so it flows through to the
wrapped rustc: `RUSTCLOAK_VM=1`, `RUSTCLOAK_HARDEN=1`, `RUSTCLOAK_SUBST_DEPTH=3`, `RUSTCLOAK_SEED=…`,
etc. (see the README flag table).

## Knobs

| env | effect |
|---|---|
| `RUSTCLOAK_PLUGIN` | path to `libRustCloak.so` (default `<repo>/build/libRustCloak.so`) |
| `RUSTCLOAK_CRATES` | comma list of crate names to harden (default: the whole primary package) |
| `RUSTCLOAK_TOOLCHAIN` | rustc toolchain, e.g. `nightly-2024-06-15` → runs `cargo +<tc>` |

## The one requirement, and why the wrapper checks it first

`-Zllvm-plugins` is a **nightly** flag, and the plugin loads only into a rustc whose bundled LLVM
(a) is the plugin's LLVM major and (b) **exports** the symbols the plugin references. Many rustup
toolchains statically link LLVM and hide those symbols, so the load fails there (a property of how
that rustc was built, not of the architecture — see the README "Rust integration notes").

The wrapper **probes this before building** and, if the plugin cannot load, stops with the reason
rather than silently producing an unhardened binary.

## If your rustc can't load the plugin: the IR-level path (any rustc)

This always works — it is what `test/rust_e2e.sh` does — but it hardens at the IR/object level; you
relink yourself.

```sh
rustc --emit=llvm-ir -O -o crate.ll src/main.rs
opt -load-pass-plugin=build/libRustCloak.so \
    -passes='strenc,function(virt,constenc,subst,bogus,flatten)' crate.ll -S -o crate_hard.ll
clang -c crate_hard.ll -o crate_hard.o        # then link crate_hard.o as usual
```

For a whole cargo crate graph via this path you need per-codegen-unit IR and a relink step; that is
why the `-Zllvm-plugins` wrapper above is the recommended route when your rustc supports it.
