# Examples

Small programs for Wasmcop to check, so you can see what it catches.

Each directory has a small C file, the module compiled from it, and a spec file that tests it.

The modules are checked in, so you only need Wasmcop to run them.

```sh
wasmcop check examples/01-compare/compare.toml
```

Paths in a spec file are relative to that file, so you can run it from anywhere.

Read each spec file next to its C code. They're short.

| Directory              | What it shows                                              | Exit code |
| ---------------------- | ---------------------------------------------------------- | --------- |
| `01-compare`           | A branch on a secret, and the constant-time fix            | 1         |
| `02-table-lookup`      | A memory access indexed by a secret, and `--blame`         | 1         |
| `03-select`            | Code that only leaks on one backend, and a compiler trap   | 1         |
| `04-partial-secret`    | A buffer that's only partly secret                         | 1         |
| `05-siphash`           | Multi-step tests, known answers and `declassify`           | 0         |
| `06-division`          | Division on a secret, with the patched Valgrind            | 1         |
| `07-poison`            | A value that becomes secret halfway through a test         | 1         |
| `08-annotations`       | A module that marks its own secrets                        | 1         |
| `09-wasi`              | Randomness, arguments, environment and printing a secret   | 1 and 0   |
| `10-imports-and-alloc` | Imports Wasmcop doesn't know, and a custom allocator       | 0         |
| `11-broken-tests`      | What a test that can't be trusted looks like               | 2         |

Why do so many of these exit with 1? Because most examples put a leaky function next to a fixed one on purpose.

The exit codes:

- 0: nothing found
- 1: findings
- 2: the test itself can't be trusted

Add `--full` to any of these commands to try every optimization level and CPU profile.

## 01-compare: start here

`compare_leaky` returns as soon as two bytes differ. So it branches on the secret.

`compare_ct` reads every byte, and only the combined difference decides the result.

```text
stops early
                      singlepass  cranelift   llvm
  branch                       1          1      1

  BRANCH in compare_leaky at wasm 0x6f (./compare.c:10) [cranelift]
    cranelift: jne 0x58
  BRANCH in compare_leaky +0x21 [llvm]
    llvm: jne short 0x2d
  BRANCH in compare_leaky +0xc3 [singlepass]
    singlepass: je 0xce

constant time
  no findings
```

The table counts findings per backend.

Below it, each finding gives you the function, the place, and the instruction that used the secret.

## 02-table-lookup: secrets as array indexes

`sbox_leaky` uses a secret as an array index. That shows up as a `memory-address` finding on every backend.

Singlepass also reports a branch there, even though the wasm has none. It's part of the code Singlepass generates for the memory access.

`sbox_ct` reads the whole table every time and keeps the entry it wants with a mask.

Then there's `encrypt`, which has two secrets. Only the key goes through the table, and `--blame` tells them apart:

```console
$ wasmcop check examples/02-table-lookup/table.toml --blame --backend cranelift
  ...
  MEMORY-ADDRESS in encrypt at wasm 0xe8 (./table.c:38) [cranelift]
    cranelift: movzx rdi, byte ptr [rax+rdi]
      reached from: key
```

## 03-select: the compiler trap

The same choice between two values, written two ways.

`choose_masked` looks fine. It's plain arithmetic in C, but clang spots the pattern and emits a wasm `select` anyway.

You can see it with `wasm-tools print examples/03-select/select.wasm`.

So what happens to a `select`? Cranelift and LLVM compile it to a conditional move, and Singlepass compiles it to a branch. That's why this one only gets reported on Singlepass.

Reading the C code wouldn't have told you any of that. That's why it's worth checking the compiled module.

`choose_opaque` is the same code with an empty `asm` statement that hides the mask from the optimizer. It comes out clean.

```console
$ wasmcop check examples/03-select/select.toml --backend cranelift
```

With only Cranelift, both tests pass.

## 04-partial-secret: only some of the bytes

`bytes(64, secret=16..48)` is a buffer where only bytes 16 to 47 are secret.

`digest` branches on the public salt, and that's fine.

`digest_as_string` stops at the first zero byte of the key, and that gets reported.

## 05-siphash: the one to copy

SipHash-2-4 in full. Copy this one when you write tests for your own code.

The spec file:

- checks an answer from the SipHash paper, both in one shot and through the streaming interface
- tries message lengths around the 8-byte block size
- sets its own `iterations` and `seed`
- passes results from one call to the next

Nothing leaks, so it exits with 0.

Two values are declared public. A tag gets sent anyway, and whether it was accepted is no secret either.

Delete `declassify(tag)` from the "using a tag" test and the table lookups in `hex_encode` get reported.

## 06-division: yes, division can leak

`compress_div` has the same shape as the KyberSlash bug in ML-KEM implementations.

Only Singlepass keeps that division. Cranelift and LLVM turn a division by a constant into a multiplication.

`compress_mul` is the fix that went into the reference code.

A secret divisor can't be optimized away, though, so `reduce` gets reported on all three backends.

Just keep in mind that you need the patched Valgrind from `scripts/build-valgrind.sh` for this one.

A stock Valgrind reports nothing here and lists the divisions it couldn't check at the end of the report.

## 07-poison: secret from here on

`poison(key)` makes a buffer secret from that step on.

`derive_key` runs on public data first, so it isn't what's being checked.

The last test does the same by address, with `poison(4096, 16)` and `declassify(4096, 4)`.

You'd use that for memory that nothing in the test has a name for.

## 08-annotations: marking secrets from inside

A module can import functions from a module called `wasmcop`, instead of leaving everything to the test.

`sample` is a rejection loop, and it gets reported. Wasmcop can't know that leaking how many candidates were rejected is harmless.

And it's only harmless when the candidates are independent and uniformly random. That's for you to judge.

`sample_declassified` says so with `declassify_i32`, right where the decision is made.

`device_key_fingerprint` uses a key stored in the module, so only the module can mark it with `poison`.

`send_packet` calls `assert_public` on what's about to leave. Give it a secret and you get a `check` finding.

## 09-wasi: talking to the outside world

This module calls WASI directly, without any libc.

What `random_get` returns is secret, so you can test a key generator without saying anything about the key.

`keygen_retry` draws again when the first byte is zero, and that gets reported. `keygen` doesn't.

Printing a secret gets reported too.

The `[wasi]` table sets the arguments and the environment.

`public-random.toml` runs the same retry loop with `random = "public"`. That's the right setting for something like a nonce, and it comes out clean.

## 10-imports-and-alloc: when a module needs things

You need an `[imports]` table as soon as a module imports something Wasmcop doesn't know. For each import:

- a number makes that function return the number
- `"trap"` fails the test if the function is ever called

`alloc = "export:my_alloc"` makes buffers come from the module's own allocator.

`seal` refuses any other memory. So without that line, the run exits with 2 and says `env.abort was called`.

## 11-broken-tests: when the test is the problem

Every test in this file is wrong on purpose, because sooner or later you'll write one of these.

"the secret is never used" passes a 16-byte key to a function that only reads 32-byte ones.

You get no findings and a warning, and the exit code would stay 0 if it were the only test.

So when a report comes back clean, check it for warnings too.

"wrong known answer" fails an `expect`, and "out of bounds" traps. So the file exits with 2.

Failures are listed twice per backend. That's because every test also runs once without any secrets, as a sanity check.

## Rebuilding the modules

`make -C examples` rebuilds whatever changed.

All it needs is Zig, because `zig cc` brings its own clang and linker.

The modules here were built with Zig 0.18, which uses clang 23.

Just keep in mind that another version can generate different code, and `03-select` in particular depends on what the compiler decides to do.
