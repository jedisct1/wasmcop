# Wasmcop

Wasmcop checks whether the native code generated for a WebAssembly module handles secrets in constant time.

You give it a `.wasm` file, say which function to call and which arguments are secret.

It compiles the module with Singlepass, Cranelift and LLVM, runs the result under Valgrind with the secrets marked as uninitialized memory, and tells you about every branch and memory access that depended on them.

The same module can be fine on one backend and leak on another.

A wasm `select` on a secret is a conditional move on Cranelift and a real branch on Singlepass.

Linux on x86-64 only for now.

## Checking a function

`wasmcop list` shows what a module exports:

```console
$ wasmcop list hmac.wasm
functions:
  hmac(i32, i32, i32, i32, i32) -> i32
memory: can use buffers
```

Then describe the call, with one argument per parameter.

Anything not marked `secret` is public.

```sh
wasmcop check hmac.wasm --call 'hmac(tag: out(32), m: bytes(64), len(m), k: secret bytes(32), len(k))'
```

The exit code is 0 if nothing was found, 1 if something was, and 2 if the analysis couldn't be trusted, for example because the code trapped.

If it says 2, read the message before believing anything else in the report.

### Arguments

| Argument                                                | What it is                                               |
| ------------------------------------------------------- | -------------------------------------------------------- |
| `42`, `0x2a`, `1.5`                                     | A number                                                 |
| `rand`                                                  | A random number                                          |
| `secret rand`, `secret 42`                              | A secret number                                          |
| `bytes(16)`                                             | 16 random bytes in memory. The function gets the address |
| `bytes(16, zero)`, `bytes(16, ones)`, `bytes(16, 0xa5)` | Bytes with a chosen value                                |
| `hex(00ff)`                                             | Exactly these bytes                                      |
| `secret bytes(32)`, `secret hex(...)`                   | Secret bytes. The address isn't secret, the contents are |
| `bytes(64, secret=16..48)`                              | Only part of the buffer is secret                        |
| `out(64)`                                               | An empty buffer for the function to write to             |
| `len(m)`                                                | The length of the buffer named `m`                       |
| `name: <argument>`                                      | Gives an argument a name                                 |

Buffers also accept `align=64` and `at=4096`.

Argument types come from the module, so you never write `i32`.

Each test runs four times by default, with random secrets, all zeros, all ones, and random again.

Use `--iterations` to change that, and add more `--call` options to try different public inputs.

### More options

`--backend cranelift,llvm` picks backends.

`--full` tries every optimization level and CPU profile.

`--blame` works out which secret causes each finding.

`--format json` gives you everything, including what the text report leaves out.

## Multi-step tests

Stateful APIs need more than one call. Put them in a TOML file and run `wasmcop check test.toml`:

```toml
wasm = "hmac.wasm"
iterations = 8

[[test]]
name = "streaming"
steps = """
st = out(256)
key = secret bytes(32)
msg = bytes(1024)
hmac_init(st, key, len(key))
hmac_update(st, msg, len(msg))
tag = out(32)
hmac_final(st, tag)
expect(tag, hex(5bdcc146bf60754e...))
declassify(tag)
ok = hmac_verify(tag, key)
"""
```

Secrets stay secret from one call to the next.

`expect` checks an output against a known answer.

It's worth using, because it proves the test really exercised the function.

`declassify` is for results that really are public, such as a tag before comparing it.

`poison` marks something as secret.

The file can also set `seed`, `alloc = "grow"` or `alloc = "export:my_malloc"`, and a `[wasi]` table with `args` and `env`.

The output of `random_get` is secret unless you set `random = "public"`.

An `[imports]` table says what to do about imports Wasmcop doesn't know:

```toml
[imports]
"env.abort" = "trap"
"env.getpid" = 1
```

WASI preview 1 is built in. Time and randomness are fixed by the test, so runs are reproducible.

## Marking secrets from inside a module

If you can rebuild the code, it can import these from a module called `wasmcop`:

| Function                                 | What it does                                   |
| ---------------------------------------- | ---------------------------------------------- |
| `poison(ptr, len)`                       | Marks memory as secret                         |
| `declassify(ptr, len)`                   | Marks memory as public                         |
| `assert_public(ptr, len)`                | Reports a finding if the memory holds a secret |
| `declassify_i32(x)`, `declassify_i64(x)` | Returns `x`, now public                        |

This is how you'd handle something like the rejection loop in a signature scheme, where leaking that a retry happened is fine.
