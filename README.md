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
