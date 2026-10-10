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
