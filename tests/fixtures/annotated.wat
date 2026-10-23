;; A module that marks its own secrets through the optional wasmcop imports.
(module
  (import "wasmcop" "poison" (func $poison (param i32 i32)))
  (import "wasmcop" "declassify" (func $declassify (param i32 i32)))
  (import "wasmcop" "assert_public" (func $assert_public (param i32 i32)))
  (import "wasmcop" "declassify_i32" (func $declassify_i32 (param i32) (result i32)))
  (import "wasmcop" "declassify_i64" (func $declassify_i64 (param i64) (result i64)))
  (memory (export "memory") 1)

  (func $branch_on (param $v i32)
    (if (local.get $v) (then (i32.store (i32.const 16) (i32.const 1)))))

  ;; Only the first four bytes are declared public, so only the second branch is a leak.
  (func (export "declassify_part") (param $p i32) (result i32)
    (call $declassify (local.get $p) (i32.const 4))
    (call $branch_on (i32.load8_u (local.get $p)))
    (call $branch_on (i32.load8_u (i32.add (local.get $p) (i32.const 5))))
    (i32.const 0))

  (func (export "self_poison") (param $p i32) (result i32)
    (call $poison (local.get $p) (i32.const 4))
    (call $branch_on (i32.load8_u (local.get $p)))
    (i32.const 0))

  (func (export "check_public") (param $p i32) (result i32)
    (call $assert_public (local.get $p) (i32.const 4))
    (i32.const 0))

  (func (export "scalars") (param $p i32) (result i32)
    (call $branch_on (call $declassify_i32 (i32.load (local.get $p))))
    (call $branch_on (i32.wrap_i64 (call $declassify_i64 (i64.load (local.get $p)))))
    (i32.const 0))

  ;; Trapping here, instead of writing somewhere random, is what the runner promises.
  (func (export "bad_range") (result i32)
    (call $poison (i32.const -4) (i32.const 8))
    (i32.const 0))
)
