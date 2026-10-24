;; The start function needs memory, and everything after it depends on what it did.
(module
  (import "wasi_snapshot_preview1" "random_get" (func $random_get (param i32 i32) (result i32)))
  (memory (export "memory") 1)

  (func $init (drop (call $random_get (i32.const 64) (i32.const 8))))
  (start $init)

  (func (export "uses_key") (result i32)
    (if (i32.load8_u (i32.const 64)) (then (i32.store (i32.const 128) (i32.const 1))))
    (i32.const 0))
)
