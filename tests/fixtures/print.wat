(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)

  (func (export "print") (param $data i32) (param $len i32) (result i32)
    (i32.store (i32.const 64) (local.get $data))
    (i32.store (i32.const 68) (local.get $len))
    (call $fd_write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 72)))
)
