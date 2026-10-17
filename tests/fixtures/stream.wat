;; A small streaming API, to check that taint survives between calls.
(module
  (memory (export "memory") 1)

  (func (export "init") (param $st i32) (param $key i32) (i64.store (local.get $st) (i64.load (local.get $key))))
  (func (export "update") (param $st i32) (i64.store (local.get $st) (i64.mul (i64.load (local.get $st)) (i64.const 31))))
  (func (export "finish") (param $st i32) (param $out i32) (i64.store (local.get $out) (i64.load (local.get $st))))

  (func (export "branch_on") (param $p i32) (result i32)
    (if (result i32) (i32.load8_u (local.get $p)) (then (i32.const 1)) (else (i32.const 0))))

  ;; Never looks at the key if the length is wrong.
  (func (export "early_exit") (param $key i32) (param $len i32) (result i32)
    (if (i32.ne (local.get $len) (i32.const 32)) (then (return (i32.const -1))))
    (i32.load (local.get $key)))

  (func (export "only_first") (param $a i32) (param $b i32) (result i32)
    (if (result i32) (local.get $a) (then (i32.const 1)) (else (i32.const 0))))
  ;; Keeps a value for later, so that two calls can feed a third.
  (func (export "put") (param $slot i32) (param $value i32)
    (i32.store (i32.add (i32.const 256) (local.get $slot)) (local.get $value)))
  (func (export "branch_on_stored_and") (result i32)
    (if (result i32) (i32.and (i32.load (i32.const 256)) (i32.load (i32.const 260))) (then (i32.const 1)) (else (i32.const 0))))

  (func (export "branch_on_and") (param $a i32) (param $b i32) (result i32)
    (if (result i32) (i32.and (i32.load (local.get $a)) (i32.load (local.get $b))) (then (i32.const 1)) (else (i32.const 0))))

  (func (export "both") (param $a i32) (param $b i32) (result i32)
    (if (result i32) (i32.and (local.get $a) (local.get $b)) (then (i32.const 1)) (else (i32.const 0))))
)
