(module
  (memory (export "memory") 1)

  (func (export "branch_i32") (param i32) (result i32)
    (if (result i32) (local.get 0) (then (i32.const 1)) (else (i32.const 2))))
  (func (export "branch_i64") (param i64) (result i32)
    (if (result i32) (i64.eqz (local.get 0)) (then (i32.const 1)) (else (i32.const 2))))
  (func (export "branch_f32") (param f32) (result i32)
    (if (result i32) (f32.gt (local.get 0) (f32.const 0)) (then (i32.const 1)) (else (i32.const 2))))
  (func (export "branch_f64") (param f64) (result i32)
    (if (result i32) (f64.gt (local.get 0) (f64.const 0)) (then (i32.const 1)) (else (i32.const 2))))
  (func (export "branch_v128") (param v128) (result i32)
    (if (result i32) (v128.any_true (local.get 0)) (then (i32.const 1)) (else (i32.const 2))))

  (func (export "identity") (param i32) (result i32) (local.get 0))
  (func (export "pair") (param i32) (result i32 i32) (local.get 0) (local.get 0))

  (func (export "branch_at") (param $p i32) (param $offset i32) (result i32)
    (if (result i32) (i32.load8_u (i32.add (local.get $p) (local.get $offset)))
      (then (i32.const 1)) (else (i32.const 2))))

  ;; Writes the sum of the bytes at $src to $dst.
  (func (export "sum_into") (param $dst i32) (param $src i32) (param $len i32)
    (local $i i32) (local $sum i32)
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $sum (i32.add (local.get $sum) (i32.load8_u (i32.add (local.get $src) (local.get $i)))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))
    (i32.store (local.get $dst) (local.get $sum)))
)
