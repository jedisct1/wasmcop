;; Each function has one secret-dependent site among similar public ones, to check that findings point at the right one.
(module
  (memory (export "memory") 1)

  (func (export "site_branch") (param $p i32) (param $public i32) (result i32)
    (if (local.get $public) (then (i32.store (i32.const 1024) (i32.const 1))))
    (if (i32.load8_u (local.get $p)) (then (i32.store (i32.const 1028) (i32.const 2))))
    (if (local.get $public) (then (i32.store (i32.const 1032) (i32.const 3))))
    (i32.const 0))

  (func (export "site_load") (param $p i32) (result i32)
    (i32.add
      (i32.add
        (i32.load8_u (i32.const 2048))
        (i32.load8_u (i32.add (i32.const 8192) (i32.and (i32.load8_u (local.get $p)) (i32.const 7)))))
      (i32.load8_u (i32.const 2056))))
)
