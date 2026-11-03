;; Kyber's poly_tomsg with the division by q that KyberSlash exploited.
(module
  (memory (export "memory") 1)

  (func (export "poly_tomsg") (param $msg i32) (param $poly i32)
    (local $i i32) (local $t i32) (local $byte i32)
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $i) (i32.const 256)))
        (local.set $t (i32.load16_u (i32.add (local.get $poly) (i32.shl (local.get $i) (i32.const 1)))))
        (local.set $t (i32.and
          (i32.div_u (i32.add (i32.shl (local.get $t) (i32.const 1)) (i32.const 1665)) (i32.const 3329))
          (i32.const 1)))
        (local.set $byte (i32.add (local.get $msg) (i32.shr_u (local.get $i) (i32.const 3))))
        (i32.store8 (local.get $byte)
          (i32.or (i32.load8_u (local.get $byte)) (i32.shl (local.get $t) (i32.and (local.get $i) (i32.const 7)))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next))))
)
