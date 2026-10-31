(module
  (memory (export "memory") 1)

  (func (export "f32_div") (param $p i32) (result f32) (f32.div (f32.const 3) (f32.load (local.get $p))))
  (func (export "f64_div") (param $p i32) (result f64) (f64.div (f64.const 3) (f64.load (local.get $p))))
  (func (export "f32_sqrt") (param $p i32) (result f32) (f32.sqrt (f32.load (local.get $p))))
  (func (export "f64_sqrt") (param $p i32) (result f64) (f64.sqrt (f64.load (local.get $p))))

  ;; The divisor is secret and so is where it's loaded from.
  (func (export "div_secret_address") (param $p i32) (result f64)
    (f64.div (f64.const 3)
      (f64.load (i32.add (local.get $p) (i32.and (i32.load8_u (local.get $p)) (i32.const 8))))))
)
