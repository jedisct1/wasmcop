(module
  (memory (export "memory") 1)

  (func (export "f32x4_div") (param $p i32) (result v128) (f32x4.div (v128.const f32x4 3 3 3 3) (v128.load (local.get $p))))
  (func (export "f64x2_div") (param $p i32) (result v128) (f64x2.div (v128.const f64x2 3 3) (v128.load (local.get $p))))
  (func (export "f32x4_sqrt") (param $p i32) (result v128) (f32x4.sqrt (v128.load (local.get $p))))
  (func (export "f64x2_sqrt") (param $p i32) (result v128) (f64x2.sqrt (v128.load (local.get $p))))

  ;; Scalar operations on the low lane of a vector.
  ;; Only that lane matters.
  (func (export "f64_div_lane") (param $p i32) (result f64) (f64.div (f64.const 3) (f64x2.extract_lane 0 (v128.load (local.get $p)))))
  (func (export "f32_div_lane") (param $p i32) (result f32) (f32.div (f32.const 3) (f32x4.extract_lane 0 (v128.load (local.get $p)))))
  (func (export "f64_sqrt_lane") (param $p i32) (result f64) (f64.sqrt (f64x2.extract_lane 0 (v128.load (local.get $p)))))
  (func (export "f32_sqrt_lane") (param $p i32) (result f32) (f32.sqrt (f32x4.extract_lane 0 (v128.load (local.get $p)))))

  ;; Shifts a public vector by a secret count, then branches on the result and uses it as an address.
  (func (export "shift_by_secret") (param $p i32) (result i32)
    (local $lane i32)
    (local.set $lane
      (i32x4.extract_lane 0
        (i32x4.shl (v128.const i32x4 1 1 1 1) (i32.load8_u (local.get $p)))))
    (if (local.get $lane) (then (i32.store (i32.const 1024) (i32.const 1))))
    (i32.load8_u (i32.and (local.get $lane) (i32.const 255))))
)
