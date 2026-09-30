;; mem_* functions take a pointer to secret bytes, arg_* functions take a secret scalar.
(module
  (memory (export "memory") 2)
  (data (i32.const 4096) "\01\02\03\04\05\06\07\08")

  (type $ii (func (result i32)))
  (func $one (type $ii) (i32.const 1))
  (func $two (type $ii) (i32.const 2))
  (table 2 funcref)
  (elem (i32.const 0) $one $two)

  (func (export "mem_ct") (param $p i32) (result i32)
    (i32.xor (i32.load (local.get $p)) (i32.load (i32.add (local.get $p) (i32.const 4)))))

  (func (export "mem_branch") (param $p i32) (result i32)
    (if (result i32) (i32.load8_u (local.get $p))
      (then (i32.const 7)) (else (i32.const 9))))

  ;; The side effects stop compilers from turning this into arithmetic.
  (func (export "mem_branch_effect") (param $p i32) (result i32)
    (if (i32.load8_u (local.get $p))
      (then (i32.store (i32.const 8192) (i32.const 1)))
      (else (i32.store (i32.const 8196) (i32.const 2))))
    (i32.const 0))

  (func (export "arg_branch") (param $s i32) (result i32)
    (if (result i32) (local.get $s)
      (then (i32.const 7)) (else (i32.const 9))))

  (func (export "arg_ct") (param $s i32) (result i32)
    (i32.add (i32.mul (local.get $s) (i32.const 3)) (i32.const 1)))

  (func (export "mem_select") (param $p i32) (result i32)
    (select (i32.const 11) (i32.const 22) (i32.load8_u (local.get $p))))

  (func (export "mem_fselect") (param $p i32) (result i32)
    (i32.trunc_f64_u (select (f64.const 1) (f64.const 2) (i32.load8_u (local.get $p)))))

  (func (export "mem_index") (param $p i32) (result i32)
    (i32.load8_u (i32.add (i32.const 4096)
      (i32.and (i32.load8_u (local.get $p)) (i32.const 7)))))

  (func (export "mem_brtable") (param $p i32) (result i32)
    (block (block (block
      (br_table 0 1 2 (i32.and (i32.load8_u (local.get $p)) (i32.const 3))))
      (return (i32.const 1)))
      (return (i32.const 2)))
    (i32.const 3))

  (func (export "mem_callind") (param $p i32) (result i32)
    (call_indirect (type $ii) (i32.and (i32.load8_u (local.get $p)) (i32.const 1))))

  (func (export "mem_copy_len") (param $p i32) (result i32)
    (memory.copy (i32.const 16384) (i32.const 4096) (i32.load8_u (local.get $p)))
    (i32.const 0))

  (func (export "mem_copy_data") (param $p i32) (result i32)
    (memory.copy (i32.const 16384) (local.get $p) (i32.const 32))
    (i32.const 0))

  (func (export "mem_clz") (param $p i32) (result i32) (i32.clz (i32.load (local.get $p))))
  (func (export "mem_ctz") (param $p i32) (result i32) (i32.ctz (i32.load (local.get $p))))
  (func (export "mem_popcnt") (param $p i32) (result i32) (i32.popcnt (i32.load (local.get $p))))
  (func (export "mem_shift") (param $p i32) (result i32)
    (i32.shl (i32.const 1) (i32.load (local.get $p))))
  (func (export "mem_rotl") (param $p i32) (result i32)
    (i32.rotl (i32.const 3) (i32.load (local.get $p))))
  (func (export "mem_cmp_value") (param $p i32) (result i32)
    (i32.eq (i32.load (local.get $p)) (i32.const 5)))
  (func (export "mem_mul64") (param $p i32) (result i64)
    (i64.mul (i64.load (local.get $p)) (i64.const 0x1234567)))
  (func (export "arg_ignored") (param $s i32) (result i32) (i32.const 42))

  (func (export "mem_div_const") (param $p i32) (result i32)
    (i32.div_u (i32.load (local.get $p)) (i32.const 3329)))
  (func (export "mem_div_var") (param $p i32) (result i32)
    (i32.div_u (i32.load (local.get $p)) (i32.load (i32.const 4096))))

  (func (export "trap_unreachable") (param $p i32) (result i32) (unreachable))
  (func (export "trap_oob") (param $p i32) (result i32) (i32.load (i32.const 0xfffffff0)))
  (func (export "trap_div0") (param $p i32) (result i32) (i32.div_u (i32.const 1) (i32.const 0)))
)
