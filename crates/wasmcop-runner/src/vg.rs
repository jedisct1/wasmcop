//! Valgrind client requests, written by hand so the build doesn't need Valgrind's headers.

use std::arch::asm;
use std::hint::black_box;

const RUNNING_ON_VALGRIND: u64 = 0x1001;
const COUNT_ERRORS: u64 = 0x1201;
const MAKE_MEM_UNDEFINED: u64 = 0x4d43_0001;
const MAKE_MEM_DEFINED: u64 = 0x4d43_0002;

/// The magic sequence from `valgrind.h`.
/// It does nothing outside Valgrind.
#[inline(always)]
fn request(code: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let args: [u64; 6] = [code, a1, a2, a3, 0, 0];
    let mut result: u64 = 0;
    unsafe {
        asm!(
            "rol rdi, 3", "rol rdi, 13", "rol rdi, 61", "rol rdi, 51",
            "xchg rbx, rbx",
            inout("rdx") result,
            in("rax") args.as_ptr(),
            options(nostack),
        );
    }
    result
}

pub fn running_on_valgrind() -> bool {
    request(RUNNING_ON_VALGRIND, 0, 0, 0) != 0
}

pub fn count_errors() -> u64 {
    request(COUNT_ERRORS, 0, 0, 0)
}

pub fn make_undefined(ptr: *const u8, len: usize) {
    request(MAKE_MEM_UNDEFINED, ptr as u64, len as u64, 0);
}

pub fn make_defined(ptr: *const u8, len: usize) {
    request(MAKE_MEM_DEFINED, ptr as u64, len as u64, 0);
}

pub fn undefined_value<T: Copy>(value: T) -> T {
    make_undefined(&value as *const T as *const u8, size_of::<T>());
    black_box(value)
}

pub fn defined_value<T: Copy>(value: T) -> T {
    make_defined(&value as *const T as *const u8, size_of::<T>());
    black_box(value)
}
