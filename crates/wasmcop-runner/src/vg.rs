//! Valgrind client requests, written by hand so the build doesn't need Valgrind's headers.

use std::arch::asm;

const RUNNING_ON_VALGRIND: u64 = 0x1001;

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
