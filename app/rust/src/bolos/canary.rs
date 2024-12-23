use crate::bolos;

extern "C" {
    fn check_app_canary();
}

#[cfg(all(
    not(test),
    not(feature = "clippy"),
    not(feature = "fuzzing"),
    not(feature = "cpp_tests")
))]
pub fn c_check_app_canary() {
    unsafe { check_app_canary() }
}

#[cfg(any(test, feature = "clippy", feature = "fuzzing", feature = "cpp_tests"))]
pub fn c_check_app_canary() {}
