#[cfg(all(
    not(test),
    not(feature = "clippy"),
    not(feature = "fuzzing"),
    not(feature = "cpp_tests")
))]
extern "C" {
    fn io_heartbeat();
}

// Lets the device breath between computations
pub(crate) fn heartbeat() {
#[cfg(all(
    not(test),
    not(feature = "clippy"),
    not(feature = "fuzzing"),
    not(feature = "cpp_tests")
))]
    unsafe {
        io_heartbeat()
    }
}
