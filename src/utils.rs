#[macro_export]
macro_rules! ensure_err {
    ($cond:expr, $err:expr) => {
        if !$cond {
            return Err($err);
        }
    };
}
