use std::{cell::LazyCell, fmt::{Debug, Pointer}, io, path::Display};

// pub struct ProxyError {
//     pub err : String,
//     a: LazyCell<>
// }

// impl From<io::Error> for ProxyError {
//     fn from(value: io::Error) -> Self {
//         Self {err: value.to_string()}
//     }
// }

// impl Debug for ProxyError {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f,"ProxyError {}",&self.err)
//     }
// }
