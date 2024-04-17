/*  file:       ig_error.rs
    author:     garnt
    date:       04/15/2024
    desc:       IGError type and associated functions.
 */

use std::fmt;

// Custom error type
pub struct IGError {
    // string containing the custom error text
    error_msg: String
}

// Function impls for IGError
impl IGError {
    // new() constructs an IGError from a referenced error message.
    pub fn new(msg: &str) -> Self {
        IGError {
            error_msg: msg.to_owned()
        }
    }
}

// std::fmt::Display trait impl for IGError
impl fmt::Display for IGError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_msg)
    }
}

// std::fmt::Debug trait impl for IGError
impl fmt::Debug for IGError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{{} @ file: {}, line: {} }}", self.error_msg, file!(), line!())
    }
}