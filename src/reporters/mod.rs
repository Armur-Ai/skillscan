//! Reporters render a `Report` into a target format.
//!
//! Phase 1: terminal + JSON. Phase 3: SARIF, Markdown, HTML.

pub mod json;
pub mod terminal;
