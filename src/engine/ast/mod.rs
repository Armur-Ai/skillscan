//! Tree-sitter-backed AST analysis.
//!
//! Currently ships parsing helpers for Python. Bash will join in a follow-up. Each AST rule
//! parses the file it cares about and walks the tree looking for specific call patterns; a parse
//! cache across rules is a Phase 2.4 follow-up once `rayon` parallelism lands.

pub mod bash;
pub mod python;
