//! Bash AST helpers built on tree-sitter-bash.

use tree_sitter::{Node, Parser, Tree};

use crate::model::Span;

#[must_use]
pub fn parse(src: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .ok()?;
    parser.parse(src, None)
}

pub fn walk<F: FnMut(Node<'_>)>(node: Node<'_>, f: &mut F) {
    f(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, f);
    }
}

#[must_use]
pub fn node_text<'a>(node: Node<'_>, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

#[must_use]
pub fn span_of(node: Node<'_>) -> Span {
    let start = node.start_position();
    let end = node.end_position();
    Span {
        line: start.row + 1,
        col: start.column + 1,
        end_line: end.row + 1,
        end_col: end.column + 1,
        byte_start: node.start_byte(),
        byte_end: node.end_byte(),
    }
}

/// If `node` is a bash `command`, return the text of its `command_name` child (e.g. "eval",
/// "source", ".").
#[must_use]
pub fn command_name<'a>(node: Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    if node.kind() != "command" {
        return None;
    }
    let name = node.child_by_field_name("name")?;
    Some(node_text(name, src))
}

/// Iterate the argument children of a `command` node. Skips the command_name itself.
pub fn command_args<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    if node.kind() != "command" {
        return out;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "command_name" | "variable_assignment" | "file_redirect" => continue,
            _ => out.push(child),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trivial_bash() {
        let t = parse("echo hello\n").expect("parses");
        assert_eq!(t.root_node().kind(), "program");
    }

    #[test]
    fn finds_command_name_eval() {
        let src = "eval \"$x\"\n";
        let tree = parse(src).expect("parses");
        let bytes = src.as_bytes();
        let mut found = false;
        walk(tree.root_node(), &mut |n| {
            if let Some(name) = command_name(n, bytes) {
                if name == "eval" {
                    found = true;
                }
            }
        });
        assert!(found);
    }
}
