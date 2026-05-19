//! Python AST helpers built on tree-sitter-python.

use tree_sitter::{Node, Parser, Tree};

use crate::model::Span;

/// Parse a Python source string into a tree. Returns `None` if the parser failed to initialize or
/// produced no tree (extremely rare; only seen when the language version mismatches).
#[must_use]
pub fn parse(src: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    parser.parse(src, None)
}

/// Pre-order recursive walk. `f` is invoked once per node.
pub fn walk<F: FnMut(Node<'_>)>(node: Node<'_>, f: &mut F) {
    f(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, f);
    }
}

/// Return the source text spanned by `node`.
#[must_use]
pub fn node_text<'a>(node: Node<'_>, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

/// Convert a tree-sitter node into a `Span` using 1-based line/column conventions.
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

/// If `node` is a `call`, return its callee text (e.g. `os.system`, `eval`).
#[must_use]
pub fn call_callee_text<'a>(node: Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    if node.kind() != "call" {
        return None;
    }
    let callee = node.child_by_field_name("function")?;
    Some(node_text(callee, src))
}

/// If `node` is a `call`, look for a `keyword_argument` named `name`. Returns the argument node.
#[must_use]
pub fn call_keyword_arg<'a>(node: Node<'a>, name: &str, src: &[u8]) -> Option<Node<'a>> {
    if node.kind() != "call" {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() != "keyword_argument" {
            continue;
        }
        let key = child.child_by_field_name("name")?;
        if node_text(key, src) == name {
            return child.child_by_field_name("value");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trivial_python() {
        let t = parse("x = 1\n").expect("parses");
        assert!(t.root_node().kind() == "module");
    }

    #[test]
    fn finds_subprocess_shell_true() {
        let src = "import subprocess\nsubprocess.run(['ls'], shell=True)\n";
        let tree = parse(src).expect("parses");
        let bytes = src.as_bytes();
        let mut hits = 0;
        walk(tree.root_node(), &mut |n| {
            if let Some(callee) = call_callee_text(n, bytes) {
                if callee == "subprocess.run" {
                    let v = call_keyword_arg(n, "shell", bytes);
                    if v.is_some_and(|val| node_text(val, bytes) == "True") {
                        hits += 1;
                    }
                }
            }
        });
        assert_eq!(hits, 1);
    }
}
