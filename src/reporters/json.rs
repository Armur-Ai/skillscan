use crate::model::Report;

/// Print a `Report` as pretty-printed JSON on stdout.
///
/// # Errors
/// Returns an error if serialization fails. In practice, this should not happen.
pub fn print(report: &Report) -> anyhow::Result<()> {
    let s = serde_json::to_string_pretty(report)?;
    println!("{s}");
    Ok(())
}
