use assert_cmd::Command;
use predicates::str::contains;

fn bin() -> Command {
    Command::cargo_bin("skillscan").expect("binary built")
}

#[test]
fn prints_version() {
    bin()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn prints_help() {
    bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Security scanner for Claude Skills"));
}

#[test]
fn scan_subcommand_exists() {
    bin()
        .arg("scan")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("--fail-on"));
}

#[test]
fn missing_path_is_error() {
    bin().arg("scan").assert().failure();
}
