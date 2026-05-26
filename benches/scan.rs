//! Microbenchmarks for the rule engine. Run with `cargo bench`.

use std::fs;
use std::path::Path;

use criterion::{criterion_group, criterion_main, Criterion};

use skillscan::engine::Engine;
use skillscan::loaders::DirectoryLoader;
use skillscan::rules;

fn bench_scan_clean(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("SKILL.md"),
        "---\n\
         name: clean\n\
         description: A clean skill used as a benchmark baseline for the rule engine.\n\
         version: 0.1.0\n\
         license: Apache-2.0\n\
         allowed-tools:\n  - Read\n  - Bash(git status)\n\
         ---\n\
         # Clean\n\
         \n\
         This skill is intentionally boring.\n",
    )
    .expect("write");

    let skill = DirectoryLoader::new(dir.path()).load().expect("load");
    let engine = Engine::new(rules::builtin_rules());

    c.bench_function("scan/clean-1-file", |b| {
        b.iter(|| std::hint::black_box(engine.scan(&skill)));
    });
}

fn bench_scan_realistic(c: &mut Criterion) {
    // Synthetic 50-file skill: 1 SKILL.md + 49 small support files. Mirrors what a real
    // moderate-complexity skill might ship.
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("SKILL.md"),
        "---\n\
         name: synthetic\n\
         description: Synthetic skill for benchmarking the rule engine across files.\n\
         version: 0.1.0\n\
         license: Apache-2.0\n\
         allowed-tools:\n  - Read\n  - Bash(git status)\n\
         ---\n\
         # Synthetic\n",
    )
    .expect("write");

    let scripts_dir = dir.path().join("scripts");
    fs::create_dir_all(&scripts_dir).expect("mkdir");
    for i in 0..25 {
        fs::write(
            scripts_dir.join(format!("util_{i:02}.py")),
            format!("def f_{i}(x):\n    return x * {i}\n\nresult = f_{i}(42)\n"),
        )
        .expect("write py");
    }
    let bash_dir = dir.path().join("hooks");
    fs::create_dir_all(&bash_dir).expect("mkdir");
    for i in 0..15 {
        fs::write(
            bash_dir.join(format!("hook_{i:02}.sh")),
            format!("#!/bin/bash\necho \"hook {i}\"\n"),
        )
        .expect("write sh");
    }
    let docs_dir = dir.path().join("docs");
    fs::create_dir_all(&docs_dir).expect("mkdir");
    for i in 0..9 {
        fs::write(
            docs_dir.join(format!("note_{i:02}.md")),
            format!("# Note {i}\n\nSome ordinary documentation paragraph.\n"),
        )
        .expect("write md");
    }

    let skill = DirectoryLoader::new(dir.path()).load().expect("load");
    let engine = Engine::new(rules::builtin_rules());

    c.bench_function("scan/synthetic-50-file", |b| {
        b.iter(|| std::hint::black_box(engine.scan(&skill)));
    });
}

fn bench_loader_only(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("SKILL.md"),
        "---\nname: load-bench\ndescription: A skill used to measure loader cost in isolation.\nversion: 0.1.0\nlicense: Apache-2.0\nallowed-tools:\n  - Read\n---\n# Body\n",
    )
    .expect("write");
    let root: &Path = dir.path();

    c.bench_function("loader/single-file", |b| {
        b.iter(|| {
            let s = DirectoryLoader::new(root).load().expect("load");
            std::hint::black_box(s)
        });
    });
}

criterion_group!(
    benches,
    bench_loader_only,
    bench_scan_clean,
    bench_scan_realistic
);
criterion_main!(benches);
