use std::{fs, process::Command};

#[test]
fn generates_all_supported_separators() {
    for (template, expected) in [
        ("$fname.$lname", "aaliyah.abbott@example.com"),
        ("$fname_$lname", "aaliyah_abbott@example.com"),
        ("$fname-$lname", "aaliyah-abbott@example.com"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mprobe"))
            .args(["-q", "-t", "example.com", "-c", template, "-l", "1"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), expected);
    }
}

#[test]
fn maps_positional_external_lists_in_template_order() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.txt");
    let last = directory.path().join("last.txt");
    fs::write(&first, "Jane\nJohn\n").unwrap();
    fs::write(&last, "Doe\nSmith\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mprobe"))
        .args(["-t", "example.com", "-c", "$fname.$lname", "-l", "4"])
        .args([&first, &last])
        .arg("-q")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "jane.doe@example.com\njane.smith@example.com\njohn.doe@example.com\njohn.smith@example.com\n"
    );
}

#[test]
fn reports_bundled_wordlists() {
    let output = Command::new(env!("CARGO_BIN_EXE_mprobe"))
        .arg("-s")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for name in ["$fname", "$lname", "$petname", "$role"] {
        assert!(stdout.contains(name));
    }
}

#[test]
fn color_can_be_forced_or_disabled() {
    let colored = Command::new(env!("CARGO_BIN_EXE_mprobe"))
        .args(["--color", "always", "--connections", "0"])
        .output()
        .unwrap();
    assert!(!colored.status.success());
    assert!(colored.stderr.starts_with(b"\x1b["));

    let plain = Command::new(env!("CARGO_BIN_EXE_mprobe"))
        .args(["--color", "never", "--connections", "0"])
        .output()
        .unwrap();
    assert!(!plain.status.success());
    assert!(!plain.stderr.contains(&0x1b));
}
