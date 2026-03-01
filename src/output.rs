use std::io::{self, IsTerminal, Write};

fn is_tty() -> bool {
    io::stderr().is_terminal()
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";

pub fn info(msg: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{BOLD}{GREEN}▸{RESET} {msg}");
    } else {
        let _ = writeln!(out, "▸ {msg}");
    }
}

pub fn warn(msg: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{BOLD}{YELLOW}⚠{RESET} {msg}");
    } else {
        let _ = writeln!(out, "⚠ {msg}");
    }
}

pub fn error(msg: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{BOLD}{RED}✗{RESET} {msg}");
    } else {
        let _ = writeln!(out, "✗ {msg}");
    }
}

pub fn ok(msg: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{BOLD}{GREEN}✓{RESET} {msg}");
    } else {
        let _ = writeln!(out, "✓ {msg}");
    }
}

pub fn verbose(msg: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{DIM}  {msg}{RESET}");
    } else {
        let _ = writeln!(out, "  {msg}");
    }
}

pub fn status_header(label: &str, value: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{BOLD}{CYAN}{label}{RESET}: {value}");
    } else {
        let _ = writeln!(out, "{label}: {value}");
    }
}

pub fn dry_run_line(line: &str) {
    let out = io::stdout();
    let mut out = out.lock();
    let _ = writeln!(out, "{line}");
}
