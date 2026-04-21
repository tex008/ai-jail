# `--claude-dir` Flag Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--claude-dir <path>` flag that mounts a custom Claude config directory rw inside the sandbox and injects `CLAUDE_CONFIG_DIR` as an env var, enabling multiple Claude profiles.

**Architecture:** New optional field `claude_dir: Option<PathBuf>` flows from `CliArgs` → `Config` (with tilde expansion at merge time). The sandbox layers (bwrap mount, bwrap setenv, Landlock rw rule, seatbelt writable path) each consume it from `Config`. Bootstrap uses it to write `settings.json` to the correct dir.

**Tech Stack:** Rust, lexopt (CLI parsing), serde/toml (config), bwrap (Linux sandbox), landlock crate, sandbox-exec (macOS).

---

## File Map

| File | Change |
|------|--------|
| `src/cli.rs` | Add `claude_dir: Option<PathBuf>` to `CliArgs`, parse `--claude-dir`, update HELP |
| `src/config.rs` | Add `claude_dir` field to `Config`, expand tilde in `merge`, handle in `merge_with_global` |
| `src/sandbox/bwrap.rs` | Add Bind mount + `CLAUDE_CONFIG_DIR` setenv + pass `--claude-dir` to landlock wrapper |
| `src/sandbox/landlock.rs` | Add `claude_dir` to rw paths in `collect_normal_paths` |
| `src/sandbox/seatbelt.rs` | Add `claude_dir` to `macos_writable_paths`, set env in `build` |
| `src/bootstrap.rs` | Accept `Option<&Path>` in `claude_config_path`, thread through `run` |

---

## Task 1: Data layer — `CliArgs` and `Config`

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/config.rs`

### CLI (`src/cli.rs`)

- [ ] **Step 1: Add `claude_dir` field to `CliArgs` struct**

In `src/cli.rs`, add the field after `allow_tcp_ports` at line 67:

```rust
pub allow_tcp_ports: Vec<u16>,
pub claude_dir: Option<PathBuf>,   // ← add this
pub exec: bool,
```

- [ ] **Step 2: Add parsing branch in the lexopt loop**

In `parse_from`, after the `Long("allow-tcp-port")` arm (around line 132), add:

```rust
Long("claude-dir") => {
    let val = parser.value().map_err(|e| e.to_string())?;
    args.claude_dir = Some(PathBuf::from(val.to_string_lossy().into_owned()));
}
```

- [ ] **Step 3: Add `--claude-dir` to the HELP string**

In the `HELP` const (around line 17), add after `--rw-map`:

```
    --claude-dir <PATH>            Use PATH as Claude config dir (sets CLAUDE_CONFIG_DIR)
```

- [ ] **Step 4: Write the failing test**

In the `#[cfg(test)]` module in `src/cli.rs`, add:

```rust
#[test]
fn parse_claude_dir() {
    let args =
        parse_test(&["--claude-dir", "/home/user/.claude-example", "claude"])
            .unwrap();
    assert_eq!(
        args.claude_dir,
        Some(PathBuf::from("/home/user/.claude-example"))
    );
    assert_eq!(args.command, vec!["claude"]);
}

#[test]
fn parse_claude_dir_missing_value_errors() {
    assert!(parse_test(&["--claude-dir"]).is_err());
}
```

- [ ] **Step 5: Run failing tests**

```bash
cargo test --lib cli::tests::parse_claude_dir 2>&1 | tail -5
cargo test --lib cli::tests::parse_claude_dir_missing_value_errors 2>&1 | tail -5
```

Expected: FAIL (field doesn't exist yet)

- [ ] **Step 6: Confirm both tests pass after steps 1-3**

```bash
cargo test --lib cli::tests::parse_claude_dir
cargo test --lib cli::tests::parse_claude_dir_missing_value_errors
```

Expected: PASS

### Config (`src/config.rs`)

- [ ] **Step 7: Add `claude_dir` field to `Config` struct**

In `src/config.rs`, in the `Config` struct, add after `allow_tcp_ports` at line 51:

```rust
#[serde(default)]
pub allow_tcp_ports: Vec<u16>,
#[serde(default, skip_serializing_if = "Option::is_none")]
pub claude_dir: Option<PathBuf>,  // ← add this
```

- [ ] **Step 8: Add tilde-expansion helper**

Add this private function anywhere in `src/config.rs` before `merge`:

```rust
fn expand_home_in_path(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    p
}
```

- [ ] **Step 9: Wire `claude_dir` in `merge`**

In `config::merge` (around line 330), add before the final `config` return:

```rust
if let Some(p) = cli.claude_dir.clone() {
    config.claude_dir = Some(expand_home_in_path(p));
}
```

- [ ] **Step 10: Wire `claude_dir` in `merge_with_global`**

In `config::merge_with_global` (around line 155), add in the block that merges optional fields (after the `allow_tcp_ports` block):

```rust
if local.claude_dir.is_some() {
    c.claude_dir = local.claude_dir;
}
```

- [ ] **Step 11: Write the failing tests**

In the `#[cfg(test)]` module in `src/config.rs`, add:

```rust
#[test]
fn regression_v0_9_0_config_without_claude_dir() {
    // v0.9.0 configs don't have claude_dir. Must parse and default to None.
    let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = false
no_landlock = false
no_status_bar = false
no_seccomp = false
no_rlimits = false
"#;
    let cfg = parse_toml(toml).unwrap();
    assert_eq!(cfg.claude_dir, None);
}

#[test]
fn parse_claude_dir_from_toml() {
    let toml = r#"
command = ["claude"]
claude_dir = "/home/user/.claude-example"
"#;
    let cfg = parse_toml(toml).unwrap();
    assert_eq!(cfg.claude_dir, Some(PathBuf::from("/home/user/.claude-example")));
}

#[test]
fn merge_claude_dir_from_cli() {
    let existing = Config::default();
    let cli = CliArgs {
        claude_dir: Some(PathBuf::from("/home/user/.claude-example")),
        ..CliArgs::default()
    };
    let merged = merge(&cli, existing);
    assert_eq!(
        merged.claude_dir,
        Some(PathBuf::from("/home/user/.claude-example"))
    );
}

#[test]
fn merge_claude_dir_expands_tilde() {
    let _env = ENV_LOCK.lock().unwrap();
    unsafe { std::env::set_var("HOME", "/home/testuser") };

    let existing = Config::default();
    let cli = CliArgs {
        claude_dir: Some(PathBuf::from("~/.claude-example")),
        ..CliArgs::default()
    };
    let merged = merge(&cli, existing);
    assert_eq!(
        merged.claude_dir,
        Some(PathBuf::from("/home/testuser/.claude-example"))
    );

    unsafe { std::env::remove_var("HOME") };
}

#[test]
fn merge_cli_no_claude_dir_preserves_config_claude_dir() {
    let existing = Config {
        claude_dir: Some(PathBuf::from("/home/user/.claude-example")),
        ..Config::default()
    };
    let cli = CliArgs::default();
    let merged = merge(&cli, existing);
    assert_eq!(
        merged.claude_dir,
        Some(PathBuf::from("/home/user/.claude-example"))
    );
}

#[test]
fn roundtrip_claude_dir() {
    let config = Config {
        command: vec!["claude".into()],
        claude_dir: Some(PathBuf::from("/home/user/.claude-example")),
        ..Config::default()
    };
    let serialized = toml::to_string_pretty(&config).unwrap();
    let deserialized = parse_toml(&serialized).unwrap();
    assert_eq!(deserialized.claude_dir, config.claude_dir);
}

#[test]
fn roundtrip_claude_dir_none_not_written() {
    let config = Config {
        command: vec!["claude".into()],
        claude_dir: None,
        ..Config::default()
    };
    let serialized = toml::to_string_pretty(&config).unwrap();
    assert!(!serialized.contains("claude_dir"));
}
```

- [ ] **Step 12: Run failing tests**

```bash
cargo test --lib config::tests::regression_v0_9_0_config_without_claude_dir 2>&1 | tail -5
cargo test --lib config::tests::parse_claude_dir_from_toml 2>&1 | tail -5
cargo test --lib config::tests::merge_claude_dir_from_cli 2>&1 | tail -5
```

Expected: FAIL

- [ ] **Step 13: Confirm all new config tests pass**

```bash
cargo test --lib config::tests 2>&1 | tail -20
```

Expected: all pass

- [ ] **Step 14: Run full test suite to check nothing regressed**

```bash
cargo test 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 15: Commit**

```bash
git add src/cli.rs src/config.rs
git commit -m "feat: add --claude-dir flag to CLI and Config"
```

---

## Task 2: bwrap — rw bind mount + CLAUDE_CONFIG_DIR env var

**Files:**
- Modify: `src/sandbox/bwrap.rs`

This task adds the claude_dir Bind mount to the home dotfiles list and injects
`CLAUDE_CONFIG_DIR` as a `--setenv` in the bwrap argv.

### Write the failing test first

- [ ] **Step 1: Write the failing test**

In the `#[cfg(test)]` module of `src/sandbox/bwrap.rs`, add:

```rust
#[test]
fn claude_dir_produces_bind_mount_and_setenv() {
    let tmp_root = std::env::temp_dir()
        .join(format!("ai-jail-bwrap-claude-{}", std::process::id()));
    let claude_dir = tmp_root.join(".claude-example");
    let _ = std::fs::create_dir_all(&claude_dir);

    let config = Config {
        command: vec!["claude".into()],
        claude_dir: Some(claude_dir.clone()),
        no_gpu: Some(true),
        no_docker: Some(true),
        no_display: Some(true),
        ..Config::default()
    };
    let project = PathBuf::from("/tmp/project");

    let args = build_dry_run_args(
        &config,
        &project,
        Path::new("/tmp/hosts"),
        None,
        Path::new("/tmp/empty"),
        false,
    )
    .unwrap();

    // --bind claude_dir claude_dir must appear
    let bind_pos = args.windows(3).position(|w| {
        w[0] == "--bind"
            && w[1] == claude_dir.display().to_string()
            && w[2] == claude_dir.display().to_string()
    });
    assert!(
        bind_pos.is_some(),
        "--bind for claude_dir not found in argv: {args:?}"
    );

    // --setenv CLAUDE_CONFIG_DIR <path> must appear
    let setenv_pos = args.windows(3).position(|w| {
        w[0] == "--setenv"
            && w[1] == "CLAUDE_CONFIG_DIR"
            && w[2] == claude_dir.display().to_string()
    });
    assert!(
        setenv_pos.is_some(),
        "--setenv CLAUDE_CONFIG_DIR not found in argv: {args:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[test]
fn no_claude_dir_no_setenv() {
    let config = Config {
        command: vec!["claude".into()],
        claude_dir: None,
        no_gpu: Some(true),
        no_docker: Some(true),
        no_display: Some(true),
        ..Config::default()
    };
    let project = PathBuf::from("/tmp/project");
    let args = build_dry_run_args(
        &config,
        &project,
        Path::new("/tmp/hosts"),
        None,
        Path::new("/tmp/empty"),
        false,
    )
    .unwrap();

    assert!(
        !args.iter().any(|a| a == "CLAUDE_CONFIG_DIR"),
        "CLAUDE_CONFIG_DIR must not appear when claude_dir is None"
    );
}
```

- [ ] **Step 2: Run failing tests**

```bash
cargo test --lib sandbox::bwrap::tests::claude_dir_produces_bind_mount_and_setenv 2>&1 | tail -5
cargo test --lib sandbox::bwrap::tests::no_claude_dir_no_setenv 2>&1 | tail -5
```

Expected: FAIL

### Implement

- [ ] **Step 3: Add `claude_env` field to `MountSet`**

In `src/sandbox/bwrap.rs`, in the `MountSet` struct (around line 66), add:

```rust
ssh_env: Vec<(String, String)>,
claude_env: Vec<(String, String)>,  // ← add this
pictures: Vec<Mount>,
```

- [ ] **Step 4: Emit `CLAUDE_CONFIG_DIR` in `isolation_args`**

In `MountSet::isolation_args`, after the `ssh_env` block (around line 179):

```rust
// SSH agent env (non-lockdown only — lockdown clears env)
if !lockdown {
    for (key, val) in &self.ssh_env {
        args.push("--setenv".into());
        args.push(key.clone());
        args.push(val.clone());
    }
}

// CLAUDE_CONFIG_DIR: inject regardless of lockdown so custom
// profiles work in both normal and lockdown modes.
for (key, val) in &self.claude_env {
    args.push("--setenv".into());
    args.push(key.clone());
    args.push(val.clone());
}
```

- [ ] **Step 5: Populate `claude_env` in `discover_mounts`**

In `discover_mounts`, build `claude_env` and add the rw Bind mount.
Add after the `ssh_agent_mount` block (around line 866) and update the `MountSet` literal:

```rust
// claude_dir: explicit rw bind + CLAUDE_CONFIG_DIR env var.
// A Bind mount placed after the normal dotfiles scan overrides
// any RoBind that the scan might have added for the same dir.
let claude_env: Vec<(String, String)> = if !lockdown {
    if let Some(dir) = &config.claude_dir {
        vec![("CLAUDE_CONFIG_DIR".into(), dir.display().to_string())]
    } else {
        vec![]
    }
} else {
    if let Some(dir) = &config.claude_dir {
        vec![("CLAUDE_CONFIG_DIR".into(), dir.display().to_string())]
    } else {
        vec![]
    }
};
```

(Both branches are the same — `CLAUDE_CONFIG_DIR` is always injected when
`claude_dir` is set, regardless of lockdown mode.)

Simplify to:

```rust
let claude_env: Vec<(String, String)> =
    if let Some(dir) = &config.claude_dir {
        vec![("CLAUDE_CONFIG_DIR".into(), dir.display().to_string())]
    } else {
        vec![]
    };
```

Then add the Bind mount to `home_dotfiles`. Replace the current assignment:

```rust
home_dotfiles: discover_home_dotfiles(
    lockdown,
    &config.hide_dotdirs,
    &exempt,
    verbose,
),
```

With:

```rust
home_dotfiles: {
    let mut dotfiles = discover_home_dotfiles(
        lockdown,
        &config.hide_dotdirs,
        &exempt,
        verbose,
    );
    // Explicit rw bind for custom claude_dir. Placed after the
    // normal dotfiles scan so it overrides any ro bind the scan
    // added for the same path.
    if !lockdown {
        if let Some(dir) = &config.claude_dir {
            if super::path_exists(dir) {
                if verbose {
                    output::verbose(&format!(
                        "claude-dir: {} rw",
                        dir.display()
                    ));
                }
                dotfiles.push(Mount::Bind {
                    src: dir.clone(),
                    dest: dir.clone(),
                });
            }
        }
    }
    dotfiles
},
```

And add `claude_env` to the `MountSet` literal:

```rust
ssh_agent: ssh_agent_mount,
ssh_env,
claude_env,   // ← add this
pictures: pictures_mount,
```

- [ ] **Step 6: Pass `--claude-dir` in `landlock_wrapper_args`**

In `landlock_wrapper_args` (around line 593), add after the `--mask` block:

```rust
for path in &config.mask {
    args.push("--mask".into());
    args.push(path.display().to_string());
}

// Pass claude_dir so the inner landlock-exec process applies the
// correct Landlock rw rules.
if let Some(dir) = &config.claude_dir {
    args.push("--claude-dir".into());
    args.push(dir.display().to_string());
}
```

- [ ] **Step 7: Confirm tests pass**

```bash
cargo test --lib sandbox::bwrap::tests::claude_dir_produces_bind_mount_and_setenv
cargo test --lib sandbox::bwrap::tests::no_claude_dir_no_setenv
```

Expected: PASS

- [ ] **Step 8: Run full test suite**

```bash
cargo test 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 9: Commit**

```bash
git add src/sandbox/bwrap.rs
git commit -m "feat: mount claude_dir rw and inject CLAUDE_CONFIG_DIR in bwrap"
```

---

## Task 3: Landlock — rw rule for `claude_dir`

**Files:**
- Modify: `src/sandbox/landlock.rs`

Without this, Landlock blocks access to claude_dir even though bwrap bind-mounts it.

### Write failing test first

- [ ] **Step 1: Write the failing test**

In `#[cfg(test)]` of `src/sandbox/landlock.rs`, add:

```rust
#[test]
fn normal_paths_claude_dir_is_writable() {
    let tmp_root = std::env::temp_dir()
        .join(format!("ai-jail-landlock-claude-{}", std::process::id()));
    let claude_dir = tmp_root.join(".claude-example");
    let _ = std::fs::create_dir_all(&claude_dir);

    let config = Config {
        no_gpu: Some(true),
        no_docker: Some(true),
        claude_dir: Some(claude_dir.clone()),
        ..Config::default()
    };
    let (_, rw) = collect_normal_paths(&config, Path::new("/tmp"), false);
    assert!(
        rw.contains(&claude_dir),
        "claude_dir must be in Landlock rw paths"
    );

    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[test]
fn normal_paths_no_claude_dir_unchanged() {
    let config = Config {
        no_gpu: Some(true),
        no_docker: Some(true),
        claude_dir: None,
        ..Config::default()
    };
    let (_, rw) = collect_normal_paths(&config, Path::new("/tmp"), false);
    // Verify no phantom CLAUDE_CONFIG_DIR path sneaked in
    assert!(
        !rw.iter().any(|p| p.to_string_lossy().contains("claude-example")),
        "Unexpected claude-example path in rw list"
    );
}
```

- [ ] **Step 2: Run failing tests**

```bash
cargo test --lib sandbox::landlock::tests::normal_paths_claude_dir_is_writable 2>&1 | tail -5
```

Expected: FAIL

### Implement

- [ ] **Step 3: Add `claude_dir` rw path to `collect_normal_paths`**

In `collect_normal_paths` in `src/sandbox/landlock.rs`, after the `~/.claude.json` block (around line 475), add:

```rust
// claude_dir: rw access for non-default Claude config directories.
// When --claude-dir is set, bwrap bind-mounts it; Landlock must
// allow rw access too, otherwise VFS-level checks block the process.
if let Some(dir) = &config.claude_dir {
    if super::path_exists(dir) {
        if verbose {
            output::verbose(&format!(
                "Landlock: claude-dir {} rw",
                dir.display()
            ));
        }
        rw.push(dir.clone());
    }
}
```

- [ ] **Step 4: Confirm tests pass**

```bash
cargo test --lib sandbox::landlock::tests::normal_paths_claude_dir_is_writable
cargo test --lib sandbox::landlock::tests::normal_paths_no_claude_dir_unchanged
```

Expected: PASS

- [ ] **Step 5: Run full test suite**

```bash
cargo test 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add src/sandbox/landlock.rs
git commit -m "feat: add claude_dir to Landlock rw rules"
```

---

## Task 4: Seatbelt — macOS writable path + env var

**Files:**
- Modify: `src/sandbox/seatbelt.rs`

### Implement (no unit tests — seatbelt tests are integration-only on macOS)

- [ ] **Step 1: Add `claude_dir` to `macos_writable_paths`**

In `macos_writable_paths` in `src/sandbox/seatbelt.rs`, after the `claude_json` block (around line 354), add:

```rust
let claude_json = home.join(".claude.json");
if claude_json.is_file() {
    paths.push(claude_json);
}

// claude_dir: writable when --claude-dir is set
if let Some(dir) = &config.claude_dir {
    if super::path_exists(dir) {
        paths.push(dir.clone());
    }
}
```

- [ ] **Step 2: Set `CLAUDE_CONFIG_DIR` env var in `build`**

In `seatbelt::build` (around line 70), after `cmd.env("PS1", ...)`:

```rust
cmd.env("PS1", "(jail) \\w \\$ ");
cmd.env("_ZO_DOCTOR", "0");

// Inject CLAUDE_CONFIG_DIR when a custom claude dir is configured.
if let Some(dir) = &config.claude_dir {
    cmd.env("CLAUDE_CONFIG_DIR", dir);
}
```

- [ ] **Step 3: Run full test suite**

```bash
cargo test 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 4: Check compilation**

```bash
cargo build 2>&1 | tail -10
```

Expected: no errors

- [ ] **Step 5: Commit**

```bash
git add src/sandbox/seatbelt.rs
git commit -m "feat: add claude_dir support to macOS seatbelt backend"
```

---

## Task 5: Bootstrap — write `settings.json` to the correct dir

**Files:**
- Modify: `src/bootstrap.rs`
- Modify: `src/main.rs` (update the `bootstrap::run` call)

### Write failing test first

- [ ] **Step 1: Write the failing test**

In the `#[cfg(test)]` module of `src/bootstrap.rs`, add:

```rust
#[test]
fn claude_config_path_uses_custom_dir() {
    let custom = PathBuf::from("/home/user/.claude-example");
    let path = claude_config_path(Some(&custom));
    assert_eq!(path, PathBuf::from("/home/user/.claude-example/settings.json"));
}

#[test]
fn claude_config_path_defaults_to_dot_claude() {
    let _env = crate::config::tests::ENV_LOCK.lock().unwrap();
    // ENV_LOCK is not pub — use a local env lock approach
    // (bootstrap tests already use HOME manipulation)
    unsafe { std::env::set_var("HOME", "/home/testuser") };
    let path = claude_config_path(None);
    assert_eq!(
        path,
        PathBuf::from("/home/testuser/.claude/settings.json")
    );
    unsafe { std::env::remove_var("HOME") };
}
```

*Note: `config::tests::ENV_LOCK` is not pub. Declare a local one in bootstrap tests:*

```rust
#[cfg(test)]
mod tests {
    use super::*;
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // ... tests here
}
```

- [ ] **Step 2: Run failing tests**

```bash
cargo test --lib bootstrap::tests::claude_config_path_uses_custom_dir 2>&1 | tail -5
cargo test --lib bootstrap::tests::claude_config_path_defaults_to_dot_claude 2>&1 | tail -5
```

Expected: FAIL

### Implement

- [ ] **Step 3: Change `claude_config_path` signature**

In `src/bootstrap.rs`, replace:

```rust
fn claude_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".claude").join("settings.json")
}
```

With:

```rust
fn claude_config_path(claude_dir: Option<&Path>) -> PathBuf {
    match claude_dir {
        Some(dir) => dir.join("settings.json"),
        None => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".claude").join("settings.json")
        }
    }
}
```

- [ ] **Step 4: Add `claude_dir` parameter to `bootstrap_claude`**

Replace:

```rust
fn bootstrap_claude(verbose: bool) -> Result<(), String> {
    let path = claude_config_path();
```

With:

```rust
fn bootstrap_claude(
    verbose: bool,
    claude_dir: Option<&Path>,
) -> Result<(), String> {
    let path = claude_config_path(claude_dir);
```

- [ ] **Step 5: Add `claude_dir` parameter to `run` and thread it through**

Replace:

```rust
pub fn run(verbose: bool) -> Result<(), String> {
    output::info("Bootstrapping AI tool configs...");

    bootstrap_claude(verbose)?;
```

With:

```rust
pub fn run(verbose: bool, claude_dir: Option<&Path>) -> Result<(), String> {
    output::info("Bootstrapping AI tool configs...");

    bootstrap_claude(verbose, claude_dir)?;
```

- [ ] **Step 6: Update the call site in `src/main.rs`**

In `src/main.rs`, find the bootstrap call (around line 130):

```rust
if cli.bootstrap {
    bootstrap::run(cli.verbose)?;
    return Ok(0);
}
```

Replace with:

```rust
if cli.bootstrap {
    bootstrap::run(cli.verbose, config.claude_dir.as_deref())?;
    return Ok(0);
}
```

- [ ] **Step 7: Confirm tests pass**

```bash
cargo test --lib bootstrap::tests::claude_config_path_uses_custom_dir
cargo test --lib bootstrap::tests::claude_config_path_defaults_to_dot_claude
```

Expected: PASS

- [ ] **Step 8: Run full test suite**

```bash
cargo test 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 9: Run fmt and clippy**

```bash
cargo fmt
cargo clippy -- -D warnings 2>&1 | tail -20
```

Expected: no warnings

- [ ] **Step 10: Commit**

```bash
git add src/bootstrap.rs src/main.rs
git commit -m "feat: thread claude_dir through bootstrap to write settings.json to correct dir"
```

---

## Task 6: Final verification

- [ ] **Step 1: Full test suite**

```bash
cargo test 2>&1 | tail -15
```

Expected: all pass, 0 failures

- [ ] **Step 2: Release build**

```bash
cargo build --release 2>&1 | tail -5
```

Expected: no errors

- [ ] **Step 3: Dry-run smoke test**

```bash
mkdir -p /tmp/claude-example-dir
./target/release/ai-jail \
  --dry-run \
  --no-gpu \
  --claude-dir /tmp/claude-example-dir \
  claude 2>&1 | grep -E "bind|CLAUDE_CONFIG_DIR"
```

Expected: output contains `--bind /tmp/claude-example-dir /tmp/claude-example-dir`
and `--setenv CLAUDE_CONFIG_DIR /tmp/claude-example-dir`

- [ ] **Step 4: Dry-run smoke test with tilde**

```bash
./target/release/ai-jail \
  --dry-run \
  --no-gpu \
  --claude-dir ~/.claude \
  claude 2>&1 | grep "CLAUDE_CONFIG_DIR"
```

Expected: output contains the expanded absolute path (not `~/`)

- [ ] **Step 5: Final fmt check**

```bash
cargo fmt --check
```

Expected: no diff

- [ ] **Step 6: Final commit (if any fmt changes)**

```bash
git add -u
git commit -m "style: cargo fmt"
```
