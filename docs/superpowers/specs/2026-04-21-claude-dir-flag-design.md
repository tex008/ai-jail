# Design: `--claude-dir` flag

**Date:** 2026-04-21
**Status:** Approved

## Problem

Users running multiple Claude Code profiles (e.g., one for work using `~/.claude` and
one personal using `~/.claude-tex`) cannot use ai-jail with the non-default profile.

Two failures compound each other:

1. **Alias does not survive bwrap.** A typical workaround is a shell alias like
   `alias claudetex="CLAUDE_CONFIG_DIR=~/.claude-tex command claude"`. bwrap forks a
   new process that does not inherit the parent shell's aliases, so executing
   `ai-jail claudetex` fails with "command not found".

2. **Non-default config dir is not mounted rw.** `DOTDIR_RW` in `sandbox/mod.rs` is a
   hardcoded list. Only `.claude` is in it. Any other directory (`.claude-tex`,
   `.claude-work`, etc.) either receives no mount or a read-only bind, making Claude
   unable to write sessions, history, or settings.

## Solution

Add a `--claude-dir <path>` flag. When set, ai-jail:

1. Mounts the specified directory as read-write inside the sandbox.
2. Injects `CLAUDE_CONFIG_DIR=<absolute-path>` as an env var inside the sandbox.
3. Adds the path to Landlock rw rules (Linux).
4. Redirects `--bootstrap` output to the correct `settings.json` inside that dir.

The user runs `claude` (the real binary), not `claudetex`. The flag carries the profile
selection. No aliases, no shell environment tricks.

## User Experience

```bash
# One-time setup in the personal project directory:
ai-jail --claude-dir ~/.claude-tex --init claude

# Every subsequent run in that directory:
ai-jail claude   # .ai-jail already has claude_dir persisted
```

The shell alias `claudetex` becomes unnecessary.

## Affected Files

| File | Change |
|------|--------|
| `src/cli.rs` | Add `claude_dir: Option<PathBuf>` to `CliArgs`; parse `--claude-dir <path>` |
| `src/config.rs` | Add `claude_dir: Option<PathBuf>` to `Config` with `#[serde(default)]` |
| `src/sandbox/bwrap.rs` | Mount `claude_dir` as rw bind; inject `CLAUDE_CONFIG_DIR` via `--setenv` |
| `src/sandbox/landlock.rs` | Add `claude_dir` path to rw Landlock rules |
| `src/sandbox/seatbelt.rs` | Allow rw access to `claude_dir` in SBPL profile (macOS) |
| `src/bootstrap.rs` | Use `claude_dir` in `claude_config_path()` when set |

## Detailed Design

### `cli.rs`

New field in `CliArgs`:

```rust
pub claude_dir: Option<PathBuf>,
```

Parsed in the `lexopt` loop:

```rust
Long("claude-dir") => {
    let val = parser.value()?;
    args.claude_dir = Some(PathBuf::from(val));
}
```

No short flag — consistent with the project's style for path flags.

### `config.rs`

New field in `Config`:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub claude_dir: Option<PathBuf>,
```

`serde(default)` ensures old `.ai-jail` files without this field continue parsing.
`skip_serializing_if` keeps the file clean for users who do not use the flag.

`config::merge` copies `cli.claude_dir` into `Config` when present, following the same
pattern as all other CLI-overridable fields.

The path is resolved to absolute at merge time — tilde expansion via `shellexpand` (or
manual `$HOME` substitution consistent with how the project handles other paths), then
`fs::canonicalize` if the directory already exists, otherwise just the expanded absolute
path. All downstream consumers (`bwrap`, `landlock`, `seatbelt`, `bootstrap`) receive
an already-resolved `PathBuf` with no further path logic needed.

### `sandbox/bwrap.rs`

Two additions when `config.claude_dir` is `Some(path)`:

**Mount:** Inject a `Mount::Bind { src: path.clone(), dest: path.clone() }` into the
home dotfiles mount list. This must come after the `Mount::Tmpfs` for `$HOME` and after
the standard dotdir mounts so it is not shadowed.

**Env var:** Add `--setenv CLAUDE_CONFIG_DIR <path>` to the bwrap command before the
inner command arguments. bwrap's `--setenv` sets an environment variable in the child
process without leaking the parent environment.

### `sandbox/landlock.rs`

When `config.claude_dir` is `Some(path)`, add `path` to the set of paths granted
`ReadWrite` access in the Landlock ruleset. This mirrors how the project directory
itself is handled. Without this, Landlock blocks filesystem access to the dir even
though bwrap has bind-mounted it.

### `sandbox/seatbelt.rs` (macOS)

Add the resolved path to the SBPL `allow` block with `file-read*` and `file-write*`
permissions, following the pattern used for other rw dotdirs.

### `bootstrap.rs`

`claude_config_path()` currently returns `$HOME/.claude/settings.json` unconditionally.
Change its signature to accept an `Option<&Path>`:

```rust
fn claude_config_path(claude_dir: Option<&Path>) -> PathBuf {
    let base = claude_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(home).join(".claude"));
    base.join("settings.json")
}
```

`bootstrap::run` receives the `claude_dir` from the config and passes it through.

## Backward Compatibility

- No existing config field is removed or renamed.
- No existing CLI flag changes meaning.
- `claude_dir` defaults to `None`, preserving all prior behavior when the flag is
  absent.
- Old `.ai-jail` files without `claude_dir` continue to parse correctly.

## Out of Scope

- Generic `--env KEY=VALUE` passthrough: not needed for this problem, adds complexity.
- Multi-profile support for Codex, OpenCode, or Crush: those tools do not have the same
  alternate-config-dir pattern. Add when a real use case exists.
- Windows support: not in project scope.

## Testing

- Unit test in `config.rs`: round-trip serialize/deserialize a `Config` with
  `claude_dir` set; verify old config without the field still parses.
- Unit test in `bwrap.rs`: assert that when `claude_dir` is set, the generated bwrap
  argv contains the expected `--bind` and `--setenv` arguments.
- Unit test in `bootstrap.rs`: verify `claude_config_path` returns the custom dir when
  `claude_dir` is set, and the default `.claude` path when it is `None`.
