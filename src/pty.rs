//! PTY proxy with virtual terminal for persistent status bar.
//!
//! When the status bar is enabled, ai-jail interposes a PTY between
//! itself and the sandbox child. The child writes to the PTY slave
//! while ai-jail owns the real terminal. Child output is processed
//! through a vt100 virtual terminal and diff-rendered to the real
//! terminal, giving ai-jail full control over screen content.
//!
//! This approach (similar to tmux/screen) eliminates ghost status
//! bars on resize: the virtual terminal is resized, its content is
//! re-rendered, and the status bar is redrawn cleanly.

use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::termios::{self, SetArg, Termios};
use std::os::unix::io::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Stored master raw FD for async-signal-safe resize from SIGWINCH.
static MASTER_FD: AtomicI32 = AtomicI32::new(-1);

/// Set by signal handler; IO loop clears screen + redraws status bar
/// BEFORE forwarding SIGWINCH to the child, preventing ghost bars.
static SIGWINCH_PENDING: AtomicBool = AtomicBool::new(false);

/// Mark a SIGWINCH as pending. Called from the signal handler.
pub fn set_sigwinch_pending() {
    SIGWINCH_PENDING.store(true, Ordering::SeqCst);
}

/// Resize the PTY slave to match the real terminal (minus one row
/// for the status bar). Async-signal-safe: only uses ioctl + atomics.
pub fn resize_pty() {
    let master = MASTER_FD.load(Ordering::SeqCst);
    if master < 0 {
        return;
    }
    let mut ws = unsafe { std::mem::zeroed::<nix::libc::winsize>() };
    let ret = unsafe {
        nix::libc::ioctl(
            nix::libc::STDOUT_FILENO,
            nix::libc::TIOCGWINSZ,
            &mut ws,
        )
    };
    if ret != 0 || ws.ws_row < 2 || ws.ws_col == 0 {
        return;
    }
    ws.ws_row -= 1;
    unsafe {
        nix::libc::ioctl(master, nix::libc::TIOCSWINSZ, &ws);
    }
}

/// Explicitly send SIGWINCH to the PTY foreground process group.
/// TIOCSWINSZ should do this via the kernel, but bwrap's PID
/// namespace can prevent delivery. This is the reliable fallback.
fn forward_sigwinch() {
    let master = MASTER_FD.load(Ordering::SeqCst);
    if master < 0 {
        return;
    }
    let mut pgrp: nix::libc::pid_t = 0;
    let ret =
        unsafe { nix::libc::ioctl(master, nix::libc::TIOCGPGRP, &mut pgrp) };
    if ret == 0 && pgrp > 0 {
        unsafe {
            nix::libc::kill(-pgrp, nix::libc::SIGWINCH);
        }
    }
}

fn enter_raw_mode() -> Result<Termios, String> {
    let stdin = std::io::stdin();
    let saved =
        termios::tcgetattr(&stdin).map_err(|e| format!("tcgetattr: {e}"))?;
    let mut raw = saved.clone();
    termios::cfmakeraw(&mut raw);
    termios::tcsetattr(&stdin, SetArg::TCSANOW, &raw)
        .map_err(|e| format!("tcsetattr raw: {e}"))?;
    Ok(saved)
}

fn restore_mode(saved: &Termios) {
    let stdin = std::io::stdin();
    let _ = termios::tcsetattr(&stdin, SetArg::TCSANOW, saved);
}

struct RawModeGuard(Option<Termios>);

impl RawModeGuard {
    fn new(saved: Termios) -> Self {
        Self(Some(saved))
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if let Some(saved) = self.0.take() {
            restore_mode(&saved);
        }
    }
}

fn set_initial_size(fd: &OwnedFd, rows: u16, cols: u16) {
    let ws = nix::libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        nix::libc::ioctl(fd.as_raw_fd(), nix::libc::TIOCSWINSZ, &ws);
    }
}

fn io_loop(master: &OwnedFd, init_rows: u16, init_cols: u16) {
    let stdin_fd = std::io::stdin().as_raw_fd();
    let master_raw = master.as_raw_fd();
    let stdin_bfd = unsafe { BorrowedFd::borrow_raw(stdin_fd) };
    let master_bfd = unsafe { BorrowedFd::borrow_raw(master_raw) };
    let mut buf = [0u8; 8192];

    // Virtual terminal: rows-1 to leave room for status bar.
    // No scrollback needed — the real terminal handles that via
    // the diff-rendered output we send to stdout.
    let mut parser = vt100::Parser::new(init_rows - 1, init_cols, 0);
    let mut prev_screen = parser.screen().clone();
    let mut pending_redraw = false;

    loop {
        // Handle pending SIGWINCH before anything else.
        // Order matters: resize vt100 FIRST, then resize PTY.
        // TIOCSWINSZ on the master makes the kernel deliver
        // SIGWINCH to the child, so we must ensure the virtual
        // terminal is already at the new size before the child
        // starts redrawing.
        if SIGWINCH_PENDING.swap(false, Ordering::SeqCst) {
            let (rows, cols) =
                real_term_size().unwrap_or((init_rows, init_cols));
            if rows >= 2 {
                // 1. Resize virtual terminal
                parser.screen_mut().set_size(rows - 1, cols);

                // 2. Clear real terminal and render current
                //    vt100 content at the new size.
                let stdout = nix::libc::STDOUT_FILENO;
                write_all_raw(stdout, b"\x1b[H\x1b[J");
                let screen = parser.screen();
                let output = screen.state_formatted();
                write_all_raw(stdout, &output);
                prev_screen = screen.clone();

                // 3. Redraw status bar on last row
                crate::statusbar::redraw();

                // 4. NOW resize PTY and explicitly forward
                //    SIGWINCH to the child process group.
                resize_pty();
                forward_sigwinch();

                let _ = crate::statusbar::take_requests();
                pending_redraw = false;
            }
        }

        let mut fds = [
            PollFd::new(stdin_bfd, PollFlags::POLLIN),
            PollFd::new(master_bfd, PollFlags::POLLIN),
        ];

        if crate::statusbar::take_requests() {
            pending_redraw = true;
        }

        match poll(&mut fds, PollTimeout::from(100_u16)) {
            Ok(0) => {
                if pending_redraw {
                    crate::statusbar::redraw();
                    pending_redraw = false;
                }
                continue;
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
            Ok(_) => {}
        }

        // Check master (child output) first for responsiveness
        if let Some(revents) = fds[1].revents() {
            if revents.contains(PollFlags::POLLIN) {
                match nix::unistd::read(master_raw, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        parser.process(&buf[..n]);
                        let screen = parser.screen();
                        let diff = screen.state_diff(&prev_screen);
                        write_all_raw(nix::libc::STDOUT_FILENO, &diff);
                        prev_screen = screen.clone();
                        pending_redraw = true;
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(nix::errno::Errno::EIO) => break,
                    Err(_) => break,
                }
            }
            if revents.contains(PollFlags::POLLHUP)
                || revents.contains(PollFlags::POLLERR)
            {
                loop {
                    match nix::unistd::read(master_raw, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            parser.process(&buf[..n]);
                        }
                    }
                }
                let screen = parser.screen();
                let diff = screen.state_diff(&prev_screen);
                write_all_raw(nix::libc::STDOUT_FILENO, &diff);
                crate::statusbar::redraw();
                break;
            }
        }

        // Redraw status bar when child is quiet
        if !matches!(
            fds[1].revents(),
            Some(r) if r.contains(PollFlags::POLLIN)
        ) && pending_redraw
        {
            crate::statusbar::redraw();
            pending_redraw = false;
        }

        // Check stdin (user input) — forward directly to PTY
        if let Some(revents) = fds[0].revents() {
            if revents.contains(PollFlags::POLLIN) {
                match nix::unistd::read(stdin_fd, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        write_all_raw(master_raw, &buf[..n]);
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(_) => break,
                }
            }
        }
    }
}

/// Write all bytes to a raw fd using libc::write (works in all
/// contexts including pre_exec).
fn write_all_raw(fd: i32, data: &[u8]) {
    let mut off = 0;
    while off < data.len() {
        let n = unsafe {
            nix::libc::write(
                fd,
                data[off..].as_ptr() as *const nix::libc::c_void,
                data.len() - off,
            )
        };
        if n <= 0 {
            break;
        }
        off += n as usize;
    }
}

/// Run the command through a PTY proxy with virtual terminal.
/// Creates PTY pair, enters raw mode, spawns child with PTY slave
/// as stdio, runs IO loop with vt100 diff-rendering, waits for
/// child, restores terminal. Returns exit code.
pub fn run(cmd: &mut std::process::Command) -> Result<i32, String> {
    use std::os::unix::process::CommandExt;

    let (rows, cols) = real_term_size().unwrap_or((24, 80));
    if rows < 2 {
        return Err("Terminal too small for status bar".into());
    }

    // Create PTY pair
    let pty =
        nix::pty::openpty(None, None).map_err(|e| format!("openpty: {e}"))?;
    let master = pty.master;
    let slave = pty.slave;

    // Set FD_CLOEXEC on master so child doesn't inherit it
    let master_raw = master.as_raw_fd();
    unsafe {
        let flags = nix::libc::fcntl(master_raw, nix::libc::F_GETFD);
        nix::libc::fcntl(
            master_raw,
            nix::libc::F_SETFD,
            flags | nix::libc::FD_CLOEXEC,
        );
    }

    // Set initial PTY size (rows-1 for status bar)
    set_initial_size(&master, rows - 1, cols);

    // Enter raw mode on real stdin
    let saved = enter_raw_mode()?;
    let raw_mode_guard = RawModeGuard::new(saved);

    // Configure child to use PTY slave as stdin/stdout/stderr
    let slave_raw = slave.as_raw_fd();
    unsafe {
        cmd.pre_exec(move || {
            if nix::libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if nix::libc::ioctl(
                slave_raw,
                nix::libc::TIOCSCTTY as nix::libc::c_ulong,
                0,
            ) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            nix::libc::dup2(slave_raw, 0);
            nix::libc::dup2(slave_raw, 1);
            nix::libc::dup2(slave_raw, 2);
            if slave_raw > 2 {
                nix::libc::close(slave_raw);
            }
            Ok(())
        });
    }

    // Spawn child
    let child = cmd
        .spawn()
        .map_err(|e| format!("Failed to start sandbox: {e}"))?;

    let pid = child.id() as i32;
    crate::signals::set_child_pid(pid);
    MASTER_FD.store(master_raw, Ordering::SeqCst);

    // Close slave in parent — child has its own copy
    drop(slave);

    // Run IO loop (blocks until child exits / master HUP)
    io_loop(&master, rows, cols);

    // Clean up
    MASTER_FD.store(-1, Ordering::SeqCst);
    drop(master);
    drop(raw_mode_guard);

    // Wait for child
    let exit_code = crate::signals::wait_child(pid);

    // Prevent double-wait
    std::mem::forget(child);

    Ok(exit_code)
}

fn real_term_size() -> Option<(u16, u16)> {
    let mut ws = unsafe { std::mem::zeroed::<nix::libc::winsize>() };
    let ret = unsafe {
        nix::libc::ioctl(
            nix::libc::STDOUT_FILENO,
            nix::libc::TIOCGWINSZ,
            &mut ws,
        )
    };
    if ret == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
        Some((ws.ws_row, ws.ws_col))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn vt100_screen_tracks_content() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(b"Hello, world!");
        let screen = parser.screen();
        let row = screen.rows(0, 80).next().unwrap();
        assert!(row.starts_with("Hello, world!"));
    }

    #[test]
    fn vt100_diff_produces_output() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        let prev = parser.screen().clone();
        parser.process(b"test output");
        let diff = parser.screen().contents_diff(&prev);
        assert!(!diff.is_empty());
    }

    #[test]
    fn vt100_resize_preserves_content() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(b"line1\r\nline2\r\nline3");
        parser.screen_mut().set_size(30, 100);
        let screen = parser.screen();
        let row0 = screen.rows(0, 100).next().unwrap();
        assert!(row0.starts_with("line1"));
    }

    #[test]
    fn vt100_state_diff_includes_mode_changes() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        let prev = parser.screen().clone();
        // Enable bracketed paste mode
        parser.process(b"\x1b[?2004h");
        let diff = parser.screen().state_diff(&prev);
        // state_diff includes both content and mode changes
        assert!(parser.screen().bracketed_paste());
        assert!(!prev.bracketed_paste());
        // Diff should contain the mode change sequence
        assert!(!diff.is_empty());
    }

    #[test]
    fn vt100_alt_screen_tracking() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        assert!(!parser.screen().alternate_screen());
        parser.process(b"\x1b[?1049h");
        assert!(parser.screen().alternate_screen());
        parser.process(b"\x1b[?1049l");
        assert!(!parser.screen().alternate_screen());
    }

    #[test]
    fn vt100_mouse_mode_tracking() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        assert_eq!(
            parser.screen().mouse_protocol_mode(),
            vt100::MouseProtocolMode::None
        );
        parser.process(b"\x1b[?1003h");
        assert_eq!(
            parser.screen().mouse_protocol_mode(),
            vt100::MouseProtocolMode::AnyMotion
        );
    }

    #[test]
    fn vt100_cursor_visibility() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        assert!(!parser.screen().hide_cursor());
        parser.process(b"\x1b[?25l");
        assert!(parser.screen().hide_cursor());
        parser.process(b"\x1b[?25h");
        assert!(!parser.screen().hide_cursor());
    }
}
