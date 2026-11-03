// a minimal terminal layer for the tui: raw mode, the alternate screen,
// reading keys, and the display width of text

use std::io::{Read as _, Write as _};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Ctrl(char),
    Alt(char),
    Enter,
    Tab,
    BackTab,
    Backspace,
    Delete,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    F(u8),
}

pub struct Terminal {
    saved: rustix::termios::Termios,
    input: Vec<u8>,
}

impl Terminal {
    pub fn enter() -> anyhow::Result<Self> {
        let stdin = std::io::stdin();
        let saved = rustix::termios::tcgetattr(&stdin).map_err(|e| {
            anyhow::anyhow!("the tui needs a terminal on stdin: {e}")
        })?;
        let mut raw = saved.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(
            &stdin,
            rustix::termios::OptionalActions::Flush,
            &raw,
        )?;
        let term = Self {
            saved,
            input: vec![],
        };
        // alternate screen, hide the cursor
        write_stdout(b"\x1b[?1049h\x1b[?25l\x1b[2J")?;

        // restore the terminal if anything panics, so that the panic message
        // is readable and the shell keeps working
        let saved = term.saved.clone();
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore(&saved);
            hook(info);
        }));
        Ok(term)
    }

    // gives the terminal back temporarily, e.g. for pinentry or an editor
    pub fn suspend<T>(&self, f: impl FnOnce() -> T) -> anyhow::Result<T> {
        restore(&self.saved);
        let res = f();
        let mut raw = self.saved.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(
            std::io::stdin(),
            rustix::termios::OptionalActions::Flush,
            &raw,
        )?;
        write_stdout(b"\x1b[?1049h\x1b[?25l\x1b[2J")?;
        Ok(res)
    }

    pub fn size() -> (usize, usize) {
        terminal_size::terminal_size()
            .map_or((80, 24), |(w, h)| (usize::from(w.0), usize::from(h.0)))
    }

    // waits up to timeout for input, and returns the keys that were read
    pub fn read_keys(
        &mut self,
        timeout: std::time::Duration,
    ) -> anyhow::Result<Vec<Key>> {
        // input left over from the last call is an incomplete escape or
        // utf-8 sequence (e.g. alt+[ sends just "\x1b["). give the rest a
        // moment to arrive, and drop it if it doesn't, rather than blocking
        // until the next key.
        let pending = !self.input.is_empty();
        let wait = if pending {
            std::time::Duration::from_millis(30)
        } else {
            timeout
        };
        if !wait_readable(wait)? {
            self.input.clear();
            return Ok(vec![]);
        }
        self.fill()?;
        // a lone escape could be the start of an escape sequence which
        // hasn't fully arrived yet
        if self.input.last() == Some(&0x1b)
            && wait_readable(std::time::Duration::from_millis(30))?
        {
            self.fill()?;
        }
        let (keys, consumed) = parse_keys(&self.input);
        self.input.drain(..consumed);
        Ok(keys)
    }

    fn fill(&mut self) -> anyhow::Result<()> {
        let mut buf = [0; 1024];
        let n = std::io::stdin().lock().read(&mut buf)?;
        self.input.extend_from_slice(&buf[..n]);
        Ok(())
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        restore(&self.saved);
        let _ = std::panic::take_hook();
    }
}

fn restore(saved: &rustix::termios::Termios) {
    let _ = write_stdout(b"\x1b[0m\x1b[?25h\x1b[?1049l");
    let _ = rustix::termios::tcsetattr(
        std::io::stdin(),
        rustix::termios::OptionalActions::Flush,
        saved,
    );
}

pub fn write_stdout(bytes: &[u8]) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(bytes)?;
    stdout.flush()
}

fn wait_readable(timeout: std::time::Duration) -> anyhow::Result<bool> {
    let stdin = std::io::stdin();
    let mut fds = [rustix::event::PollFd::new(
        &stdin,
        rustix::event::PollFlags::IN,
    )];
    let timeout = rustix::event::Timespec {
        tv_sec: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(timeout.subsec_nanos()),
    };
    match rustix::event::poll(&mut fds, Some(&timeout)) {
        Ok(n) => Ok(n > 0),
        Err(rustix::io::Errno::INTR) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

// returns the parsed keys, and how many bytes they used up. an incomplete
// utf-8 sequence at the end is left for the next read.
fn parse_keys(input: &[u8]) -> (Vec<Key>, usize) {
    let mut keys = vec![];
    let mut i = 0;
    while i < input.len() {
        let (key, len) = match input[i] {
            0x1b => match parse_escape(&input[i..]) {
                Some(key) => key,
                None => break,
            },
            b'\r' | b'\n' => (Some(Key::Enter), 1),
            b'\t' => (Some(Key::Tab), 1),
            0x7f | 0x08 => (Some(Key::Backspace), 1),
            c @ 0x01..=0x1a => (Some(Key::Ctrl(char::from(c - 1 + b'a'))), 1),
            0x00 | 0x1c..=0x1f => (None, 1),
            c => {
                let len = match c {
                    0xc0..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf7 => 4,
                    _ => 1,
                };
                if i + len > input.len() {
                    break;
                }
                (
                    std::str::from_utf8(&input[i..i + len])
                        .ok()
                        .and_then(|s| s.chars().next())
                        .map(Key::Char),
                    len,
                )
            }
        };
        keys.extend(key);
        i += len;
    }
    (keys, i)
}

// returns None if the escape sequence is incomplete
fn parse_escape(input: &[u8]) -> Option<(Option<Key>, usize)> {
    Some(match input.get(1) {
        Some(b'[') => {
            // csi: parameters, then a final byte
            let end =
                input[2..].iter().position(|b| (0x40..=0x7e).contains(b))?;
            let params = &input[2..2 + end];
            let first: u32 = params
                .split(|&b| b == b';')
                .next()
                .and_then(|p| std::str::from_utf8(p).ok())
                .and_then(|p| p.parse().ok())
                .unwrap_or(0);
            let key = match input[2 + end] {
                b'~' => match first {
                    1 | 7 => Some(Key::Home),
                    4 | 8 => Some(Key::End),
                    3 => Some(Key::Delete),
                    5 => Some(Key::PageUp),
                    6 => Some(Key::PageDown),
                    11 => Some(Key::F(1)),
                    12 => Some(Key::F(2)),
                    _ => None,
                },
                b'Z' => Some(Key::BackTab),
                c => cursor_key(c),
            };
            (key, 3 + end)
        }
        Some(b'O') => (cursor_key(*input.get(2)?), 3),
        Some(0x7f) => (Some(Key::Alt('\x7f')), 2),
        Some(&c) if c.is_ascii_graphic() => {
            (Some(Key::Alt(char::from(c))), 2)
        }
        _ => (Some(Key::Esc), 1),
    })
}

// the final byte of the sequences sent for the cursor and function keys
const fn cursor_key(c: u8) -> Option<Key> {
    match c {
        b'A' => Some(Key::Up),
        b'B' => Some(Key::Down),
        b'C' => Some(Key::Right),
        b'D' => Some(Key::Left),
        b'H' => Some(Key::Home),
        b'F' => Some(Key::End),
        b'P' => Some(Key::F(1)),
        b'Q' => Some(Key::F(2)),
        _ => None,
    }
}

// vault data can contain anything, including escape sequences which would
// otherwise be interpreted by the terminal, and bidi overrides which make
// text display differently from what it is, so everything displayed goes
// through this
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if is_unprintable(c) { ' ' } else { c })
        .collect()
}

fn is_unprintable(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

// an approximation of the number of columns a character takes, without the
// full unicode tables: combining marks and zero width characters take none,
// east asian wide characters and emoji take two
pub fn char_width(c: char) -> usize {
    let c = u32::from(c);
    let zero = [
        (0x0300, 0x036f),
        (0x0483, 0x0489),
        (0x0591, 0x05bd),
        (0x0610, 0x061a),
        (0x064b, 0x065f),
        (0x0e31, 0x0e31),
        (0x0e34, 0x0e3a),
        (0x0e47, 0x0e4e),
        (0x1ab0, 0x1aff),
        (0x1dc0, 0x1dff),
        (0x200b, 0x200f),
        (0x20d0, 0x20ff),
        (0xfe00, 0xfe0f),
        (0xfe20, 0xfe2f),
        (0xfeff, 0xfeff),
        (0xe0100, 0xe01ef),
    ];
    let wide = [
        (0x1100, 0x115f),
        (0x231a, 0x231b),
        (0x2329, 0x232a),
        (0x23e9, 0x23ec),
        (0x23f0, 0x23f3),
        (0x25fd, 0x25fe),
        (0x2614, 0x2615),
        (0x2648, 0x2653),
        (0x26a1, 0x26a1),
        (0x26aa, 0x26ab),
        (0x26bd, 0x26be),
        (0x26c4, 0x26c5),
        (0x26ce, 0x26ce),
        (0x26d4, 0x26d4),
        (0x26ea, 0x26ea),
        (0x26f2, 0x26f5),
        (0x26fa, 0x26fd),
        (0x2705, 0x2705),
        (0x270a, 0x270b),
        (0x2728, 0x2728),
        (0x274c, 0x274e),
        (0x2753, 0x2757),
        (0x2795, 0x2797),
        (0x27b0, 0x27bf),
        (0x2b1b, 0x2b1c),
        (0x2b50, 0x2b55),
        (0x2e80, 0x303e),
        (0x3041, 0x33ff),
        (0x3400, 0x4dbf),
        (0x4e00, 0x9fff),
        (0xa000, 0xa4cf),
        (0xa960, 0xa97f),
        (0xac00, 0xd7a3),
        (0xf900, 0xfaff),
        (0xfe10, 0xfe19),
        (0xfe30, 0xfe6f),
        (0xff00, 0xff60),
        (0xffe0, 0xffe6),
        (0x16fe0, 0x18cff),
        (0x1b000, 0x1b2ff),
        (0x1f004, 0x1f004),
        (0x1f0cf, 0x1f0cf),
        (0x1f18e, 0x1f18e),
        (0x1f191, 0x1f19a),
        (0x1f200, 0x1f251),
        (0x1f300, 0x1f64f),
        (0x1f680, 0x1f6ff),
        (0x1f7e0, 0x1f7eb),
        (0x1f90c, 0x1f9ff),
        (0x1fa70, 0x1faff),
        (0x20000, 0x3fffd),
    ];
    let within = |ranges: &[(u32, u32)]| {
        ranges.iter().any(|&(a, b)| (a..=b).contains(&c))
    };
    if within(&zero) {
        0
    } else if within(&wide) {
        2
    } else {
        1
    }
}

pub fn width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

// the longest prefix of s which fits into the given number of columns
pub fn truncate(s: &str, columns: usize) -> &str {
    let mut used = 0;
    for (i, c) in s.char_indices() {
        used += char_width(c);
        if used > columns {
            return &s[..i];
        }
    }
    s
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_keys() {
        assert_eq!(
            parse_keys(b"a\x1b[A\x1b[5~\x10\x1bx\x1b[Z\r\x7f"),
            (
                vec![
                    Key::Char('a'),
                    Key::Up,
                    Key::PageUp,
                    Key::Ctrl('p'),
                    Key::Alt('x'),
                    Key::BackTab,
                    Key::Enter,
                    Key::Backspace,
                ],
                16
            )
        );
        assert_eq!(parse_keys(b"\x1b"), (vec![Key::Esc], 1));
        assert_eq!(parse_keys("ä".as_bytes()), (vec![Key::Char('ä')], 2));
        // an incomplete utf-8 sequence waits for the rest
        assert_eq!(parse_keys(&"ä".as_bytes()[..1]), (vec![], 0));
        assert_eq!(parse_keys(b"\x1b[1;5A"), (vec![Key::Up], 6));
        // an incomplete escape sequence waits for the rest as well
        assert_eq!(parse_keys(b"a\x1b[1;"), (vec![Key::Char('a')], 1));
    }

    #[test]
    fn test_width() {
        assert_eq!(width("abc"), 3);
        assert_eq!(width("日本"), 4);
        assert_eq!(width("e\u{301}"), 1);
        assert_eq!(truncate("日本語", 5), "日本");
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(sanitize("a\x1b[31mb\nc"), "a [31mb c");
        assert_eq!(sanitize("a\u{202e}b\u{2066}c"), "a b c");
    }
}
