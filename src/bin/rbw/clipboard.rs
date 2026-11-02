use std::io::Write as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "clipboard"), allow(dead_code))]
pub enum Mode {
    // print values instead of copying them
    Off,
    On,
    // like On, but falls back to having the terminal set the clipboard
    WithOsc52,
}

impl Mode {
    #[cfg(feature = "clipboard")]
    pub fn new(clipboard: bool, osc52: bool) -> Self {
        match (clipboard, osc52) {
            (false, _) => Self::Off,
            (true, false) => Self::On,
            (true, true) => Self::WithOsc52,
        }
    }
}

pub fn store(text: &str, mode: Mode) -> anyhow::Result<()> {
    let mut last_err = None;
    for (program, args) in candidates() {
        match run(program, args, text) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => last_err = Some(format!("{program} failed: {e}")),
        }
    }

    // sending the value to the terminal works over ssh, but terminal
    // multiplexers and recorders may keep a copy of it, so this is only done
    // if explicitly requested
    if mode == Mode::WithOsc52 {
        return osc52(text);
    }

    Err(anyhow::anyhow!(
        "couldn't store value to clipboard: {}\n\
        (to have the terminal set the clipboard using the OSC 52 escape \
        sequence instead, pass --osc52)",
        last_err.unwrap_or_else(|| NO_TOOL_FOUND.to_string())
    ))
}

#[cfg(target_os = "macos")]
const NO_TOOL_FOUND: &str = "pbcopy not found";

#[cfg(not(target_os = "macos"))]
const NO_TOOL_FOUND: &str = "no clipboard tool found (install wl-clipboard \
    on wayland, or xclip or xsel on x11)";

#[cfg(target_os = "macos")]
fn candidates() -> Vec<(&'static str, &'static [&'static str])> {
    vec![("pbcopy", &[])]
}

#[cfg(not(target_os = "macos"))]
fn candidates() -> Vec<(&'static str, &'static [&'static str])> {
    let is_set = |var| std::env::var_os(var).is_some_and(|v| !v.is_empty());

    let mut candidates: Vec<(&'static str, &'static [&'static str])> = vec![];
    if is_set("WAYLAND_DISPLAY") {
        candidates.push(("wl-copy", &["--type", "text/plain"]));
    }
    if is_set("DISPLAY") {
        candidates.push(("xclip", &["-selection", "clipboard"]));
        candidates.push(("xsel", &["--clipboard", "--input"]));
    }
    candidates
}

fn run(program: &str, args: &[&str], text: &str) -> std::io::Result<()> {
    // these tools fork a background process to serve the clipboard contents,
    // which would keep our stdout and stderr open if it inherited them
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    // pass the value over stdin so that it doesn't show up in the process list
    let mut stdin = child.stdin.take().unwrap();
    let res = stdin.write_all(text.as_bytes());
    drop(stdin);
    let status = child.wait()?;
    res?;
    if !status.success() {
        return Err(std::io::Error::other(format!("exited with {status}")));
    }
    Ok(())
}

fn osc52(text: &str) -> anyhow::Result<()> {
    // write to the terminal directly, since stdout may be redirected
    let mut tty = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|e| {
            anyhow::anyhow!(
                "couldn't store value to clipboard: couldn't open the \
                terminal to send OSC 52: {e}"
            )
        })?;
    write!(tty, "\x1b]52;c;{}\x07", rbw::base64::encode(text))?;
    tty.flush()?;
    Ok(())
}
