use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::Context as _;

pub struct StartupAck {
    writer: std::os::unix::io::OwnedFd,
}

impl StartupAck {
    pub fn ack(self) -> anyhow::Result<()> {
        rustix::io::write(&self.writer, &[0])?;
        Ok(())
    }
}

// exit code used when an agent is already running, which the cli checks for
const ALREADY_RUNNING: u8 = 23;

pub fn daemonize(no_daemonize: bool) -> anyhow::Result<Option<StartupAck>> {
    if no_daemonize {
        let mut pidfile = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o666)
            .open(rbw::dirs::pid_file())
            .context("failed to open pid file")?;
        rustix::fs::flock(
            &pidfile,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .context("failed to lock pid file")?;
        writeln!(pidfile, "{}", std::process::id())
            .context("failed to write pid file")?;
        // don't close the pidfile until the process exits, to ensure it
        // stays locked
        std::mem::forget(pidfile);

        return Ok(None);
    }

    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stdout_file())?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stderr_file())?;

    let (r, w) = rustix::pipe::pipe()?;

    // SAFETY: we are still single threaded at this point
    if let Some(child) = unsafe { fork() }? {
        // the first child exits as soon as it has forked again
        let mut status = 0;
        // SAFETY: child is a pid we just forked
        unsafe { libc::waitpid(child, &raw mut status, 0) };
        drop(w);
        // the daemon writes its exit status to the pipe once it is ready to
        // accept connections. if it fails before that, it closes the pipe
        // without writing anything (and the error is printed to stderr or
        // the agent's stderr log).
        let mut buf = [0; 1];
        let code = match rustix::io::read(&r, &mut buf) {
            Ok(1) => buf[0].into(),
            _ => 1,
        };
        std::process::exit(code);
    }
    drop(r);

    std::env::set_current_dir("/")?;
    rustix::process::setsid()?;
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o027));
    // fork again so that we are not a session leader, and so can't
    // reacquire a controlling terminal
    // SAFETY: we are still single threaded at this point
    if unsafe { fork() }?.is_some() {
        std::process::exit(0);
    }

    let mut pidfile = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o666)
        .open(rbw::dirs::pid_file())
        .context("failed to open pid file")?;
    if rustix::fs::flock(
        &pidfile,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .is_err()
    {
        // this means that there is already an agent running, so return a
        // special exit code to allow the cli to detect this case and not
        // error out
        rustix::io::write(&w, &[ALREADY_RUNNING])?;
        std::process::exit(ALREADY_RUNNING.into());
    }

    let devnull = std::fs::File::open("/dev/null")?;
    rustix::stdio::dup2_stdin(&devnull)?;
    rustix::stdio::dup2_stdout(&stdout)?;
    rustix::stdio::dup2_stderr(&stderr)?;

    pidfile.set_len(0).context("failed to truncate pid file")?;
    writeln!(pidfile, "{}", std::process::id())
        .context("failed to write pid file")?;
    // don't close the pidfile until the process exits, to ensure it stays
    // locked
    std::mem::forget(pidfile);

    Ok(Some(StartupAck { writer: w }))
}

// SAFETY: the process must be single threaded
unsafe fn fork() -> std::io::Result<Option<libc::pid_t>> {
    // SAFETY: guaranteed by the caller
    match unsafe { libc::fork() } {
        -1 => Err(std::io::Error::last_os_error()),
        0 => Ok(None),
        pid => Ok(Some(pid)),
    }
}
