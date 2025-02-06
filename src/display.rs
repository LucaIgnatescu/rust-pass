use anyhow::Result;
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg, Termios};
use std::io::{stdin, stdout, Write};

pub fn display_error(e: anyhow::Error) {
    println!("Error:{}", e);
}

pub struct TerminalControl {
    term: Termios,
}

pub struct InputReader;

impl InputReader {
    pub fn read_password() -> Result<String> {
        let term = TerminalControl::new()?;
        term.disable_echo()?;
        print!("Please enter a master password: ");
        stdout().flush()?;

        let mut buf = String::new();
        stdin().read_line(&mut buf)?;
        println!();
        Ok(buf)
    }

    pub fn read_command() -> Result<String> {
        print!("> ");
        stdout().flush()?;

        let mut buf = String::new();
        stdin().read_line(&mut buf)?;

        Ok(buf)
    }
}

impl TerminalControl {
    pub fn new() -> Result<Self> {
        Ok(Self {
            term: tcgetattr(&stdin())?,
        })
    }

    pub fn disable_echo(&self) -> Result<()> {
        let in_fd = stdin();
        let mut term = tcgetattr(&in_fd)?;
        term.local_flags &= !LocalFlags::ECHO;
        Ok(tcsetattr(&in_fd, SetArg::TCSANOW, &term)?)
    }

    fn restore(&self) -> Result<()> {
        Ok(tcsetattr(&stdin(), SetArg::TCSANOW, &self.term)?)
    }
}

impl Drop for TerminalControl {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
