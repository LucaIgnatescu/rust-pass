use crate::commands::{Executable, Salts, VaultManager};
use anyhow::anyhow;
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags};
use std::{
    io::{stdin, stdout, Write},
    path::Path,
};

pub struct CreateCommand {
    name: String,
    path: String,
}

impl CreateCommand {
    pub fn new(name: String, path: String) -> Self {
        Self { name, path }
    }
}

impl Executable for CreateCommand {
    fn execute(&self) -> anyhow::Result<()> {
        let file_path = Path::new(&self.path);
        if file_path.is_file() {
            return Err(anyhow!("Could not create database - file already exists!"));
        }

        let buf = read_password()?;

        let salts = Salts::new()?;

        let mut vm = VaultManager::default();

        println!("vault: {:?}", vm);

        return Ok(());
    }
}

fn read_password() -> anyhow::Result<String> {
    let in_fd = stdin();
    let mut term = tcgetattr(&in_fd)?;
    print!("Please enter a master password: ");
    term.local_flags &= !LocalFlags::ECHO;
    tcsetattr(&in_fd, nix::sys::termios::SetArg::TCSANOW, &term)?;
    stdout().flush()?;
    let mut buf = String::new();
    in_fd.read_line(&mut buf)?;
    println!();
    Ok(buf)
}
