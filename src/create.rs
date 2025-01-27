use crate::{
    commands::Executable,
    protos::rpdb::{Body, Header, RPDB},
};
use anyhow::anyhow;
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags};
use protobuf::{well_known_types::timestamp::Timestamp, MessageField};
use ring::rand::SecureRandom;
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

    fn initialize_vault() -> anyhow::Result<(RPDB)> {
        let rng = ring::rand::SystemRandom::new();
        let mut header = Header::new();
        header.signature = 0x3af9c42;

        let mut salt = vec![0u8; 32];
        rng.fill(&mut salt);
        header.master_salt = salt;
        header.version = 0x0001;

        let mut body = Body::new();
        rng.fill(&mut salt);
        body.created_at = MessageField::some(Timestamp::now());
        body.last_modified = MessageField::some(Timestamp::now());

        let mut rpdb = RPDB::new();
        rpdb.header = MessageField::some(header);

        rpdb.body = body;

        Ok(rpdb)
    }
}

impl Executable for CreateCommand {
    fn execute(&self) -> anyhow::Result<()> {
        let file_path = Path::new(&self.path);
        if file_path.is_file() {
            return Err(anyhow!("Could not create database - file already exists!"));
        }
        let buf = read_password()?;
        println!("Password is {buf}");
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
