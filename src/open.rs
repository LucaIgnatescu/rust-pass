use crate::{
    commands::{Executable, VaultManager},
    display::InputReader,
};
use anyhow::{anyhow, Result};
use std::{path::PathBuf, str::FromStr};

pub struct OpenCommand {
    file_path: String,
}

impl OpenCommand {
    pub fn new(file_path: String) -> Self {
        Self { file_path }
    }
}

impl Executable for OpenCommand {
    fn execute(&self) -> Result<()> {
        let path = PathBuf::from_str(&self.file_path)?.canonicalize()?;
        if !path.is_file() {
            return Err(anyhow!("Path does point to an .rpdb file"));
        }
        let mut vm = VaultManager::default();
        let master = InputReader::read_password()?;
        vm.initialize_from_file(path, master)?;
        Ok(())
    }
}

trait ReplCommand: Sized {
    fn parse(args: &[&str]) -> Result<Self>;
    fn execute(&self, state: &mut ReplState) -> Result<()>;
    fn help(&self);
}

struct LSCommand;

impl ReplCommand for LSCommand {
    fn execute(&self, state: &mut ReplState) -> Result<()> {
        unimplemented!()
    }
    fn help(&self) -> () {
        unimplemented!()
    }
    fn parse(args: &[&str]) -> Result<Self> {
        unimplemented!()
    }
}

struct MKDirCommand {
    dir_name: String,
}

impl ReplCommand for MKDirCommand {
    fn execute(&self, state: &mut ReplState) -> Result<()> {
        unimplemented!()
    }
    fn help(&self) -> () {
        unimplemented!()
    }
    fn parse(args: &[&str]) -> Result<Self> {
        unimplemented!()
    }
}

struct GetCommand {
    key_name: String,
}

impl ReplCommand for GetCommand {
    fn execute(&self, state: &mut ReplState) -> Result<()> {
        unimplemented!()
    }
    fn help(&self) -> () {
        unimplemented!()
    }
    fn parse(args: &[&str]) -> Result<Self> {
        unimplemented!()
    }
}

struct AddCommand {
    key_name: String,
}

impl ReplCommand for AddCommand {
    fn execute(&self, state: &mut ReplState) -> Result<()> {
        unimplemented!()
    }
    fn help(&self) -> () {
        unimplemented!()
    }
    fn parse(args: &[&str]) -> Result<Self> {
        unimplemented!()
    }
}

struct ExitCommand;

impl ReplCommand for ExitCommand {
    fn execute(&self, state: &mut ReplState) -> Result<()> {
        unimplemented!()
    }
    fn help(&self) -> () {
        unimplemented!()
    }
    fn parse(args: &[&str]) -> Result<Self> {
        unimplemented!()
    }
}

enum ReplCommandType {
    LS(LSCommand),
    MKDIR(MKDirCommand),
    GET(GetCommand),
    ADD(AddCommand),
    EXIT(ExitCommand),
}

macro_rules! delegate {
    (self, $method: ident, $($arg:ident : $arg_type:ty),* => $ret_type:ty) => {
        fn $method(&self, $($arg: $arg_type)*) -> $ret_type{
            match self{
                ReplCommandType::LS(cmd) => cmd.$method($($arg), *),
                ReplCommandType::MKDIR(cmd) => cmd.$method($($arg), *),
                ReplCommandType::GET(cmd) => cmd.$method($($arg), *),
                ReplCommandType::ADD(cmd) => cmd.$method($($arg), *),
                ReplCommandType::EXIT(cmd) => cmd.$method($($arg), *),
            }
        }
    };
}

impl ReplCommand for ReplCommandType {
    delegate!(self, execute, state: &mut ReplState => Result<()>);
    delegate!(self, help, => ());

    fn parse(args: &[&str]) -> Result<Self> {
        if args.is_empty() {
            return Err(anyhow!("No command provided"));
        }

        Ok(match args[0] {
            "ls" => Self::LS(LSCommand::parse(args)?),
            "mkdir" => Self::MKDIR(MKDirCommand::parse(args)?),
            "get" => Self::GET(GetCommand::parse(args)?),
            "add" => Self::ADD(AddCommand::parse(args)?),
            "exit" => Self::EXIT(ExitCommand::parse(args)?),
            _ => return Err(anyhow!("Invalid command")),
        })
    }
}

#[derive(Default)]
struct ReplState {
    running: bool,
}

struct Repl {
    vm: VaultManager,
    state: ReplState,
}

impl Repl {
    pub fn new(vm: VaultManager) -> Self {
        Self {
            vm,
            state: ReplState::default(),
        }
    }

    pub fn start(&mut self) {
        self.state.running = true;
        while self.state.running {
            let buf = InputReader::read_command().unwrap();
            let contents: Vec<&str> = buf.split_whitespace().collect();
            let command = ReplCommandType::parse(&contents).unwrap();
            command.execute(&mut self.state).unwrap();
        }
    }
}
