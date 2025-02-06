use crate::{
    commands::{DirectoryManager, Executable, VaultManager},
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

fn repl(mut vm: VaultManager) {
    let mut running = false;
    let mut dm: Option<DirectoryManager> = None;
    while running {
        let buf = InputReader::read_command().unwrap(); // FIX: don't use unwrap
        let contents: Vec<&str> = buf.split_whitespace().collect();
        let command = ReplCommandType::parse(&contents).unwrap();
        command.execute(&mut vm, &mut dm, &mut running).unwrap();
    }
}

trait ReplCommand: Sized {
    fn parse(args: &[&str]) -> Result<Self>;
    fn execute(
        &self,
        vm: &mut VaultManager,
        dm: &mut Option<DirectoryManager>,
        running: &mut bool,
    ) -> Result<()>;
}

macro_rules! help {
    () => {
        anyhow!("Incorrect usage of command. Try running help.")
    };
}

struct LSCommand;

impl ReplCommand for LSCommand {
    fn execute(
        &self,
        vm: &mut VaultManager,
        dm: &mut Option<DirectoryManager>,
        running: &mut bool,
    ) -> Result<()> {
        //let directories = match repl.curr_dir {
        //    None => repl.vm.get_directories(),
        //    Some(dir) => {}
        //}
        //
        Ok(())
    }

    fn parse(args: &[&str]) -> Result<Self> {
        const NARGS: usize = 0;
        if args.len() != NARGS {
            return Err(help!());
        }
        Ok(Self)
    }
}

struct MKDirCommand {
    dir_name: String,
}

impl MKDirCommand {
    fn validate_dir_name(dir_name: &str) -> Result<&str> {
        if !dir_name.chars().all(|c| c.is_alphanumeric()) {
            return Err(anyhow!(
                "Directory name must only consist of alphanumeric characters"
            ));
        }

        if dir_name
            .chars()
            .next()
            .ok_or_else(|| anyhow!("Directory name cannot be empty"))?
            .is_numeric()
        {
            return Err(anyhow!("Directory name cannot start with a number"));
        }

        Ok(dir_name)
    }
}

impl ReplCommand for MKDirCommand {
    fn execute(
        &self,
        vm: &mut VaultManager,
        dm: &mut Option<DirectoryManager>,
        running: &mut bool,
    ) -> Result<()> {
        unimplemented!()
    }
    fn parse(args: &[&str]) -> Result<Self> {
        const NARGS: usize = 2;
        if args.len() != NARGS {
            return Err(help!());
        }
        let dir_name = Self::validate_dir_name(args[0])?;

        Ok(Self {
            dir_name: dir_name.to_string(),
        })
    }
}

struct GetCommand {
    key_name: String,
}

impl ReplCommand for GetCommand {
    fn execute(
        &self,
        vm: &mut VaultManager,
        dm: &mut Option<DirectoryManager>,
        running: &mut bool,
    ) -> Result<()> {
        unimplemented!()
    }
    fn parse(args: &[&str]) -> Result<Self> {
        const NARGS: usize = 1;

        if args.len() != NARGS {
            return Err(help!());
        }

        Ok(Self {
            key_name: args[0].to_string(),
        })
    }
}

struct AddCommand {
    key_name: String,
}

impl ReplCommand for AddCommand {
    fn execute(
        &self,
        vm: &mut VaultManager,
        dm: &mut Option<DirectoryManager>,
        running: &mut bool,
    ) -> Result<()> {
        unimplemented!()
    }
    fn parse(args: &[&str]) -> Result<Self> {
        const NARGS: usize = 1;

        if args.len() != NARGS {
            return Err(help!());
        }

        Ok(Self {
            key_name: args[0].to_string(),
        })
    }
}

struct ExitCommand;

impl ReplCommand for ExitCommand {
    fn execute(
        &self,
        vm: &mut VaultManager,
        dm: &mut Option<DirectoryManager>,
        running: &mut bool,
    ) -> Result<()> {
        unimplemented!()
    }
    fn parse(args: &[&str]) -> Result<Self> {
        const NARGS: usize = 0;

        if args.len() != NARGS {
            return Err(help!());
        }

        Ok(Self {})
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
        fn $method(&self, $($arg: $arg_type,)*) -> $ret_type{
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
    delegate!(self, execute, vm: &mut VaultManager, dm: &mut Option<DirectoryManager>, running: &mut bool => Result<()>);

    fn parse(args: &[&str]) -> Result<Self> {
        if args.is_empty() {
            return Err(anyhow!("No command provided"));
        }

        Ok(match args[0] {
            "ls" => Self::LS(LSCommand::parse(&args[1..])?),
            "mkdir" => Self::MKDIR(MKDirCommand::parse(&args[1..])?),
            "get" => Self::GET(GetCommand::parse(&args[1..])?),
            "add" => Self::ADD(AddCommand::parse(&args[1..])?),
            "exit" => Self::EXIT(ExitCommand::parse(&args[1..])?),
            _ => return Err(anyhow!("Invalid command")),
        })
    }
}
