use crate::config::ConfigCommand;
use crate::create::CreateCommand;
use crate::open::OpenCommand;
use crate::parsing::Commands;

pub trait Executable {
    fn execute(&self) -> anyhow::Result<()> {
        println!("Executing...");
        Ok(())
    }
}

pub fn command_factory(command: Commands) -> Box<dyn Executable> {
    match command {
        Commands::Create { name, path } => Box::new(CreateCommand::new(name, path)),
        Commands::Open { file_path } => Box::new(OpenCommand::new(file_path)),
        Commands::Config => Box::new(ConfigCommand::new()),
    }
}
