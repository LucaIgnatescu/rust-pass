use crate::parsing::Commands;

mod config;
mod create;
mod open;

pub trait Executable {
    fn execute(&self) {
        println!("Executing...");
    }
}

pub fn command_factory(command: Commands) -> Box<dyn Executable> {
    match command {
        Commands::Create { name, path } => Box::new(create::CreateCommand::new(name, path)),
        Commands::Open { file_path } => Box::new(open::OpenCommand::new(file_path)),
        Commands::Config => Box::new(config::ConfigCommand::new()),
    }
}
