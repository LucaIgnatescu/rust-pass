mod parsing;
mod protos;

use clap::Parser;
use parsing::{Commands, MainParser};

fn main() {
    let parser = MainParser::parse();

    match parser.command {
        Commands::Create { name, path } => {
            println!("Opening {} {}", name, path)
        }
        Commands::Open { file_path } => {
            println!("File path {}", file_path)
        }
        Commands::Config => println!("Config"),
    }
}
