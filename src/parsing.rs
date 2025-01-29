use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "RustPass")]
#[command(about = "A rust-based password manager.", long_about = None)]
pub struct MainParser {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Create {
        #[arg(short, long)]
        name: String,

        #[arg(short, long, default_value = ".")]
        dir: String,
    },
    Open {
        #[arg(value_name = "PATH_TO_FILE")]
        file_path: String,
    },
    Config,
}
