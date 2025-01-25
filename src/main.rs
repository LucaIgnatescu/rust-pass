mod commands;
mod config;
mod create;
mod display;
mod open;
mod parsing;
mod protos;
mod rng;

use clap::Parser;
use commands::command_factory;
use display::display_error;
use parsing::MainParser;

fn main() {
    let mut config = config::LocalConfig::new();
    println!("Init from file...");
    config.init_from_file().unwrap_or_else(|e| display_error(e));
    println!("Saving...");
    config.save().unwrap_or_else(|e| display_error(e));
    println!("Ran and saved \n\n\n");
    //let parser = MainParser::parse();
    //command_factory(parser.command)
    //    .execute()
    //    .unwrap_or_else(|e| {
    //        display_error(e);
    //    })
}
