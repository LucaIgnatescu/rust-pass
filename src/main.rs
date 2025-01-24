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
    let parser = MainParser::parse();
    command_factory(parser.command)
        .execute()
        .unwrap_or_else(|e| {
            display_error(e);
        })
}
