mod commands;
mod display;
mod parsing;
mod protos;

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
