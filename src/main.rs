mod commands;
mod parsing;
mod protos;

use clap::Parser;
use commands::command_factory;
use parsing::MainParser;

fn main() {
    let parser = MainParser::parse();
    command_factory(parser.command).execute();
}
