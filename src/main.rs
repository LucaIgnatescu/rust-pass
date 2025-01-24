mod parsing;
mod protos;

use clap::Parser;
use parsing::RustPass;

fn main() {
    let parser = RustPass::parse();
}
