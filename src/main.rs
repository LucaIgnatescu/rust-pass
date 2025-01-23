mod protos;

use protobuf::Message;
use protos::example::Example;

fn main() {
    let mut example = Example::new();
    example.set_name(String::from("cheg"));
    example.set_id(32);

    let serialized = example.write_to_bytes().unwrap();
    println!("{:?}", serialized);

    let deserialized = Example::parse_from_bytes(&serialized).unwrap();
    println!("{:?}", deserialized);
}
