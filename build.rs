fn main() {
    protobuf_codegen::Codegen::new()
        .cargo_out_dir("protos")
        .include("src/protos")
        .input("src/protos/header.proto")
        .input("src/protos/rpdb.proto")
        .input("src/protos/config.proto")
        .run_from_script();
}
