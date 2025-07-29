fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(
            &[
                "proto/authly/connect.proto",
                "proto/authly/mandate_submission.proto",
                "proto/authly/service.proto",
            ],
            &["proto/"],
        )?;

    println!("cargo:rerun-if-changed=build.rs");

    Ok(())
}
