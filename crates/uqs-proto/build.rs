use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join("../../protos");

    let proto_files = [
        proto_root.join("securemessage.proto"),
        proto_root.join("securegcm.proto"),
        proto_root.join("ukey.proto"),
        proto_root.join("device_to_device_messages.proto"),
        proto_root.join("offline_wire_formats.proto"),
        proto_root.join("proto/sharing_enums.proto"),
        proto_root.join("wire_format.proto"),
        proto_root.join("value_set/valueset.proto"),
        proto_root.join("platform_sdk/v1/trace_context.proto"),
        proto_root.join("platform_sdk/v1/platform_channel.proto"),
        proto_root.join("platform_sdk/v1/platform_message.proto"),
        proto_root.join("platform_sdk/v1/manifest.proto"),
        proto_root.join("platform_sdk/v1/device_resource_manager.proto"),
        proto_root.join("side_channel/v1/main.proto"),
        proto_root.join("file_transfer/v1/transfer_info.proto"),
        proto_root.join("fre/v1/proximal_onboarding_message.proto"),
    ];

    for p in &proto_files {
        println!("cargo:rerun-if-changed={}", p.display());
    }

    let fds = protox::compile(&proto_files, [&proto_root])?;
    let mut config = prost_build::Config::new();
    config.compile_fds(fds)?;
    Ok(())
}
