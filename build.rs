fn main() {
    println!("cargo:rerun-if-changed=assets/rdesk.rc");
    println!("cargo:rerun-if-changed=assets/rdesk.ico");
    println!("cargo:rerun-if-changed=assets/rdesk.manifest");
    embed_resource::compile("assets/rdesk.rc", embed_resource::NONE)
        .manifest_required()
        .expect("cannot embed the icon and manifest");

    // Fluent is the Windows 11 look; it has light and dark variants.
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/app.slint", config).expect("cannot compile the interface");
}
