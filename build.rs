fn main() {
    println!("cargo:rerun-if-changed=assets/rdesk.rc");
    println!("cargo:rerun-if-changed=assets/rdesk.ico");
    println!("cargo:rerun-if-changed=assets/rdesk.manifest");
    embed_resource::compile("assets/rdesk.rc", embed_resource::NONE)
        .manifest_required()
        .expect("cannot embed the icon and manifest");
}
