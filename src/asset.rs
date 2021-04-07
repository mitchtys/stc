use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../embed/"]
struct Asset;
