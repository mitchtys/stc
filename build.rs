fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with("."))
        .unwrap_or(false)
}

fn is_tf(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.ends_with(".template") || s.ends_with(".tf"))
        .unwrap_or(false)
}

fn is_dir(entry: &walkdir::DirEntry) -> bool {
    entry.file_type().is_dir()
}

fn is_shell(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.ends_with(".sh"))
        .unwrap_or(false)
}

fn main() -> Result<(), std::io::Error> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=tf");
    println!("cargo:rerun-if-changed=embed");
    vergen::generate_cargo_keys(vergen::ConstantsFlags::all())
        .expect("Unable to generate cargo build env keys!");

    let _rmdir = std::fs::remove_dir_all("embed")?;
    let _whatever = std::fs::create_dir("embed")?;
    let tgz = std::fs::File::create("embed/embed.tgz")?;
    let enc = flate2::write::GzEncoder::new(tgz, flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);

    let walker = walkdir::WalkDir::new("tf").into_iter();
    for entry in walker.filter_entry(|e| !is_hidden(e) && (is_dir(e) || is_tf(e) || is_shell(e))) {
        // If only one could do multiple if let Ok()'s in a single conditional...
        if let Ok(thing) = entry {
            eprintln!("{}", thing.path().display());
            if let Ok(relpath) = thing.path().strip_prefix("tf/") {
                if let Some(s) = relpath.to_str() {
                    if s != "" {
                        tar.append_path_with_name(thing.path(), relpath)?;
                    }
                }
            }
        }
    }

    tar.finish()?;

    Ok(())
}
