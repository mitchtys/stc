use anyhow::Context;

fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
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

fn main() -> anyhow::Result<(), anyhow::Error> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=tf");

    // Throw the embed dir into the $OUT_DIR folder that cargo builds so ci
    // works.
    let out_dir = "OUT_DIR";

    let embed_dir = match std::env::var(out_dir) {
        Ok(s) => format!("{}/embed", s),
        _ => return Err(anyhow::anyhow!("OUT_DIR isn't set in build.rs?")),
    };

    let mut config = vergen::Config::default();

    *config.build_mut().kind_mut() = vergen::TimestampKind::All;
    *config.build_mut().timezone_mut() = vergen::TimeZone::Local;
    *config.git_mut().sha_kind_mut() = vergen::ShaKind::Short;
    *config.git_mut().semver_kind_mut() = vergen::SemverKind::Normal;
    *config.git_mut().semver_dirty_mut() = Some("-dirty");

    vergen::vergen(config).expect("Unable to generate cargo build environment values");

    if !std::path::Path::new(&embed_dir).exists() {
        if let Err(err) = std::fs::create_dir(&embed_dir) {
            dbg!(err);
            eprintln!("std::fs::create_dir({}) failed, oh well", embed_dir);
        }
    }

    let tgz = std::fs::File::create(format!("{}/embed.tgz", embed_dir))
        .with_context(|| format!("std::fs::File::create({}) failed", embed_dir))?;
    let enc = flate2::write::GzEncoder::new(tgz, flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);

    let walker = walkdir::WalkDir::new("tf").into_iter();
    for thing in walker
        .filter_entry(|e| !is_hidden(e) && (is_dir(e) || is_tf(e) || is_shell(e)))
        .flatten()
    {
        // If only one could do multiple if let Ok()'s in a single conditional...
        eprintln!("{}", thing.path().display());
        if let Ok(relpath) = thing.path().strip_prefix("tf/") {
            if let Some(s) = relpath.to_str() {
                if !s.is_empty() {
                    tar.append_path_with_name(thing.path(), relpath)
                        .with_context(|| format!("appending {:?} to tar failed", &s))?;
                }
            }
        }
    }

    tar.finish().context("tar.finish() failed?")?;

    Ok(())
}
