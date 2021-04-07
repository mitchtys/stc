extern crate serde;
extern crate serde_yaml;

use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<(), anyhow::Error> {
    let config_dir = dirs_next::config_dir().context(
        "couldnt figure out where the config dir should be on this platform, likely a bug",
    )?;
    let cache_dir = dirs_next::cache_dir().context(
        "couldnt figure out where the cache dir should be on this platform, likely a bug",
    )?;
    let config = std::path::Path::new(&config_dir).join(clap::crate_name!());
    let cache = std::path::Path::new(&cache_dir).join(clap::crate_name!());

    let mut settings = config::Config::default();
    if let Ok(s) = settings.merge(config::File::with_name("config")) {
        settings = s.clone();
    }
    if let Ok(s) = settings.merge(config::Environment::with_prefix("STC")) {
        settings = s.clone();
    }

    let target_triple = env!("VERGEN_TARGET_TRIPLE");
    let build_timestamp = env!("VERGEN_BUILD_TIMESTAMP");
    let short_sha = env!("VERGEN_SHA_SHORT");

    let stc_version_verbose = format!(
        "{} arch {} built on {} commit {}\n",
        concat!("version ", clap::crate_version!()),
        target_triple,
        build_timestamp,
        &short_sha
    );

    let cli = clap::App::new(clap::crate_name!())
        .version(concat!(clap::crate_version!(), "\n"))
        .long_version(&stc_version_verbose[..])
        .setting(clap::AppSettings::TrailingVarArg)
        .setting(clap::AppSettings::UnifiedHelpMessage)
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .about("Standard Template Constructor")
        .subcommand(clap::SubCommand::with_name("config").about(
            "dump out configuration file settings/information (at best useful for debugging)",
        ))
        .subcommand(
            clap::SubCommand::with_name("cache").about("cache a vm setup (not fully functional)"),
        )
        .subcommand(
            clap::SubCommand::with_name("apply")
                .about("apply a vm setup")
                .arg(
                    clap::Arg::with_name("file")
                        .short("f")
                        .long("file")
                        .required(true)
                        .takes_value(true)
                        .help("config file to use"),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("delete")
                .about("delete a vm setup")
                .arg(
                    clap::Arg::with_name("file")
                        .short("f")
                        .long("file")
                        .required(true)
                        .takes_value(true)
                        .help("config file to use"),
                ),
        );

    let cmd = cli.get_matches();

    if let Some(_matches) = cmd.subcommand_matches("config") {
        dbg!(settings);
        dbg!(config);
        dbg!(cache);
    } else if let Some(matches) = cmd.subcommand_matches("apply") {
        let user_config = load_config(matches.value_of("file"))?;

        // TODO: Need to get rid of these hard coded hacks for getting
        // binaries/etc... but thats for future me to fix, sorry future me past
        // me is a jerk
        tf_bin(cache.clone())?;
        packer_bin(cache.clone())?;

        let packer_image = packer_image(
            "a string that will eventually have useful data".to_string(),
            "packer_cache/build/opensuse-leap-15.2-x86_64.qcow2".to_string(),
            cache.clone(),
        )?;

        let tf_dir = embed_asset(
            "embed.tgz".to_string(),
            short_sha.to_string(),
            cache.clone(),
        )?;

        stc::CacheEntry::new(
            stc::CacheSource::TerraformUp {
                cwd: tf_dir,
                image: packer_image,
                user_config,
            },
            None,
            cache,
            None,
        )
        .cache()?;

    // TODO: Caching of terraform init plugins, but how?
    //
    // Shitty thought: have a cache/plan switch that does everything *but*
    // terraform apply... then tar+gz the .terraform directory itself as
    // some sort of composite asset/file?
    //
    // Future me figure it out.
    //
    // if stc::tf_plugins_ok(stc::tf_plugin_lockfile()) {
    //     eprintln!("tf plugins ok");
    // } else {
    //     eprintln!("tf plugins nok");
    // }
    } else if let ("delete", _) = cmd.subcommand() {
        tf_bin(cache.clone())?;

        let tf_dir = embed_asset(
            "embed.tgz".to_string(),
            short_sha.to_string(),
            cache.clone(),
        )?;

        stc::CacheEntry::new(
            stc::CacheSource::TerraformDown { cwd: tf_dir },
            None,
            cache,
            None,
        )
        .cache()?;
    } else if let ("cache", _) = cmd.subcommand() {
        // TODO: have tf_bin and packer_bin return the pathbuf to their
        // respective binaries
        tf_bin(cache.clone())?;
        packer_bin(cache.clone())?;

        packer_image(
            "a string that will eventually have useful data".to_string(),
            "packer_cache/build/opensuse-leap-15.2-x86_64.qcow2".to_string(),
            cache.clone(),
        )?;

        embed_asset("embed.tgz".to_string(), short_sha.to_string(), cache)?;
    }

    Ok(())
}

fn packer_zip(cachedir: std::path::PathBuf) -> stc::CacheEntry {
    packer_zip_prime(
        "1.7.0".to_string(),
        "935e81c07381a964bdbaddde2d890c91d52e88b9e5375f3882840925f6a96893".to_string(),
        cachedir,
    )
}

fn tf_zip(cachedir: std::path::PathBuf) -> stc::CacheEntry {
    tf_zip_prime(
        "0.13.6".to_string(),
        "55f2db00b05675026be9c898bdd3e8230ff0c5c78dd12d743ca38032092abfc9".to_string(),
        cachedir,
    )
}

fn tf_zip_prime(
    version: std::string::String,
    sha: std::string::String,
    cachedir: std::path::PathBuf,
) -> stc::CacheEntry {
    let tf = &format!("terraform_{}_{}.zip", version, stc::go_platform());
    let uri = &format!(
        "https://releases.hashicorp.com/terraform/{}/{}",
        version, tf
    )[..];

    stc::CacheEntry::new(
        stc::CacheSource::Uri(uri.to_string()),
        Some(tf.to_string()),
        cachedir,
        Some(sha),
    )
}

fn tf_bin(cachedir: std::path::PathBuf) -> anyhow::Result<std::path::PathBuf> {
    Ok(stc::CacheEntry::new(
        stc::CacheSource::CompressedFile {
            file: tf_zip(cachedir.clone()).cache()?,
            dir: "bin".to_string(),
        },
        Some("bin/terraform".to_string()),
        cachedir,
        Some("432c69434a8f093e02891a2a9e9c43558c233343972d03b3809bf6fd9a6f9659".to_string()),
    )
    .cache()?)
}

fn packer_zip_prime(
    version: std::string::String,
    sha: std::string::String,
    cachedir: std::path::PathBuf,
) -> stc::CacheEntry {
    let packer = &format!("packer_{}_{}.zip", version, stc::go_platform());
    let uri: &str = &format!(
        "https://releases.hashicorp.com/packer/{}/{}",
        version, packer
    )[..];

    stc::CacheEntry::new(
        stc::CacheSource::Uri(uri.to_string()),
        Some(packer.to_string()),
        cachedir,
        Some(sha),
    )
}

fn packer_bin(cachedir: std::path::PathBuf) -> anyhow::Result<std::path::PathBuf> {
    Ok(stc::CacheEntry::new(
        stc::CacheSource::CompressedFile {
            file: packer_zip(cachedir.clone()).cache()?,
            dir: "bin".to_string(),
        },
        Some("bin/packer".to_string()),
        cachedir,
        Some("eaf2506aeda6d934d7121638026b768a312798420e0545e2103004d3159e1f4a".to_string()),
    )
    .cache()?)
}

fn bento_zip(cachedir: std::path::PathBuf) -> stc::CacheEntry {
    stc::CacheEntry::new(
        stc::CacheSource::Uri(
            "https://github.com/mitchtys/bento/archive/refs/heads/master.zip".to_string(),
        ),
        Some("bento-master.zip".to_string()),
        cachedir,
        Some("9cda61467b9a006f29abfa47024981eef8f2fc00009b91072741ccb71f7a3471".to_string()),
    )
}

fn bento_dir(cachedir: std::path::PathBuf) -> anyhow::Result<std::path::PathBuf> {
    let bento_zip = bento_zip(cachedir.clone()).cache()?;
    let mut bento_dir = stc::CacheEntry::new(
        stc::CacheSource::CompressedFile {
            file: bento_zip,
            dir: "bento".to_string(),
        },
        None,
        cachedir,
        None,
    )
    .cache()?;
    bento_dir.push("bento-master");
    Ok(bento_dir)
}

fn packer_image(
    content: std::string::String,
    image: std::string::String,
    cachedir: std::path::PathBuf,
) -> anyhow::Result<std::path::PathBuf> {
    Ok(stc::CacheEntry::new(
        stc::CacheSource::PackerBuildImage {
            cwd: bento_dir(cachedir.clone())?,
            content: content.clone(),
            image,
        },
        Some(format!("{}.qcow2", stc::sha256_string(content))),
        cachedir,
        None,
    )
    .cache()?)
}

fn embed_asset(
    source: std::string::String,
    commit: std::string::String,
    cachedir: std::path::PathBuf,
) -> anyhow::Result<std::path::PathBuf> {
    let asset =
        stc::Asset::get(&source).ok_or(anyhow::anyhow!(format!("no asset {} found", source)))?;
    let reader = std::io::BufReader::new(asset.as_ref());
    let digest = stc::sha256_digest(reader)?;

    let tf_sha = format!("tf-{}", &commit);
    let mut tf_dir = cachedir.clone();
    tf_dir.push(&tf_sha);

    let _embed_tgz = stc::CacheEntry::new(
        stc::CacheSource::Asset {
            name: source,
            dir: tf_sha,
        },
        Some(format!("embed-{}.tgz", commit)),
        cachedir,
        Some(data_encoding::HEXLOWER.encode(digest.as_ref())),
    )
    .cache()?;
    Ok(tf_dir)
}

fn load_config(config: Option<&str>) -> anyhow::Result<stc::UserConfig> {
    if let Some(file) = config {
        // TODO: some .ends_with() maybe on the file name to know if we
        // should load a yaml file or json i suppose
        let contents = std::fs::read_to_string(file).with_context(|| format!("std::fs::read_to_string() failed on user input {}, does this file exist and is it readable by the current user?", &file))?;

        Ok(serde_yaml::from_str::<stc::UserConfig>(&contents)?)
    } else {
        Err(anyhow::anyhow!("should be impossible to get here"))
    }
}
