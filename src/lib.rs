// Tests are up top as they should be to show how some of this is used.
#[cfg(test)]
mod tests {
    use super::*;

    // Add any other silly differences here. aarch64 is here mostly to catch the
    // default case, never tested on that arch
    #[test]
    fn test_go_platform_prime() {
        assert_eq!(
            "linux_amd64",
            go_platform_prime("linux".to_string(), "x86_64".to_string())
        );
        assert_eq!(
            "linux_aarch64",
            go_platform_prime("linux".to_string(), "aarch64".to_string())
        );
    }
}

// Split this apart in near future.
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "embed/"]
pub struct Asset;

use anyhow::Context;
use serde_json::error::Error as SerdeJsonError;

// use std::borrow::Borrow;
// use std::hash::Hash;
// use std::collections::HashMap;

// pub trait AllKeys<K: Hash + Eq> {
//     fn all<Q: ?Sized>(&self, keys: &[&Q]) -> bool
//         where K: Borrow<Q>,
//               Q: Hash + Eq + Ord;
// }

// impl<V, K: Hash + Eq> AllKeys<K> for HashMap<K, V> {
//     fn all<Q: ?Sized>(&self, all_keys: &[&Q]) -> bool
//         where K: Borrow<Q>,
//               Q: Hash + Eq + Ord
//     {
//         all_keys.iter().all(|key| self.all(key))
//     }
// }

pub fn tf_plugins_installed(
    path: std::path::PathBuf,
) -> Result<std::collections::HashMap<String, String>, SerdeJsonError> {
    let s = std::fs::read_to_string(path).unwrap();
    let cfg: std::collections::HashMap<String, String> = serde_json::from_str(&s)?;
    Ok(cfg)
}

// For now just see if all the keys are there, this a stub anyway atm
pub fn tf_plugins_ok(path: std::path::PathBuf) -> bool {
    if let Ok(plugins) = tf_plugins_installed(path) {
        let all = vec!["random", "libvirt", "null", "tls", "template", "local"];
        let mut found: usize = 0;
        for x in &all {
            if plugins.iter().any(|(i, _)| i.clone() == x.to_string()) {
                found += 1;
            }
        }
        return found == all.len();
    }
    false
}

pub fn tf_plugin_lockfile() -> std::path::PathBuf {
    std::path::PathBuf::from(format!(".terraform/plugins/{}/lock.json", go_platform()))
}

// go stuff records x86_64 as amd64, which is lame but whatever mimic it so we
// can find what plugins are installed in .terraform.
// we'll only care about linux/windows/macos here most likely...
// https://doc.rust-lang.org/std/env/consts/constant.OS.html
// https://doc.rust-lang.org/std/env/consts/constant.ARCH.html
pub fn go_platform() -> String {
    go_platform_prime(
        std::env::consts::OS.to_string(),
        std::env::consts::ARCH.to_string(),
    )
}

pub fn go_platform_prime(os: String, arch: String) -> String {
    if arch == "x86_64" {
        format!("{}_amd64", os)
    } else {
        format!("{}_{}", os, arch)
    }
}

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_yaml;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Provider {
    // TODO: future
    //    Vsphere,
    #[serde(rename = "libvirt")]
    Libvirt,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    // For now whatever will be fine
    #[serde(rename = "apiVersion")]
    api_version: String,

    #[serde(rename = "provider")]
    provider: Provider,

    // TODO: need to figure out a way to deal with mapping more than just yaml
    // values, but later task for future me
    #[serde(rename = "terraformVars")]
    #[serde(flatten)]
    vars: std::collections::HashMap<String, serde_yaml::Value>,
}

#[derive(Debug)]
pub enum CacheSource {
    File(std::path::PathBuf),
    Uri(std::string::String),
    Asset {
        name: std::string::String,
        dir: std::string::String,
    },
    CompressedFile {
        file: std::path::PathBuf,
        dir: std::string::String,
    },
    PackerBuildImage {
        cwd: std::path::PathBuf,
        content: std::string::String,
        image: std::string::String,
    },
    TerraformUp {
        cwd: std::path::PathBuf,
        image: std::path::PathBuf,
        user_config: UserConfig,
    },
    TerraformDown {
        cwd: std::path::PathBuf,
    },
}

// Quick hack struct to describe a type of cached item/file.
#[derive(Debug)]
pub struct CacheEntry {
    pub tag: Option<String>,
    pub source: CacheSource,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub name: Option<String>,
    cachedir: std::path::PathBuf,
}

impl CacheEntry {
    pub fn new(
        source: CacheSource,
        name: Option<String>,
        cachedir: std::path::PathBuf,
        sha256: Option<String>,
    ) -> Self {
        Self {
            tag: None,
            cachedir: cachedir,
            source: source,
            sha256: sha256,
            size: None,
            name: name,
        }
    }

    // Once I get cache() sorted and start saving data on what is downloaded,
    // this should "do stuff"
    pub fn check(&self) -> anyhow::Result<bool> {
        match &self.source {
            CacheSource::PackerBuildImage {
                cwd: _,
                content,
                image: _,
            } => {
                let shasum = sha256_string(content.to_string());
                let mut image = self.cachedir.clone();
                image.push(format!("{}.qcow2", shasum));

                if image.exists() {
                    return Ok(true);
                }
            }
            // For now assets are always fine, we write them out unconditionally
            // anyway.
            CacheSource::Asset { name: _, dir: _ } => {
                return Ok(false);
            }
            _ => {
                if let Some(validate) = self.sha256.clone() {
                    let mut fname = std::path::PathBuf::from(self.cachedir.clone());

                    if let Some(name) = &self.name {
                        fname.push(name.clone());
                    }

                    if fname.is_file() {
                        if let Ok(file) = std::fs::File::open(&fname.clone()) {
                            let reader = std::io::BufReader::new(file);
                            if let Ok(digest) = sha256_digest(reader) {
                                let sha = data_encoding::HEXLOWER.encode(digest.as_ref());
                                if sha == validate {
                                    return Ok(true);
                                } else {
                                    return Err(anyhow::anyhow!(format!(
                                        "sha mismatch for {:?} expected: {} found: {}",
                                        fname, validate, sha
                                    )));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    // For now this does "too much", I have it extracting the zip file etc...
    //
    // Should really make a Composite Remote or something type that encompasses
    // "do stuff on a thing we downloaded"
    pub fn cache(&mut self) -> anyhow::Result<std::path::PathBuf> {
        let mut fname = std::path::PathBuf::from(self.cachedir.clone());
        if let Some(name) = &self.name {
            fname.push(name.clone());
        }

        if !self.cachedir.exists() {
            std::fs::create_dir_all(&self.cachedir)
                .with_context(|| format!("std::fs::create_dir_all on :{:?}", &self.cachedir))?;
        }

        let check = self
            .check()
            .with_context(|| format!("cache file check() failed, refusing to continue"))?;

        if check {
            return Ok(fname.clone());
        }

        return match &self.source {
            CacheSource::Uri(uri) => {
                let response = ureq::get(&uri)
                    .timeout_connect(15_000)
                    .timeout_read(15_000)
                    .call();

                if response.synthetic() {
                    let error = response.into_synthetic_error().unwrap();
                    return Err(error.into());
                }

                if response.error() {
                    anyhow::bail!("Received status code {}", response.status());
                }

                let content_length = if let Some(content_length) = response.header("Content-Length")
                {
                    if let Ok(parsed) = content_length.parse::<u64>() {
                        self.size = Some(parsed);
                        parsed
                    } else {
                        0
                    }
                } else {
                    0
                };

                let progress_bar = indicatif::ProgressBar::new(content_length);
                if content_length > 0 {
                    progress_bar.set_style(indicatif::ProgressStyle::default_bar().template(
                        concat!(
                            "{elapsed_precise} {percent}% [{bar:20.cyan/red}] ",
                            "{binary_bytes}/{binary_total_bytes} ",
                            "{bytes_per_sec} {eta} left" // TODO: Why does binary_bytes_per_sec not render?
                        ),
                    ));
                } else {
                    progress_bar.set_style(indicatif::ProgressStyle::default_bar().template(
                        concat!(
                            "{elapsed_precise} {percent}% [{bar:20.cyan/red}] ",
                            "{binary_bytes} ",
                            "{bytes_per_sec} ? time left"
                        ),
                    ));
                }
                progress_bar.tick();
                progress_bar.enable_steady_tick(250);

                let mut reader = ReaderWithProgress {
                    inner: response.into_reader(),
                    progress_bar: progress_bar.clone(),
                };

                // The actual copy to fs with progress bar
                let mut file = std::fs::File::create(&fname).with_context(|| {
                    format!("std::fs::File::create() failed with file: {:?}", &fname)
                })?;
                std::io::copy(&mut reader, &mut file).with_context(|| {
                    format!("std::io::copy() failed copying data to {:?}", &file)
                })?;

                progress_bar.finish_and_clear();
                return Ok(fname.clone());
            }

            CacheSource::CompressedFile { file, dir } => {
                let zip = std::fs::File::open(file.clone()).with_context(|| {
                    format!("std::fs::File::open() failed with file: {:?}", &file)
                })?;
                let mut archive = zip::ZipArchive::new(zip).with_context(|| {
                    format!("zip::ZipArchive::new() on file: {:?} failed", &file)
                })?;

                let mut outdir = std::path::PathBuf::from(self.cachedir.clone());
                outdir.push(dir);

                if !outdir.exists() {
                    std::fs::create_dir_all(&outdir)
                        .with_context(|| format!("std::fs::create_dir_all on :{:?}", &outdir))?;
                }

                for i in 0..archive.len() {
                    let mut afile = archive.by_index(i).with_context(|| {
                        format!("zip archive.by_index() failed for index: {}", i)
                    })?;
                    let out = match afile.enclosed_name() {
                        Some(path) => path.to_owned(),
                        None => continue,
                    };

                    if let Some(path) = out.parent() {
                        let mut dname = outdir.clone();
                        dname.push(path);

                        if !dname.exists() {
                            std::fs::create_dir_all(&dname).with_context(|| {
                                format!("std::fs::create_dir_all on :{:?}", &dname)
                            })?;
                        }

                        // How does windows do this stuff? Future me figure this out.
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;

                            if let Some(mode) = afile.unix_mode() {
                                std::fs::set_permissions(
                                    &dname,
                                    std::fs::Permissions::from_mode(mode),
                                )
                                .with_context(|| {
                                    format!(
                                        "std::fs::set_permissions on :{:?} with mode {:?}",
                                        &dname,
                                        std::fs::Permissions::from_mode(mode)
                                    )
                                })?;
                            }
                        }

                        if afile.is_dir() {
                            continue;
                        }
                    }

                    let mut fname = outdir.clone();
                    fname.push(out.clone());

                    // Don't throw up a progress bar if the size is under 10MiB,
                    // no sense in spamming the tty
                    if afile.size() > (1024 * 1024 * 10) {
                        let extract_bar = indicatif::ProgressBar::new(afile.size());
                        extract_bar.set_style(indicatif::ProgressStyle::default_bar().template(
                            concat!(
                                "Extracting {msg} {percent}% [{bar:20.green/red}] ",
                                "{binary_bytes}/{binary_total_bytes} ",
                                "{bytes_per_sec} {eta} left"
                            ),
                        ));
                        extract_bar.tick();
                        extract_bar.enable_steady_tick(250);

                        if let Some(msg) = out.to_str() {
                            extract_bar.set_message(msg);
                        }

                        let outfile = std::fs::File::create(&fname)
                            .with_context(|| format!("std::fs::File::create() on: {:?}", &fname))?;

                        let mut writer = WriterWithProgress {
                            inner: &outfile,
                            progress_bar: extract_bar.clone(),
                        };

                        std::io::copy(&mut afile, &mut writer)
                            .with_context(|| format!("std::io::copy() to {:?}", &outfile))?;
                        extract_bar.finish_and_clear();
                    } else {
                        let mut outfile = std::fs::File::create(&fname)
                            .with_context(|| format!("std::fs::File::create() on: {:?}", &fname))?;
                        std::io::copy(&mut afile, &mut outfile)
                            .with_context(|| format!("std::io::copy() to {:?}", &outfile))?;
                    }

                    // How does windows do this stuff? Future me figure this out.
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;

                        if let Some(mode) = afile.unix_mode() {
                            std::fs::set_permissions(&fname, std::fs::Permissions::from_mode(mode))
                                .with_context(|| {
                                    format!(
                                        "std::fs::set_permissions on :{:?} with mode {:?}",
                                        &fname,
                                        std::fs::Permissions::from_mode(mode)
                                    )
                                })?;
                        }
                    }
                }
                return Ok(outdir);
            }
            CacheSource::PackerBuildImage {
                cwd,
                content,
                image,
            } => {
                let shasum = sha256_string(content.to_string());
                let mut dst = self.cachedir.clone();
                dst.push(format!("{}.qcow2", shasum));

                let mut src = cwd.clone();
                src.push(image);

                let mut packer = self.cachedir.clone();
                packer.push("bin");
                packer.push("packer");

                // TODO: let check work for this, it doesn't use the sha25sum of
                // the file but the inputs for the file that is built
                //
                // packer build --only=qemu -var 'build_directory=./packer_cache/build' bento/packer_templates/sles/sles-15-sp2.json
                let path =
                    std::env::var("PATH").context("std::env::var() failed for PATH, is it set?")?;
                if let Ok(dir) = self.cachedir.clone().into_os_string().into_string() {
                    let npath = format!("{}/bin:{}", dir, path);
                    std::env::set_var("PATH", npath);
                } else {
                    return Err(anyhow::anyhow!("couldn't convert cachedir to a string?"));
                }

                // TODO: check that packer exited 0, for now who cares
                let _packer = std::process::Command::new(&packer)
                    .args(&[
                        "build",
                        "--only=qemu",
                        "-force",
                        "-var",
                        "build_directory=./packer_cache/build",
                        "packer_templates/opensuse/opensuse-leap-15.2-x86_64.json",
                    ])
                    .current_dir(&cwd)
                    .status()
                    .with_context(|| format!("{:?} build ... cwd: {:?}", packer, cwd))?;
                std::fs::rename(&src, &dst)
                    .with_context(|| format!("std::fs::rename() {:?} to {:?}", src, &dst))?;
                Ok(dst.clone())
            }
            CacheSource::Asset { name, dir } => {
                let asset = Asset::get(name)
                    .ok_or(anyhow::anyhow!(format!("no asset {} found", name)))
                    .with_context(|| format!("Asset::get() name: {}", &name))?;
                if let Some(name) = &self.name {
                    use std::io::Write;
                    let mut asset_file = self.cachedir.clone();
                    asset_file.push(name);
                    let mut dst = self.cachedir.clone();
                    dst.push(dir);

                    let mut output = std::fs::File::create(&asset_file).with_context(|| {
                        format!("std::fs::File::create() failed with file: {:?}", &fname)
                    })?;
                    output
                        .write_all(asset.as_ref())
                        .with_context(|| format!("std::fs::File::write_all() to {:?}", &fname))?;

                    // TODO: Future problem/thoughts, here is where the rubber
                    // hits the road, I need to figure out the true order of
                    // operations here in a way that will make sense, what I
                    // *want* to do is nuke any existing dir entirely and
                    // extract fresh just to be sure we're kosher on disk, but
                    // if there has been a `terraform -apply` tfstate files
                    // inside, then thats a bad idea. For now punting on this
                    // for future me to fix.
                    std::fs::create_dir_all(&dst)
                        .with_context(|| format!("std::fs::create_dir_all on :{:?}", &dst))?;
                    let tgz = std::fs::File::open(&asset_file).with_context(|| {
                        format!("std::fs::File::open() failed with file: {:?}", &asset_file)
                    })?;
                    let tar = flate2::read::GzDecoder::new(&tgz);
                    let mut archive = tar::Archive::new(tar);
                    archive
                        .unpack(&dst)
                        .with_context(|| format!("tar::Archive::unpack() for {:?}", tgz))?;
                    let mut libvirt = dst.clone();
                    libvirt.push("providers");
                    libvirt.push("libvirt.tf");
                    let mut provider = dst.clone();
                    provider.push("provider.tf");

                    std::fs::copy(&libvirt, &provider).with_context(|| {
                        format!("std::fs::copy() {:?} to {:?} failed", libvirt, provider)
                    })?;
                    return Ok(dst.clone());
                }
                Err(anyhow::anyhow!(
                    "this branch should never have been taken, bug"
                ))
            }
            CacheSource::TerraformDown { cwd } => {
                let mut dir = self.cachedir.clone();
                dir.push(cwd);

                let mut tf = self.cachedir.clone();
                tf.push("bin");
                tf.push("terraform");

                let path =
                    std::env::var("PATH").context("std::env::var() failed for PATH, is it set?")?;
                if let Ok(dir) = self.cachedir.clone().into_os_string().into_string() {
                    let npath = format!("{}/bin:{}", dir, path);
                    std::env::set_var("PATH", npath);
                } else {
                    return Err(anyhow::anyhow!("couldn't convert cachedir to a string?"));
                }

                let tf_init = std::process::Command::new(&tf)
                    .args(&["init"])
                    .current_dir(&cwd)
                    .status()
                    .with_context(|| format!("{:?} init failed in cwd {:?}", tf, cwd))?;

                if tf_init.success() {
                    // TODO: hook up force to the the arg parser
                    let tf_destroy = std::process::Command::new(&tf)
                        .args(&["destroy", "-auto-approve", "-force"])
                        .current_dir(&cwd)
                        .status()
                        .with_context(|| {
                            format!("{:?} destroy -auto-approve in cwd {:?}", &tf, cwd)
                        })?;
                    if tf_destroy.success() {
                        eprintln!("ok?");
                    } else {
                        return Err(anyhow::anyhow!(format!(
                            "{:?} destroy failed for some reason, cowardly refusing to continue",
                            tf
                        )));
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "terraform init failed for some reason, cowardly refusing to continue"
                    ));
                }
                Ok(cwd.clone())
            }
            CacheSource::TerraformUp {
                cwd,
                image,
                user_config,
            } => {
                // TODO: make this next bit a validate kinda fn
                let mkisofs = std::process::Command::new("mkisofs")
                    .arg("-v")
                    .output()
                    .context("mkisofs not present in any PATH, cannot continue")?;
                // mkisofs -v returns 1, why? who knows, every unix command is a
                // snowflake and they all want to do things their own way
                if let Some(code) = mkisofs.status.code() {
                    if code != 1 {
                        return Err(anyhow::anyhow!(format!(
                            "mkisofs -v did not return expected return code got: {}, required to run", code)
                        ));
                    }
                }

                let mut dir = self.cachedir.clone();
                dir.push(cwd);

                let mut tf = self.cachedir.clone();
                tf.push("bin");
                tf.push("terraform");

                let path =
                    std::env::var("PATH").context("std::env::var() failed for PATH, is it set?")?;
                if let Ok(dir) = self.cachedir.clone().into_os_string().into_string() {
                    let npath = format!("{}/bin:{}", dir, path);
                    std::env::set_var("PATH", npath);
                } else {
                    return Err(anyhow::anyhow!("couldn't convert cachedir to a string?"));
                }

                let tf_init = std::process::Command::new(&tf)
                    .args(&["init"])
                    .current_dir(&cwd)
                    .status()
                    .with_context(|| format!("{:?} init in cwd {:?}", &tf, cwd))?;

                if tf_init.success() {
                    if let Ok(image) = image.clone().into_os_string().into_string() {
                        let mut user_vars = vec![];

                        if let Some(vars) = user_config.vars.get("terraformVars") {
                            if vars.is_mapping() {
                                if let Some(map) = vars.as_mapping() {
                                    for (k, v) in map {
                                        if let Some(key) = k.as_str() {
                                            if let Some(value) = v.as_str() {
                                                user_vars.push("-var".to_string());
                                                user_vars.push(format!(
                                                    "{}={}",
                                                    key.to_string(),
                                                    value.to_string()
                                                ));
                                            } else if let Some(value) = v.as_u64() {
                                                user_vars.push("-var".to_string());
                                                user_vars.push(format!(
                                                    "{}={}",
                                                    key.to_string(),
                                                    value
                                                ));
                                            } else if let Some(value) = v.as_bool() {
                                                user_vars.push("-var".to_string());
                                                user_vars.push(format!(
                                                    "{}={}",
                                                    key.to_string(),
                                                    value
                                                ));
                                            } else {
                                                eprintln!("warning: ignoring input key: {} with value of: {:?} may be a bug/oversight, open an issue with all relevant information", key, v);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        let mut tf_apply_args = vec![];
                        tf_apply_args.push("apply".to_string());
                        tf_apply_args.push("-auto-approve".to_string());
                        tf_apply_args.append(&mut user_vars);
                        tf_apply_args.push("-var".to_string());
                        tf_apply_args.push(format!("qcow_source={}", image));

                        let tf_apply = std::process::Command::new(tf)
                            .args(tf_apply_args)
                            .current_dir(&cwd)
                            .status()
                            .context("terraform apply failed")?;
                        if tf_apply.success() {
                            eprintln!("ok?");
                        } else {
                            dbg!(tf_apply);
                            return Err(anyhow::anyhow!(
                            "terraform apply failed for some reason, cowardly refusing to continue"
                        ));
                        }
                    } else {
                        return Err(anyhow::anyhow!(
                            "couldn't convert filesystem qcow2 image name to a string..."
                        ));
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "terraform init failed for some reason, cowardly refusing to continue"
                    ));
                }
                Ok(cwd.clone())
            }

            _ => Err(anyhow::anyhow!("nope")),
        };
    }
}

// TODO: Did I do something wrong with this? it seems capped at 10MiB/s when
// copying data, that or the system I'm testing on is wicked slow af
struct ReaderWithProgress<R> {
    inner: R,
    progress_bar: indicatif::ProgressBar,
}

impl<R: std::io::Read> std::io::Read for ReaderWithProgress<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf).map(|n| {
            self.progress_bar.inc(n as u64);
            n
        })
    }
}

struct WriterWithProgress<W> {
    inner: W,
    progress_bar: indicatif::ProgressBar,
}

impl<W: std::io::Write> std::io::Write for WriterWithProgress<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf).map(|n| {
            self.progress_bar.inc(n as u64);
            n
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(self.inner.flush()?)
    }
}

// TODO: Validate that this gets the same digest as a file read would.
// For now whatever for future this should be validated.
pub fn sha256_string(content: std::string::String) -> std::string::String {
    use digest::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(&content[..].as_bytes());

    let result = hasher.finalize();

    hex::encode(result)
}

pub fn sha256_digest<R: std::io::Read>(
    mut reader: R,
) -> Result<ring::digest::Digest, anyhow::Error> {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}

//"https://releases.hashicorp.com/packer/1.6.6/packer_1.6.6_linux_amd64.zip"
// Simple fn to simply use http HEAD to get Content-Length header.
//
// If that fails or the header doesn't come back, simply returns None to
// indicate for whatever reason we can't get the length. For the future(ish)
// fn get_uri_len(uri: &str) -> Result<u64, anyhow::Error> {
//     return match ureq::head(uri).call() {
//         Ok(response) => {
//             if let Some(clhdr) = response.header("Content-Length") {
//                 // let res: Result<u64, ()> =clhdr.parse().map_err(drop).ok()?;
//                 let res: Result<u64, ()> = clhdr.parse().map_err(drop);
//                 let len: Option<u64> = res.ok();
//                 Ok(len)
//             } else {
//                 Ok(0)
//             }
//         },
//         // Separate match for http errors, if http failed no need to ask for
//         // an issue.
//         //
//         // Here as a placeholder essentially
//         Err(ureq::Error::Status(_code, _response)) => 0,
//         Err(x) => {
//             dbg!(x);
//             anyhow::bail!("unexpected error, if you see this message please file an issue!");
//         }
//     };
// }
