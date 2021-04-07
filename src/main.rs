extern crate console;
extern crate ipaddress;

use clap::{App, Arg, ArgMatches, SubCommand};
use fallible_iterator::FallibleIterator;
use indicatif::{ProgressBar, ProgressStyle};
use path_clean::PathClean;
use std::io::Write;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use terminal_size::{terminal_size, Height, Width};
use waiter::Waiter;

extern crate humantime;
extern crate waiter;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate lazy_static;
extern crate regex;

use regex::Regex;

use serde::de::IntoDeserializer;
use serde::Deserialize;

extern crate serde_yaml;
extern crate subprocess;

extern crate dirs;
extern crate env_logger;
extern crate fallible_iterator;
extern crate libc;
extern crate openstack;

pub fn absolute_path<P>(path: P) -> std::io::Result<PathBuf>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    if path.is_absolute() {
        Ok(path.to_path_buf().clean())
    } else {
        Ok(std::env::current_dir()?.join(path).clean())
    }
}

/// Mimic isatty(3) but if any of stdin/stdout/stderr return false, presume
/// we're not running in a tty.
// Have to consider all libc calls unsafe
pub fn isatty() -> bool {
    let stdin_isatty = unsafe { libc::isatty(libc::STDIN_FILENO as i32) } != 0;
    let stdout_isatty = unsafe { libc::isatty(libc::STDOUT_FILENO as i32) } != 0;
    let stderr_isatty = unsafe { libc::isatty(libc::STDERR_FILENO as i32) } != 0;

    stdin_isatty ^ stdout_isatty ^ stderr_isatty
}

/// Deserialize bool from String with custom value mapping
fn bool_from_invalid_string<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    match String::deserialize(deserializer)?.as_ref() {
        "true" => Ok(true),
        "True" => Ok(true),
        "false" => Ok(false),
        "False" => Ok(false),
        other => Err(serde::de::Error::invalid_value(
            serde::de::Unexpected::Str(other),
            &"True or False",
        )),
    }
}

/// Treat strings of yaml "null" as None
fn null_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: serde::de::Deserialize<'de>,
{
    let opt = Option::<String>::deserialize(de)?;
    let opt = opt.as_ref().map(String::as_str);
    match opt {
        None | Some("null") | Some("~") => Ok(None),
        Some(s) => T::deserialize(s.into_deserializer()).map(Some),
    }
}

// Most everything we so far have in this setup is string and never sensitive
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TfPrelude {
    #[serde(rename = "sensitive")]
    sensitive: bool,

    #[serde(rename = "type")]
    tftype: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct Ips {
    #[serde(rename = "sensitive")]
    sensitive: bool,
}

// Note, the sensitive/type is effectively ignored
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IpInfo {
    #[serde(rename = "value")]
    kvs: Ips,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TfCidr {
    #[serde(rename = "sensitive")]
    sensitive: bool,

    #[serde(rename = "type")]
    tftype: String,

    #[serde(rename = "value")]
    cidr: String,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TfCount {
    #[serde(rename = "sensitive")]
    sensitive: bool,

    #[serde(rename = "type")]
    tftype: String,

    #[serde(rename = "value")]
    count: String,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TfName {
    #[serde(rename = "sensitive")]
    sensitive: bool,

    #[serde(rename = "type")]
    tftype: String,

    #[serde(rename = "value")]
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Task {
    name: String,
    command: String,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TfString {
    #[serde(rename = "sensitive")]
    sensitive: bool,

    #[serde(rename = "type")]
    tftype: String,

    #[serde(rename = "value")]
    name: String,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TfConfig {
    #[serde(rename = "cmn_cidr")]
    cust_cidr: TfCidr,

    #[serde(rename = "nmn_cidr")]
    node_cidr: TfCidr,

    #[serde(rename = "hsn_cidr")]
    hsn_cidr: TfCidr,

    #[serde(rename = "res_prefix")]
    prefix: TfString,

    #[serde(rename = "sms_name")]
    sms_name: TfString,

    #[serde(rename = "sms_master_count")]
    masters: TfString,

    #[serde(rename = "sms_worker_count")]
    workers: TfString,

    #[serde(rename = "remote_ansible_ip")]
    rsync_target_ip: TfString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Play {
    #[serde(rename = "hosts")]
    host_list: String,
    tasks: Vec<Task>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Flavor {
    #[serde(rename = "craystack")]
    Openstack,
    #[serde(rename = "virtualbox")]
    Vb,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Repo {
    #[serde(rename = "name")]
    name: Option<String>,

    #[serde(rename = "url")]
    url: Option<String>,

    #[serde(rename = "branch")]
    #[serde(deserialize_with = "null_string_as_none")]
    branch_name: Option<String>,

    #[serde(rename = "date")]
    #[serde(deserialize_with = "null_string_as_none")]
    date: Option<String>,

    #[serde(rename = "depth")]
    #[serde(deserialize_with = "null_string_as_none")]
    depth: Option<usize>,

    #[serde(rename = "link")]
    #[serde(deserialize_with = "null_string_as_none")]
    isalink: Option<String>,

    #[serde(rename = "commit")]
    commit: Option<String>,
}

impl Default for Repo {
    fn default() -> Repo {
        Repo {
            name: None,
            url: None,
            branch_name: None,
            date: None,
            depth: None,
            isalink: None,
            commit: None,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Inventory {
    #[serde(rename = "craystack")]
    craystack: InventoryData,

    #[serde(rename = "virtualbox")]
    vb: InventoryData,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InventoryData {
    #[serde(rename = "repo")]
    repository: String,

    #[serde(rename = "dir")]
    url: String,

    #[serde(rename = "file")]
    file_name: String,

    #[serde(rename = "options")]
    options: RookOption,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RookOption {
    #[serde(rename = "rook_ceph_enabled")]
    #[serde(deserialize_with = "bool_from_invalid_string")]
    rook: bool,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KongExtra {
    #[serde(rename = "kong_extra_issuers")]
    issuers: Vec<String>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Role {
    #[serde(rename = "repo")]
    repository: Option<String>,

    #[serde(rename = "dir")]
    directory: Option<String>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Lib {
    #[serde(rename = "repo")]
    repository: Option<String>,

    #[serde(rename = "dir")]
    directory: Option<String>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Playbook {
    #[serde(rename = "repo")]
    repository: Option<String>,

    #[serde(rename = "file")]
    file: Option<String>,

    #[serde(rename = "extra_vars")]
    #[serde(flatten)]
    extras: std::collections::HashMap<String, serde_yaml::Value>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    #[serde(rename = "workspace")]
    workspace_dir: String,

    #[serde(rename = "target")]
    target: Flavor,

    #[serde(rename = "ssh-config")]
    ssh_configfile: String,

    #[serde(rename = "repo-defaults")]
    defaults: Defaults,

    #[serde(rename = "repos")]
    #[serde(default)]
    repositories: Vec<Repo>,

    #[serde(rename = "inventory")]
    inventory: Inventory,

    #[serde(rename = "roles")]
    roles: Vec<Role>,

    #[serde(rename = "libraries")]
    libraries: Vec<Lib>,

    #[serde(rename = "playbooks")]
    playbooks: Vec<Playbook>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Defaults {
    #[serde(rename = "branch")]
    branch: Option<String>,

    #[serde(rename = "date")]
    date: Option<String>,

    #[serde(rename = "depth")]
    depth: Option<usize>,
}

// Arg list was getting unwieldy, make the "optional" parts use Default trait for Defaults with stuff that needs to differ overridden at call site
struct RunArgs {
    verbose: bool,
    hardfail: bool,
    dir: Option<PathBuf>,
    display: Option<String>,
    timing: bool,
    print_cmd: bool,
    onfail: fn() -> (),
}

// For run_command default
fn do_nothing() -> () {}

// This assumes PWD hasn't ever changed in the running process, if not... well have fun
fn rename_fail_file() -> () {
    let r = std::fs::rename("tmp.yml", "bad.yml");
    if let Err(_) = r {
        eprintln!("Couldn't rename tmp.yml to bad.yml");
        std::process::exit(1);
    }
}

impl Default for RunArgs {
    fn default() -> Self {
        RunArgs {
            verbose: false,
            hardfail: false,
            dir: None,
            display: None,
            onfail: do_nothing,
            // Only applicable when verbose is true
            timing: true,
            // Also only applicable when verbose is true
            print_cmd: true,
        }
    }
}

fn log_command_to_timeline(command: &str, args: &[&str]) -> () {
    let mut timeline = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("timeline")
        .unwrap();

    if let Err(e) = writeln!(timeline, "{} {}", command, args.join(" ")) {
        eprintln!("Couldn't log command to timeline file: {}", e);
    }
}

// Just a silly wrapper fn to make this simpler.
fn run_command(command: &str, args: &[&str], optional: RunArgs) -> Result<(), String> {
    let cmd_fmt = format!("{} {}", command, args.join(" "));

    let mut cmd_out = cmd_fmt;

    if let Some(output) = optional.display {
        cmd_out = output;
    }

    log_command_to_timeline(command, args);

    if optional.verbose {
        let start = std::time::Instant::now();

        if optional.print_cmd {
            eprintln!("{}", cmd_out);
        }

        let cmd = if let Some(directory) = optional.dir {
            std::process::Command::new(command)
                .args(args)
                .current_dir(&directory)
                .status()
                .expect("failed...")
        } else {
            std::process::Command::new(command)
                .args(args)
                .status()
                .expect("failed...")
        };

        let duration = start.elapsed();

        if optional.timing {
            eprint!(
                "took about {}\n",
                humantime::format_duration(duration).to_string()
            );
        }

        if !cmd.success() {
            (optional.onfail)();
            match cmd.code() {
                Some(rc) => eprintln!("exited with rc: {}\n", rc),
                None => eprintln!("process was terminated by a signal prolly\n"),
            }
            std::process::exit(1);
        }
    } else {
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(200);
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("-\\|/ ")
                .template("{msg} {elapsed_precise} {spinner:.dim.bold}"),
        );
        let cwd = std::env::current_dir().expect("Unable to get cwd");

        let mut stdout_opts = subprocess::Redirection::File(
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open("cmd.log")
                .map_err(|why| format!("{}", why))?,
        );

        if !isatty() {
            stdout_opts = subprocess::Redirection::Pipe;
        }

        let child = if let Some(directory) = optional.dir {
            subprocess::Exec::cmd(command)
                .args(&args)
                .cwd(directory)
                .stdout(stdout_opts)
                .stderr(subprocess::Redirection::Merge)
                .popen()
        } else {
            subprocess::Exec::cmd(command)
                .args(&args)
                .stdout(stdout_opts)
                .stderr(subprocess::Redirection::Merge)
                .popen()
        };

        std::env::set_current_dir(&cwd).expect("Couldn't set working directory");

        match child {
            Ok(mut c) => {
                let size = terminal_size();
                if let Some((Width(w), Height(_h))) = size {
                    let width = w as usize;
                    if width > 14 && cmd_out.len() >= (width - 14) {
                        // subtract 11 to allow the time/spinner, iff over that
                        // we print out as much as we can with ... at the end
                        let msg = format!("{}...", &cmd_out[0..(width - 14)]);
                        pb.set_message(&msg[..]);
                    } else {
                        pb.set_message(&cmd_out);
                    }
                } else {
                    pb.set_message(&cmd_out);
                }

                while c.poll().is_none() {
                    pb.tick();
                    std::thread::sleep(std::time::Duration::new(1, 0))
                }

                if let Some(result) = c.poll() {
                    match result {
                        subprocess::ExitStatus::Exited(status) => {
                            if status == 0 {
                                pb.finish_and_clear();
                            } else {
                                (optional.onfail)();
                                if optional.hardfail {
                                    eprintln!("{} exited with rc: {}\n", cmd_out, status);
                                    let contents = std::fs::read_to_string("cmd.log")
                                        .expect("Couldn't read cmd.log file");
                                    eprintln!("{}", contents);
                                    std::process::exit(1);
                                }
                            }
                        }
                        _ => {
                            if optional.hardfail {
                                (optional.onfail)();
                                eprintln!("finished with {:?}", result);
                            }
                        }
                    }
                    return Ok(());
                }
            }
            Err(e) => {
                eprintln!("something broke {:?}", e);
            }
        }
    }
    return Ok(());
}

fn os_servers() -> Vec<openstack::compute::Server> {
    let os = openstack::Cloud::from_env()
        .expect("Failed to create an identity provider from the environment");

    let sorting = openstack::compute::ServerSortKey::AccessIpv4;
    let servers: Vec<openstack::compute::Server> = os
        .find_servers()
        .sort_by(openstack::Sort::Asc(sorting))
        .detailed()
        .into_iter()
        .collect()
        .expect("Cannot list servers");

    return servers;
}

// Note, in run() we setup/get the full path for any user provided functions.
//
// We also then subsequently change our cwd to the svm.yml file provided once
// fully expanding any user provided paths.
fn run(matches: ArgMatches) -> Result<(), String> {
    let ssh_key_file = get_ssh_file(matches.value_of("sshkey"));
    std::env::set_var("TF_VAR_ssh_key_file", &ssh_key_file);
    std::env::set_var("TF_VAR_remote_ansible", "sure");

    // zero out timeline file at startup
    let _timeline = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open("timeline")
        .unwrap();

    if let Some(val) = matches.value_of("compute-nodes") {
        std::env::set_var("TF_VAR_cmp_count", val);
    }

    if let Some(val) = matches.value_of("sms-masters") {
        std::env::set_var("TF_VAR_sms_master_count", val);
    }

    if let Some(val) = matches.value_of("sms-workers") {
        std::env::set_var("TF_VAR_sms_worker_count", val);
    }

    if let Some(val) = matches.value_of("with-domain") {
        std::env::set_var("TF_VAR_tld", val);
    }

    if !matches.is_present("without-subdomain") {
        std::env::set_var("TF_VAR_workspace_as_prefix", "false");
    }

    if matches.is_present("with-lustre") {
        std::env::set_var("TF_VAR_lus_enabled", "sure");
    }

    if let Some(uri) = matches.value_of("kernel-server-uri") {
        std::env::set_var("TF_VAR_kernel_server_uri", uri);
    }

    if let Some(uri) = matches.value_of("mofed-server-uri") {
        std::env::set_var("TF_VAR_mofed_server_uri", uri);
    }

    if let Some(uri) = matches.value_of("e2fsprogs-server-uri") {
        std::env::set_var("TF_VAR_e2fsprogs_server_uri", uri);
    }

    if let Some(uri) = matches.value_of("lus-server-uri") {
        std::env::set_var("TF_VAR_lus_server_uri", uri);
    }

    if let Some(uri) = matches.value_of("lus-client-uri") {
        std::env::set_var("TF_VAR_lus_client_uri", uri);
    }

    if let Some(uri) = matches.value_of("lus-emitter-uri") {
        std::env::set_var("TF_VAR_lus_emitter_uri", uri);
    }

    let yaml = get_yaml_path(matches.value_of("yaml"));
    let parent = yaml.parent();

    if !yaml.exists() {
        eprintln!(
            "{} doesn't exist or is typed incorrectly, specify a valid svm.yml file",
            yaml.display()
        );
        std::process::exit(1)
    }

    let tf_ws = matches.value_of("workspace").unwrap_or("default");
    tf_workspace(tf_ws);

    // Save the pwd where the user ran mvs
    let cwd = std::env::current_dir().expect("Cannot determine cwd");

    // We change dir into the parent directory of where the svm.yml is
    // instead of hoping the user is running this from the shasta-vm checkout directory
    if let Some(dir) = parent {
        if !std::env::set_current_dir(&dir).is_ok() {
            let msg = format!(
                "Couldn't change to the parent of the svm.yml file provided: {}",
                yaml.display()
            );
            eprintln!("{}", &msg[..]);
            std::process::exit(1);
        }
    }

    // Validate openstack env is setup correctly.
    validate_env();

    // Unset OS_PROJECT_DOMAIN_ID unconditionally it breaks the openstack
    // provider at times.
    std::env::remove_var("OS_PROJECT_DOMAIN_ID");

    // Validate our users environment/setup will function
    validate_runtime();

    match matches.subcommand() {
        ("status", Some(m)) => run_status(&m, &cwd, &yaml),
        ("verify", Some(m)) => run_verify(&m, &cwd, &yaml),
        ("up", Some(m)) => run_up(&m, &cwd, &yaml),
        ("down", Some(m)) => run_down(&m, &cwd, &yaml),
        ("provision", Some(m)) => run_provision(&m, &cwd, &yaml),
        ("unbound", Some(m)) => run_unbound(&m, &cwd, &yaml),
        ("ssh-config", Some(m)) => run_ssh_config(&m, &cwd, &yaml),
        ("daily", Some(m)) => run_ci(&m, &cwd, &yaml),
        ("ci", Some(m)) => run_ci(&m, &cwd, &yaml),
        ("redo", Some(m)) => run_redo(&m, &cwd, &yaml),
        ("test", Some(m)) => run_test(&m, &cwd, &yaml),
        ("scp", Some(m)) => run_scp(&m, &cwd, &yaml),
        ("run", Some(m)) => run_run(&m, &cwd, &yaml),
        ("cleanup", Some(m)) => run_cleanup(&m, &cwd, &yaml),
        _ => {
            eprintln!("nothing to do, no subcommand found");
            std::process::exit(1);
        }
    }
}

fn tf_prereqs() -> () {
    let _ = run_command(
        "terraform",
        &["init"],
        RunArgs {
            hardfail: true,
            ..RunArgs::default()
        },
    );
    let _ = run_command(
        "terraform",
        &["plan"],
        RunArgs {
            hardfail: true,
            ..RunArgs::default()
        },
    );
}

fn run_scp(matches: &ArgMatches, _cwd: &PathBuf, yaml: &PathBuf) -> Result<(), String> {
    let verbose = matches.is_present("verbose");
    let parent = yaml.parent();

    if parent.is_none() {
        eprintln!("couldn't get parent directory");
        std::process::exit(1);
    }

    let ssh_key_file = get_ssh_file(matches.value_of("sshkey"));

    let mut tf = std::process::Command::new("terraform");
    let tf_config = tf.arg("output").arg("--json").output();
    let tf_config_s = &tf_config.expect("terraform output couldn't be had");

    let tf_vals = serde_json::from_str::<TfConfig>(
        &String::from_utf8(tf_config_s.stdout.clone()).expect("terraform output broken?"),
    )
    .expect("can't parse terraform output --json");

    let mut hosts: Vec<Host> = Vec::new();
    let mut smss: Vec<Host> = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(
        &String::from_utf8(tf_config_s.stdout.clone()).unwrap(),
    ) {
        if let Some(sms) = json["remote_ansible_hosts"].as_object() {
            if let Some(values) = sms["value"].as_object() {
                for (k, v) in values {
                    if let Some(host) = extract_hostname(k) {
                        if v.is_string() {
                            let hostname = format!("{}-cmn", host);
                            let ip = v.as_str().unwrap().to_string();
                            hosts.push(Host {
                                hostname: hostname.clone(),
                                ip_address: ip.clone(),
                            });
                            smss.push(Host {
                                hostname: host.to_string(),
                                ip_address: ip,
                            });
                        }
                    }
                }
            }
        }
    }

    let scp_host = format!("root@{}", tf_vals.rsync_target_ip.name);
    let ssh_key_ident = format!("IdentityFile={}", &ssh_key_file);
    let scp_opts = [
        "-o",
        &ssh_key_ident[..],
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=QUIET",
    ];

    if let Some(remote) = matches.value_of("remote-source") {
        if let Some(dest) = matches.value_of("local-dest") {
            let scp_src = format!("{}:{}", scp_host, remote);
            let mut scp_cmd_opts = Vec::new();
            scp_cmd_opts.append(&mut scp_opts.to_vec());
            scp_cmd_opts.append(&mut vec!["-r", "-v"]);
            scp_cmd_opts.append(&mut vec![&scp_src[..], &dest[..]]);
            let scp_out = format!("scp {} {}", scp_src, &dest[..]);
            let _ = run_command(
                "scp",
                &scp_cmd_opts,
                RunArgs {
                    verbose: verbose,
                    hardfail: true,
                    display: Some(scp_out),
                    ..RunArgs::default()
                },
            );
        } else {
            eprintln!("the scp command requires a local destination to copy to");
        }
    } else {
        eprintln!("the scp command requires a remote source to copy from");
    }

    Ok(())
}

// Yes this is a hokey name but i'm being consistent with run_SUBCOMMAND
fn run_run(matches: &ArgMatches, _cwd: &PathBuf, yaml: &PathBuf) -> Result<(), String> {
    let parent = yaml.parent();

    if parent.is_none() {
        eprintln!("couldn't get parent directory");
        std::process::exit(1);
    }

    let ssh_key_file = get_ssh_file(matches.value_of("sshkey"));

    let mut tf = std::process::Command::new("terraform");
    let tf_config = tf.arg("output").arg("--json").output();
    let tf_config_s = &tf_config.expect("terraform output couldn't be had");

    let tf_vals = serde_json::from_str::<TfConfig>(
        &String::from_utf8(tf_config_s.stdout.clone()).expect("terraform output broken?"),
    )
    .expect("can't parse terraform output --json");

    let ssh_dest = format!("root@{}", tf_vals.rsync_target_ip.name);
    let ssh_key_ident = format!("IdentityFile={}", &ssh_key_file);
    let ssh_opts = [
        "-t",
        "-o",
        &ssh_key_ident[..],
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=QUIET",
    ];

    if let Some(cmd) = matches.value_of("command") {
        let mut ssh_cmd_opts = Vec::new();
        ssh_cmd_opts.append(&mut ssh_opts.to_vec());
        ssh_cmd_opts.append(&mut vec![&ssh_dest[..], &cmd]);
        let ssh_out = format!("ssh {} \"{}\"", ssh_dest, &cmd[..]);
        let _ = run_command(
            "ssh",
            &ssh_cmd_opts,
            RunArgs {
                verbose: true,
                hardfail: true,
                display: Some(ssh_out),
                timing: false,
                print_cmd: false,
                ..RunArgs::default()
            },
        );
    } else {
        eprintln!("the run command requires something to run remotely")
    }

    Ok(())
}

fn run_test(matches: &ArgMatches, _cwd: &PathBuf, yaml: &PathBuf) -> Result<(), String> {
    let verbose = matches.is_present("verbose");
    let parent = yaml.parent();

    if parent.is_none() {
        eprintln!("couldn't get parent directory");
        std::process::exit(1);
    }

    let ssh_key_file = get_ssh_file(matches.value_of("sshkey"));

    let mut tf = std::process::Command::new("terraform");
    let tf_config = tf.arg("output").arg("--json").output();
    let tf_config_s = &tf_config.expect("terraform output couldn't be had");

    let tf_vals = serde_json::from_str::<TfConfig>(
        &String::from_utf8(tf_config_s.stdout.clone()).expect("terraform output broken?"),
    )
    .expect("can't parse terraform output --json");

    let mut hosts: Vec<Host> = Vec::new();
    let mut smss: Vec<Host> = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(
        &String::from_utf8(tf_config_s.stdout.clone()).unwrap(),
    ) {
        if let Some(cmn_ip_map) = json["cmn_ip_map"].as_object() {
            if let Some(values) = cmn_ip_map["value"].as_object() {
                for (k, v) in values {
                    if let Some(host) = extract_hostname(k) {
                        if v.is_string() {
                            let hostname = format!("{}-cmn", host);
                            let ip = v.as_str().unwrap().to_string();
                            hosts.push(Host {
                                hostname: hostname.clone(),
                                ip_address: ip.clone(),
                            });
                            smss.push(Host {
                                hostname: host.to_string(),
                                ip_address: ip,
                            });
                        }
                    }
                }
            }
            if let Some(nmn_ip_map) = json["nmn_ip_map"].as_object() {
                if let Some(values) = nmn_ip_map["value"].as_object() {
                    for (k, v) in values {
                        if let Some(host) = extract_hostname(k) {
                            if v.is_string() {
                                let hostname = format!("{}-nmn", host);
                                let ip = v.as_str().unwrap().to_string();
                                hosts.push(Host {
                                    hostname: hostname,
                                    ip_address: ip,
                                });
                            }
                        }
                    }
                }
            }
            if let Some(hsn_ip_map) = json["hsn_ip_map"].as_object() {
                if let Some(values) = hsn_ip_map["value"].as_object() {
                    for (k, v) in values {
                        if let Some(host) = extract_hostname(k) {
                            if v.is_string() {
                                let hostname = format!("{}-hsn", host);
                                let ip = v.as_str().unwrap().to_string();
                                hosts.push(Host {
                                    hostname: hostname,
                                    ip_address: ip,
                                });
                            }
                        }
                    }
                }
            }
            if let Some(hmn_ip_map) = json["hmn_ip_map"].as_object() {
                if let Some(values) = hmn_ip_map["value"].as_object() {
                    for (k, v) in values {
                        if let Some(host) = extract_hostname(k) {
                            if v.is_string() {
                                let hostname = format!("{}-hmn", host);
                                let ip = v.as_str().unwrap().to_string();
                                hosts.push(Host {
                                    hostname: hostname,
                                    ip_address: ip,
                                });
                            }
                        }
                    }
                }
            }

            // if let Some(cmn_uuids) = json["cmn_uuids"].as_object() {
            //     if let Some(values) = cmn_uuids["value"].as_object() {
            //         println!("cmn_uuids");
            //         for (k, v) in values {
            //             if v.is_string() {
            //                 println!("{} = {}", k, v.as_str().unwrap());
            //             }
            //         }
            //     }
            // }
        }
    }

    let ssh_dest = format!("root@{}", tf_vals.rsync_target_ip.name);
    let ssh_key_ident = format!("IdentityFile={}", &ssh_key_file);
    let ssh_opts = [
        "-o",
        &ssh_key_ident[..],
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=QUIET",
    ];

    if matches.is_present("without-ct") {
        if verbose {
            eprintln!("skipping ct-driver");
        }
    } else {
        // Don't run ct-driver on normal svm.yml
        if let Some(yaml) = matches.value_of("yaml") {
            if let Ok(path) = std::fs::canonicalize(PathBuf::from(&yaml[..])) {
                if let Some(fname) = path.file_name() {
                    if fname == "svm.yml" {
                        std::process::exit(0);
                    }
                } else {
                    eprintln!("couldn't get filename for svm.yml file");
                    std::process::exit(1);
                }
            } else {
                eprintln!("couldn't canonicalize path input for svm.yml file");
                std::process::exit(1);
            }
        }

        if let Some(ct_increment) = matches.value_of("increment") {
            let ct_driver = "/opt/cray/tests/bin/ct-driver";
            let ssh_cmd_ct = format!("{} -u sms-{}/storage/cds", ct_driver, ct_increment);

            let mut ssh_cmd_opts_ct = Vec::new();

            // First up reset the blacklist by reinstalling the rpm
            let rpm_restore = "rm -f /opt/cray/tests/etc/blacklist.txt && zypper -n in -f cray-ct-driver-crayctldeploy".to_string();
            let mut rpm_restore_opts = Vec::new();
            rpm_restore_opts.append(&mut ssh_opts.to_vec());

            rpm_restore_opts.append(&mut [&ssh_dest[..], &rpm_restore[..]].to_vec());
            let rpm_out = format!("{} \"{}\"", ssh_dest, rpm_restore);
            let _ = run_command(
                "ssh",
                &rpm_restore_opts,
                RunArgs {
                    verbose: false,
                    display: Some(rpm_out),
                    ..RunArgs::default()
                },
            );

            // Then append to it, but only if we have --blacklist entries present
            if let Some(blacklists) = matches.values_of("blacklist") {
                let bss: Vec<_> = blacklists.collect();
                let tmp = bss.join("\\n");

                let update_blacklist = format!(
                    "printf \"\\n\\n{}\\n\" | tee -a /opt/cray/tests/etc/blacklist.txt",
                    tmp
                );
                let mut blacklist_opts = Vec::new();
                blacklist_opts.append(&mut ssh_opts.to_vec());
                blacklist_opts.append(&mut [&ssh_dest[..], &update_blacklist[..]].to_vec());

                let blacklist_out = format!("{} \"{}\"", ssh_dest, update_blacklist);
                let _ = run_command(
                    "ssh",
                    &blacklist_opts,
                    RunArgs {
                        verbose: false,
                        display: Some(blacklist_out),
                        ..RunArgs::default()
                    },
                );
            }

            ssh_cmd_opts_ct.append(&mut ssh_opts.to_vec());
            ssh_cmd_opts_ct.append(&mut [&ssh_dest[..], &ssh_cmd_ct[..]].to_vec());
            let ssh_out_ct = format!("{} \"{}\"", ssh_dest, ssh_cmd_ct);
            let _ = run_command(
                "ssh",
                &ssh_cmd_opts_ct,
                RunArgs {
                    verbose: verbose,
                    hardfail: true,
                    display: Some(ssh_out_ct),
                    ..RunArgs::default()
                },
            );
        }
    }

    std::process::exit(0);
}

fn run_ci(matches: &ArgMatches, cwd: &PathBuf, yaml: &PathBuf) -> Result<(), String> {
    run_down(&matches.clone(), &cwd, &yaml)?;
    run_up(&matches.clone(), &cwd, &yaml)?;
    run_provision(&matches.clone(), &cwd, &yaml)?;
    run_test(&matches.clone(), &cwd, &yaml)?;
    std::process::exit(0);
}

fn run_redo(matches: &ArgMatches, cwd: &PathBuf, yaml: &PathBuf) -> Result<(), String> {
    run_down(&matches.clone(), &cwd, &yaml)?;
    run_up(&matches.clone(), &cwd, &yaml)?;
    std::process::exit(0);
}

fn extract_hostname(from: &str) -> Option<&str> {
    lazy_static! {
        static ref RE: Regex = Regex::new(
            r"(?x)
          ^(?P<hostname>.*[-][[:digit:]]{2})[-][[:word:]]+-[0-9a-f]{16}$"
        )
        .unwrap();
    }
    RE.captures(from)
        .and_then(|mat| mat.name("hostname").map(|mat| mat.as_str()))
}

fn run_unbound(_matches: &ArgMatches, _cwd: &PathBuf, yaml: &PathBuf) -> Result<(), String> {
    let parent = yaml.parent();

    if parent.is_none() {
        eprintln!("couldn't get parent directory");
        std::process::exit(1);
    }

    let mut tf = std::process::Command::new("terraform");
    let tf_config = tf.arg("output").arg("--json").output();
    let tf_config_s = tf_config.expect("terraform output couldn't be had");

    if let Ok(json) =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8(tf_config_s.stdout).unwrap())
    {
        if let Some(tld) = json["full_tld"].as_object() {
            let tldval = &tld["value"].as_str().unwrap();
            println!("  local-zone: \"{}.\" static", &tldval);
            if let Some(cmn_ip_map) = json["cmn_ip_map"].as_object() {
                if let Some(values) = cmn_ip_map["value"].as_object() {
                    for (k, v) in values {
                        if let Some(host) = extract_hostname(k) {
                            if v.is_string() {
                                println!(
                                    "  local-data: \"{}.{}.  IN A {}\"",
                                    host,
                                    &tldval,
                                    v.as_str().unwrap()
                                );
                                println!(
                                    "  local-data-ptr: \"{} {}.{}\"",
                                    v.as_str().unwrap(),
                                    host,
                                    &tldval
                                );
                            }
                        }
                    }
                }
            }
            if let Some(lus_ip_map) = json["lus_ip_map"].as_object() {
                if let Some(values) = lus_ip_map["value"].as_object() {
                    for (k, v) in values {
                        if let Some(host) = extract_hostname(k) {
                            if v.is_string() {
                                println!(
                                    "  local-data: \"{}.{}.  IN A {}\"",
                                    host,
                                    tldval,
                                    v.as_str().unwrap()
                                );
                                println!(
                                    "  local-data-ptr: \"{} {}.{}\"",
                                    v.as_str().unwrap(),
                                    host,
                                    tldval
                                );
                            }
                        }
                    }
                }
            }
            std::process::exit(0);
        }
    }
    eprintln!("Couldn't read the terraform json output!");
    std::process::exit(1);
}

fn run_ssh_config(matches: &ArgMatches, _cwd: &PathBuf, yaml: &PathBuf) -> Result<(), String> {
    let relpath = std::path::Path::new(yaml);
    let fullpath = relpath.canonicalize().unwrap();
    let parent = fullpath.parent();

    if parent.is_none() {
        eprintln!("couldn't get parent directory");
        std::process::exit(1);
    }

    let ssh_key_file = get_ssh_file(matches.value_of("sshkey"));

    let mut tf = std::process::Command::new("terraform");
    let tf_config = tf
        .arg("output")
        .arg("--json")
        .current_dir(&parent.unwrap().to_string_lossy().as_ref())
        .output();
    let tf_config_s = tf_config.expect("terraform output couldn't be had");

    if let Ok(json) =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8(tf_config_s.stdout).unwrap())
    {
        if let Some(tld) = &json["full_tld"].as_object() {
            let tldval = &tld["value"]
                .as_str()
                .expect("couldn't find a tld defined in terraform configuration");
            if let Some(cmn_ip_map) = &json["cmn_ip_map"].as_object() {
                if let Some(values) = cmn_ip_map["value"].as_object() {
                    for (k, v) in values {
                        if let Some(host) = extract_hostname(k) {
                            if v.is_string() {
                                print!("host {}.{}\n  Hostname {}\n  IdentityFile {}\n  User root\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel QUIET\n", host, &tldval, v.as_str().unwrap(), ssh_key_file);
                            }
                        }
                    }
                }
            }
            if let Some(lus_ip_map) = json["lus_ip_map"].as_object() {
                if let Some(values) = lus_ip_map["value"].as_object() {
                    for (k, v) in values {
                        if let Some(host) = extract_hostname(k) {
                            if v.is_string() {
                                print!("host {}.{}\n  Hostname {}\n  IdentityFile {}\n  User root\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel QUIET\n", host, &tldval, v.as_str().unwrap(), ssh_key_file);
                            }
                        }
                    }
                }
            }
        }
        std::process::exit(0);
    }
    eprintln!("Couldn't read terraform json output!");
    std::process::exit(1);
}

fn run_provision(matches: &ArgMatches, _cwd: &PathBuf, yaml: &PathBuf) -> Result<(), String> {
    // Global switches in clap can't be required(true), so require it have been
    // specified in this wrapper function
    if matches.value_of("cds-release-bundle").is_none() {
        eprintln!("fatal: The -B switch is required for cds 1.x installs to work

For the latest tar file check the latest jenkins output here:
https://cje2.dev.cray.com/teams-cds-team/job/cds-team/job/CDS_Project/job/cds-release-bundle/job/cds_1.1/lastSuccessfulBuild/console

And scroll down to the bottom for the .tar file");
        std::process::exit(1);
    }

    let verbose = matches.is_present("verbose");
    let parent = yaml.parent();

    if parent.is_none() {
        eprintln!("couldn't get parent directory");
        std::process::exit(1);
    }

    let ssh_key_file = get_ssh_file(matches.value_of("sshkey"));

    let yaml_data = std::fs::read_to_string(&yaml).expect("couldn't read svm.yml file");
    let sms = serde_yaml::from_str::<Config>(&yaml_data);

    let mut this = sms
        .expect("svm.yml input seems to have had issues?")
        .clone();

    let mut tf = std::process::Command::new("terraform");
    let tf_config = tf.arg("output").arg("--json").output();
    let tf_config_s = &tf_config.expect("terraform output couldn't be had");

    let tf_vals = serde_json::from_str::<TfConfig>(
        &String::from_utf8(tf_config_s.stdout.clone()).expect("terraform output broken?"),
    )
    .expect("can't parse terraform output --json");

    let mut ws_dir = parent.unwrap().to_path_buf();
    if let Some(dir) = matches.value_of("dir") {
        ws_dir.push(dir);
    } else {
        ws_dir.push(&this.workspace_dir[..]);
    }

    let mut checkout = true;
    if matches.is_present("skip-checkout") {
        checkout = false;
    }

    if checkout {
        std::fs::create_dir_all(&ws_dir).expect("can't create workspace directory");
        for repo in &this.repositories {
            if let Some(name) = &repo.name {
                let mut git_dir = ws_dir.clone();
                git_dir.push(&name[..]);

                if name != "cms-base-box" {
                    if let Some(link) = &repo.isalink {
                        let dest_dir = std::path::Path::new(&link);
                        if dest_dir.exists() {
                            let dest_dir_full = dest_dir
                                .canonicalize()
                                .expect("couldn't canonicalize link destination");
                            if let Err(e) = std::os::unix::fs::symlink(&git_dir, &dest_dir_full) {
                                eprintln!(
                                    "coudln't symlink {:?} to {:?} error {}",
                                    git_dir, dest_dir_full, e
                                );
                                std::process::exit(1);
                            }
                        } else {
                            eprintln!(
                                "destination {:?} doesn't exist to link to, full stop",
                                dest_dir
                            );
                            std::process::exit(1);
                        }
                    } else {
                        let mut git_args = ["clone"].to_vec();
                        let mut depth: Option<usize> = None;
                        let dstr;
                        let ustr;

                        if git_dir.exists() {
                            // Validate its a git checkout by running git status
                            let _ = run_command(
                                "git",
                                &["status"],
                                RunArgs {
                                    verbose: false,
                                    dir: Some(git_dir),
                                    ..RunArgs::default()
                                },
                            );
                        } else {
                            if let Some(user_depth) = matches.value_of("depth") {
                                let idepth = user_depth
                                    .parse::<usize>()
                                    .expect("depth can't be converted to an integer");
                                depth = Some(idepth);
                            } else {
                                if let Some(user_depth) = &repo.depth {
                                    depth = Some(*user_depth);
                                }
                            }

                            if let Some(branch) = &repo.branch_name {
                                git_args.append(&mut vec!["-b", &branch[..]]);
                            }

                            if let Some(depth) = depth {
                                dstr = format!("{}", depth);
                                git_args.append(&mut vec!["--depth", &dstr[..]]);
                            }

                            if let Some(url) = &repo.url {
                                ustr = format!("{}", url);
                                git_args.append(&mut vec![&ustr[..], &name[..]]);
                            }

                            let _ = run_command(
                                "git",
                                &git_args,
                                RunArgs {
                                    verbose: verbose,
                                    hardfail: true,
                                    dir: Some(ws_dir.clone()),
                                    ..RunArgs::default()
                                },
                            );

                            if !repo.commit.is_none() {
                                let commit = repo.commit.clone().unwrap();

                                let _ = run_command(
                                    "git",
                                    &["checkout", &commit[..]],
                                    RunArgs {
                                        verbose: verbose,
                                        hardfail: true,
                                        dir: Some(git_dir),
                                        ..RunArgs::default()
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Apply supplied patches if given by the user, all patches should be
    // rooted in the workspace directory
    if let Some(patches) = matches.values_of("patch") {
        for patch in patches {
            let patch_buf = PathBuf::from(patch);
            apply_patch(&patch_buf, &ws_dir, verbose);
        }
    }

    if matches.is_present("checkout-only") {
        eprintln!("--checkout-only specified, when ready to provision run with --skip-checkout to resume provisioning steps");
        std::process::exit(0);
    }

    let prefix = "/work";

    let mut roles: Vec<String> = Vec::new();
    let mut libraries: Vec<String> = Vec::new();
    for role in &this.roles {
        if role.repository.is_none() {
            if let Some(dir) = &role.directory {
                roles.push(dir.to_string());
            }
        }
        if let Some(directory) = &role.directory {
            if let Some(repository) = &role.repository {
                roles.push(format!(
                    "{}/{}/{}",
                    prefix,
                    repository.to_string(),
                    directory.to_string()
                ));
            }
        }
    }

    for lib in &this.libraries {
        if lib.repository.is_none() {
            if let Some(dir) = &lib.directory {
                libraries.push(dir.to_string());
            }
        }
        if let Some(directory) = &lib.directory {
            if let Some(repository) = &lib.repository {
                libraries.push(format!(
                    "{}/{}/{}",
                    prefix,
                    repository.to_string(),
                    directory.to_string()
                ));
            }
        }
    }

    let data = format!(
        "[defaults]\nroles_path={}\nlibrary={}\n",
        roles.join(":"),
        libraries.join(":")
    );

    for repo in &this.repositories {
        if let Some(name) = &repo.name {
            let ansible_dir = std::path::Path::new(&ws_dir).join(&name[..]);
            if ansible_dir.exists() {
                let ansible_cfg_file = ansible_dir.join("ansible.cfg.mvs");
                let err_msg = format!("couldn't create {:?} file!", ansible_cfg_file.to_str());
                let mut ansible_cfg = std::fs::File::create(ansible_cfg_file).expect(&err_msg[..]);
                ansible_cfg
                    .write_all(data.as_bytes())
                    .expect("can't write ansible config");
                ansible_cfg
                    .sync_all()
                    .expect("can't sync ansible config file data");
            }
        }
    }

    // Loftsman hack
    // remove "- loftsman" from the l3_management_plane_install.yml file if its found
    let l3_management_plane_install_yaml =
        std::path::Path::new(&ws_dir).join("l3-installer/l3_management_plane_install.yml");
    let l3_management_plane_install_yaml_mvs =
        std::path::Path::new(&ws_dir).join("l3-installer/l3_management_plane_install.yml.mvs");

    if matches.is_present("without-loftsman") {
        if l3_management_plane_install_yaml.exists() {
            l3_management_plane_install_yaml
                .canonicalize()
                .expect("Cannot expand l3_management_plane_install.yml to a full path");

            if let Ok(content) = std::fs::read_to_string(&l3_management_plane_install_yaml) {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&l3_management_plane_install_yaml_mvs)
                {
                    Ok(mut f) => {
                        if let Err(e) = write!(f, "{}", content.replace("- loftsman", "")) {
                            eprintln!("couldn't write to file: {:?} error: {}", f, e);
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "error while trying to open() file {:?} {}",
                            l3_management_plane_install_yaml_mvs, e
                        );
                    }
                }
            } else {
                eprintln!("couldn't read file {:?}", l3_management_plane_install_yaml);
            }
        }
    } else {
        if l3_management_plane_install_yaml_mvs.exists() {
            let emsg = format!(
                "couldn't remove {:?}",
                &l3_management_plane_install_yaml_mvs
            );
            std::fs::remove_file(l3_management_plane_install_yaml_mvs).expect(&emsg[..]);
        }
    }

    // cps hack
    // remove "- cray_cps_..." entries from the cmd-premium-installer cme-premium-deployment.yml file if found
    let cme_premium_deployment_yaml =
        std::path::Path::new(&ws_dir).join("cme-premium-installer/cme-premium-deployment.yml");
    let cme_premium_deployment_yaml_mvs =
        std::path::Path::new(&ws_dir).join("cme-premium-installer/cme-premium-deployment.yml.mvs");

    if matches.is_present("without-cps") {
        if cme_premium_deployment_yaml.exists() {
            cme_premium_deployment_yaml
                .canonicalize()
                .expect("Cannot expand cme-premium-deployment.yml to a full path");

            if let Ok(content) = std::fs::read_to_string(&cme_premium_deployment_yaml) {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&cme_premium_deployment_yaml_mvs)
                {
                    Ok(mut f) => {
                        if let Err(e) = write!(
                            f,
                            "{}",
                            content
                                .replace("- cray_cps_etcd", "")
                                .replace("- cray_cps_broker", "")
                                .replace("- cray_cps_cm", "")
                                .replace("- cray_cps_pm", "")
                        ) {
                            eprintln!("couldn't write to file: {:?} error: {}", f, e);
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "error while trying to open() file {:?} {}",
                            cme_premium_deployment_yaml_mvs, e
                        );
                    }
                }
            } else {
                eprintln!("couldn't read file {:?}", cme_premium_deployment_yaml);
            }
        }
    } else {
        if cme_premium_deployment_yaml_mvs.exists() {
            let emsg = format!("couldn't remove {:?}", &cme_premium_deployment_yaml_mvs);
            std::fs::remove_file(cme_premium_deployment_yaml_mvs).expect(&emsg[..]);
        }
    }

    let network_yaml = std::path::Path::new(&ws_dir)
        .join("ansible-inventories/craystack/group_vars/all/networks.yml");
    let network_mvs_yaml = std::path::Path::new(&ws_dir)
        .join("ansible-inventories/craystack/group_vars/all/networks.yml.mvs");

    let net_estr = format!("couldn't read {:?}", &network_yaml);
    let network_yaml_contents = std::fs::read_to_string(network_yaml).expect(&net_estr[..]);

    if let Ok(mut content) = serde_yaml::from_str::<serde_yaml::Value>(&network_yaml_contents[..]) {
        let nip = ipaddress::IPAddress::parse(tf_vals.node_cidr.cidr.clone())
            .expect("can't parse node management network cidr");
        content["networks"]["node_management"]["netmask"] =
            serde_yaml::Value::String(nip.netmask().to_s());
        content["networks"]["node_management"]["network"] =
            serde_yaml::Value::String(nip.network().to_s());
        let cip = ipaddress::IPAddress::parse(tf_vals.cust_cidr.cidr)
            .expect("can't parse customer management network cidr");
        content["networks"]["customer_management"]["netmask"] =
            serde_yaml::Value::String(cip.netmask().to_s());
        content["networks"]["customer_management"]["network"] =
            serde_yaml::Value::String(cip.network().to_s());

        if matches.is_present("with-macvlan") {
            // Setup uai_macvlan_bridge_* entries manually Ref: CASMUSER-1605
            content["networks"]["node_management"]["uai_macvlan_bridge_route"] =
                serde_yaml::Value::String(tf_vals.node_cidr.cidr);

            // Get the upper /25 (prolly) subnet and use that, take first ip
            // as the "bridge ip", kinda like a real route, then use
            // second ip above that as start, and the high usable as end.
            if let Ok(net) = nip.network().split(2) {
                let last_ips = &net[1];
                let ips = Arc::new(Mutex::new(Vec::new()));
                last_ips.each(|i| ips.lock().unwrap().push(i.to_s()));
                let all_ips = ips.lock().unwrap().deref().clone();
                // yes i could make the ipaddress lib do it, but whatever one off hack...
                let bridge = format!("{}/32", all_ips[1]);
                let start = all_ips[2].clone();
                let end = all_ips[(all_ips.len() - 2)].clone();
                content["networks"]["node_management"]["uai_macvlan_bridge_ip"] =
                    serde_yaml::Value::String(bridge);
                content["networks"]["node_management"]["uai_macvlan_range_start"] =
                    serde_yaml::Value::String(start);
                content["networks"]["node_management"]["uai_macvlan_range_end"] =
                    serde_yaml::Value::String(end);
            } else {
                eprintln!(
                    "input network {:?} couldn't be split in half",
                    nip.network()
                );
                std::process::exit(1);
            }
        }

        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&network_mvs_yaml)
        {
            Ok(f) => {
                serde_yaml::to_writer(f, &content).expect("error writing networks.yml.mvs file");
            }
            Err(e) => {
                eprintln!("error writing to file {:?} {}", network_mvs_yaml, e);
            }
        }
    }

    let main_yaml = std::path::Path::new(&ws_dir)
        .join("kubernetes-installer/roles/kubernetes_dev_setup/defaults/main.yml");
    let mvs_yaml = std::path::Path::new(&ws_dir)
        .join("kubernetes-installer/roles/kubernetes_dev_setup/defaults/main.yml.mvs");
    let k8s_main_yaml = std::fs::read_to_string(main_yaml).expect("couldn't read main.yml file");
    let k8s_config = serde_yaml::from_str::<K8sdefaults>(&k8s_main_yaml);

    if let Ok(_config) = k8s_config {
        let mut hosts: Vec<Host> = Vec::new();
        let mut smss: Vec<Host> = Vec::new();
        let mut k8s_name = String::new();

        let mut tf = std::process::Command::new("terraform");
        let tf_config = tf.arg("output").arg("--json").output();
        let tf_config_s = tf_config.expect("terraform output couldn't be had");

        let tf_vals = serde_json::from_str::<TfConfig>(
            &String::from_utf8(tf_config_s.stdout.clone()).expect("terraform output broken?"),
        )
        .expect("can't parse terraform output --json");

        let mut tld = String::new();

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(
            &String::from_utf8(tf_config_s.stdout).unwrap(),
        ) {
            if let Some(sms) = json["remote_ansible_hosts"].as_object() {
                if let Some(values) = sms["value"].as_object() {
                    for (k, v) in values {
                        if let Some(host) = extract_hostname(k) {
                            if v.is_string() {
                                let hostname = format!("{}-cmn", host);
                                let ip = v.as_str().unwrap().to_string();
                                hosts.push(Host {
                                    hostname: hostname.clone(),
                                    ip_address: ip.clone(),
                                });
                                smss.push(Host {
                                    hostname: host.to_string(),
                                    ip_address: ip,
                                });
                            }
                        }
                    }
                }
            }
            if let Some(tlds) = json["full_tld"].as_object() {
                for (k, v) in tlds {
                    if k == "value" && v.is_string() {
                        tld = format!("{}", v.as_str().unwrap().to_string());
                        k8s_name = format!("sms.{}", tld);
                    }
                }
            }
            if let Some(cmn_ip_map) = json["cmn_ip_map"].as_object() {
                if let Some(values) = cmn_ip_map["value"].as_object() {
                    for (k, v) in values {
                        if let Some(host) = extract_hostname(k) {
                            if v.is_string() {
                                let hostname = format!("{}-cmn", host);
                                let ip = v.as_str().unwrap().to_string();
                                hosts.push(Host {
                                    hostname: hostname.clone(),
                                    ip_address: ip.clone(),
                                });
                            }
                        }
                    }
                }
                if let Some(values) = cmn_ip_map["value"].as_object() {
                    for (k, v) in values {
                        if let Some(host) = extract_hostname(k) {
                            if v.is_string() {
                                let hostname = format!("{}-cmn", host);
                                let ip = v.as_str().unwrap().to_string();
                                hosts.push(Host {
                                    hostname: hostname.clone(),
                                    ip_address: ip.clone(),
                                });
                            }
                        }
                    }
                }
                if let Some(nmn_ip_map) = json["nmn_ip_map"].as_object() {
                    if let Some(values) = nmn_ip_map["value"].as_object() {
                        for (k, v) in values {
                            if let Some(host) = extract_hostname(k) {
                                if v.is_string() {
                                    let hostname = format!("{}-nmn", host);
                                    let ip = v.as_str().unwrap().to_string();
                                    hosts.push(Host {
                                        hostname: hostname,
                                        ip_address: ip,
                                    });
                                }
                            }
                        }
                    }
                }
                if let Some(hsn_ip_map) = json["hsn_ip_map"].as_object() {
                    if let Some(values) = hsn_ip_map["value"].as_object() {
                        for (k, v) in values {
                            if let Some(host) = extract_hostname(k) {
                                if v.is_string() {
                                    let hostname = format!("{}-hsn", host);
                                    let ip = v.as_str().unwrap().to_string();
                                    hosts.push(Host {
                                        hostname: hostname,
                                        ip_address: ip,
                                    });
                                }
                            }
                        }
                    }
                }
                if let Some(hmn_ip_map) = json["hmn_ip_map"].as_object() {
                    if let Some(values) = hmn_ip_map["value"].as_object() {
                        for (k, v) in values {
                            if let Some(host) = extract_hostname(k) {
                                if v.is_string() {
                                    let hostname = format!("{}-hmn", host);
                                    let ip = v.as_str().unwrap().to_string();
                                    hosts.push(Host {
                                        hostname: hostname,
                                        ip_address: ip,
                                    });
                                }
                            }
                        }
                    }
                }

                // if let Some(cmn_uuids) = json["cmn_uuids"].as_object() {
                //     if let Some(values) = cmn_uuids["value"].as_object() {
                //         println!("cmn_uuids");
                //         for (k, v) in values {
                //             if v.is_string() {
                //                 println!("{} = {}", k, v.as_str().unwrap());
                //             }
                //         }
                //     }
                // }
            }
        }

        let mvs_config = K8sdefaults {
            name: k8s_name,
            hosts: Some(hosts.clone()),
        };

        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&mvs_yaml)
        {
            Ok(f) => {
                serde_yaml::to_writer(f, &mvs_config).expect("error writing down k8s default file");
            }
            Err(e) => {
                eprintln!("error writing to file {:?} {}", mvs_yaml, e);
            }
        }

        let mvs_ini =
            std::path::Path::new(&ws_dir).join("ansible-inventories/craystack/inventory.ini.mvs");
        let mut ini_data = String::new();

        let masters = tf_vals
            .masters
            .name
            .parse::<usize>()
            .expect("terraform value for sms_master_count isn't a number");
        let workers = tf_vals
            .workers
            .name
            .parse::<usize>()
            .expect("terraform value for sms_worker_count isn't a number");

        ini_data.push_str("# mvs generated inventory file begin\n\n");
        ini_data.push_str("# bare hosts are the same as the master nodes\n");

        for host in &smss[0..masters] {
            ini_data.push_str(&format!("{}.{}\n", host.hostname, tld)[..]);
        }

        ini_data.push_str("\n# master sms nodes\n");

        ini_data.push_str("[master_nodes]\n");
        for host in &smss[0..masters] {
            ini_data.push_str(&format!("{}.{}\n", host.hostname, tld)[..]);
        }
        ini_data.push_str(&format!("\n[managers:children]\nmaster_nodes\n")[..]);

        if workers > 0 {
            ini_data.push_str("\n# worker sms nodes\n");
            ini_data.push_str("[worker_nodes]\n");
            for host in &smss[masters..(masters + workers)] {
                ini_data.push_str(&format!("{}.{}\n", host.hostname, tld)[..]);
            }
            ini_data.push_str(&format!("\n[workers:children]\nworker_nodes\n")[..]);
        }

        ini_data.push_str("\n[sms:children]\n");
        ini_data.push_str("master_nodes\n");

        if workers > 0 {
            ini_data.push_str("worker_nodes\n");
        }

        ini_data.push_str("\n[bis]\n\n");
        ini_data.push_str("# mvs generated inventory file end\n");

        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&mvs_ini)
        {
            Ok(mut f) => {
                f.write_all(ini_data.as_bytes())
                    .expect("can't write data to ini file");
            }
            Err(e) => {
                eprintln!("error writing to file {:?} {}", mvs_ini, e);
            }
        }

        let kongtroller_yaml_mvs = std::path::Path::new(&ws_dir)
            .join("ansible-inventories/craystack/group_vars/all/kongtroller.yml.mvs");

        // By default add the extra issuer, unless someone asks us not to write it
        if !matches.is_present("without-issuer") {
            if smss.len() < 1 {
                eprintln!("could not find an sms to add to kong issuers");
                std::process::exit(1);
            }
            let sms_host_zero = format!("{}.{}", &smss[0].hostname, tld);
            let kong_data = KongExtra {
                issuers: vec![sms_host_zero],
            };

            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&kongtroller_yaml_mvs)
            {
                Ok(f) => {
                    serde_yaml::to_writer(f, &kong_data)
                        .expect("error writing kongtroller.yml.mvs file");
                }
                Err(e) => {
                    eprintln!(
                        "error writing to file {:?} {}",
                        kongtroller_yaml_mvs.to_str(),
                        e
                    );
                }
            }
        } else {
            if kongtroller_yaml_mvs.exists() {
                let emsg = format!("couldn't remove {:?}", &kongtroller_yaml_mvs);
                std::fs::remove_file(kongtroller_yaml_mvs).expect(&emsg[..]);
            }
        }

        if matches.is_present("debug-edits") {
            eprintln!("stopping for debug");
            std::process::exit(0);
        }

        let ssh_dest = format!("root@{}", &tf_vals.rsync_target_ip.name);
        let rsync_dest = format!("root@{}:{}", &tf_vals.rsync_target_ip.name, prefix);
        let ssh_key_ident = format!("IdentityFile={}", &ssh_key_file);
        let ssh_opts = [
            "-o",
            &ssh_key_ident[..],
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=QUIET",
        ];
        let ssh_rsync = format!("ssh {}", ssh_opts.join(" "));

        let ws_dir_str = format!("{}/", &ws_dir.to_str().unwrap());
        let rsync_opts = [
            "-e",
            &ssh_rsync,
            "--checksum",
            "--delete",
            "--delete-before",
            "--exclude=.git",
            "-avzH",
            &ws_dir_str[..],
            &rsync_dest[..],
        ];
        let rsync_out = format!(
            "rsync {}",
            &[
                "--checksum",
                "--delete",
                "--delete-before",
                "--exclude=.git",
                "-avzH",
                &ws_dir_str[..],
                &rsync_dest[..]
            ]
            .join(" ")
        );
        let _ = run_command(
            "rsync",
            &rsync_opts,
            RunArgs {
                verbose: verbose,
                hardfail: true,
                display: Some(rsync_out),
                ..RunArgs::default()
            },
        );

        // If this fails, the playbook won't run anyway...
        // exit 0 in the case where cp complains about the files being the same
        let ssh_mv = format!(
            "find {} -type f -name '?*.mvs' | sed 'p;s/\\.mvs//' | xargs -n2 -t cp; exit 0",
            prefix
        );

        let mut ssh_cmd_opts_mv = Vec::new();
        let mut ssh_opts_v_mv = ssh_opts.to_vec();
        ssh_cmd_opts_mv.append(&mut ssh_opts_v_mv);
        ssh_cmd_opts_mv.append(&mut [&ssh_dest[..], &ssh_mv[..]].to_vec());
        let ssh_out_mv = format!("ssh {} \"{}\"", ssh_dest, ssh_mv);

        let _ = run_command(
            "ssh",
            &ssh_cmd_opts_mv,
            RunArgs {
                verbose: verbose,
                hardfail: true,
                display: Some(ssh_out_mv),
                ..RunArgs::default()
            },
        );

        let single_play = matches.value_of("playbook").unwrap_or("");

        let without_commits =
            serde_yaml::to_string(&this).expect("could't serialize svm.yml config?");

        // For single plays don't save commits
        if single_play == "" {
            for repo in &mut this.repositories {
                if let Some(name) = &repo.name {
                    if name != "cms-base-box" {
                        let mut git_dir = ws_dir.clone();
                        git_dir.push(&name[..]);
                        let commit = std::process::Command::new("git")
                            .args(&["rev-parse", "HEAD"])
                            .current_dir(git_dir)
                            .output();
                        if let Ok(sha) = commit {
                            repo.commit = Some(
                                String::from_utf8_lossy(&sha.stdout)
                                    .to_string()
                                    .replace("\n", ""),
                            );
                        } // else what? fail?
                    }
                }
            }
        }

        let with_commits = serde_yaml::to_string(&this).expect("couldn't serialize config data");
        let mut svm_yaml = PathBuf::from("svm.yml");
        if let Some(yaml) = matches.value_of("yaml") {
            if let Ok(path) = std::fs::canonicalize(PathBuf::from(&yaml[..])) {
                svm_yaml = path;
            }
        }

        // Note, serde by default serializes None values into ~ this is valid per the yaml spec for null
        // https://yaml.org/spec/1.2/spec.html#id2805071
        // null == ~ in yaml specification

        let base_yml = &svm_yaml
            .parent()
            .expect("couldn't get parent dir for svm.yml file for base.yml");
        let mut base = std::fs::File::create(base_yml.join("base.yml"))
            .expect("couldn't create base.yml file");
        base.write_all(without_commits.as_bytes())
            .expect("couldn't write to base.yml file");
        let tmp_yml = svm_yaml
            .parent()
            .expect("couldn't get parent dir for svm.yml file for tmp.yml");
        let mut tmp =
            std::fs::File::create(tmp_yml.join("tmp.yml")).expect("couldn't create tmp.yml file");
        tmp.write_all(with_commits.as_bytes())
            .expect("couldn't write to tmp.yml file");

        for playbook in this.playbooks {
            let repo = playbook.repository.unwrap().clone();

            let mut run = true;

            if single_play != "" && repo != single_play {
                run = false;
            }

            if run {
                let file = playbook.file.unwrap().clone();
                let mut extra = String::new();

                // Not gonna lie, this is suuuuper annoying amounts of boilerplate
                // serde flatten is... ok I guess?
                if let Some(thing) = playbook.extras.get("extra_vars") {
                    if thing.is_mapping() {
                        if let Some(map) = thing.as_mapping() {
                            for (k, v) in map {
                                if let Some(value) = v.as_str() {
                                    if let Some(key) = k.as_str() {
                                        extra = format!("{} -e {}={}", extra, key, value);
                                    }
                                }
                            }
                        }
                    }
                }

                let ssh_cmd = format!(
                    "cd {}/{} && ansible-playbook -vv {} -i {}/ansible-inventories/craystack/inventory.ini {}",
                    prefix, repo, extra, prefix, file
                );
                let mut ssh_cmd_opts = Vec::new();
                let mut ssh_opts_v = ssh_opts.to_vec();
                ssh_cmd_opts.append(&mut ssh_opts_v);
                ssh_cmd_opts.append(&mut [&ssh_dest[..], &ssh_cmd[..]].to_vec());
                let ssh_out = format!(
                    "running playbook {} repo {} on host {} ",
                    file, repo, tf_vals.rsync_target_ip.name
                );

                let _ = run_command(
                    "ssh",
                    &ssh_cmd_opts,
                    RunArgs {
                        verbose: verbose,
                        hardfail: true,
                        display: Some(ssh_out),
                        onfail: rename_fail_file,
                        ..RunArgs::default()
                    },
                );
            }
        }
    }

    std::fs::rename("tmp.yml", "good.yml").expect("couldn't rename tmp.yml");

    if matches.is_present("cds-release-bundle") {
        let uri = matches.value_of("cds-release-bundle").unwrap_or("");

        let ssh_key_ident = format!("IdentityFile={}", &ssh_key_file);
        let ssh_opts = [
            "-o",
            &ssh_key_ident[..],
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=QUIET",
        ];

        // Get the bundle onto sms-01.

        let ssh_cmd = format!("/work/cds-release-bundle/mvs/install_bundle.sh -B {}", uri);
        let ssh_dest = format!("root@{}", &tf_vals.rsync_target_ip.name);
        let mut ssh_cmd_opts = Vec::new();
        let mut ssh_opts_v = ssh_opts.to_vec();
        ssh_cmd_opts.append(&mut ssh_opts_v);
        ssh_cmd_opts.append(&mut [&ssh_dest[..], &ssh_cmd[..]].to_vec());
        let ssh_out = format!(
            "running install_bundle.sh -B {} on host {} ",
            uri, tf_vals.rsync_target_ip.name
        );

        let _ = run_command(
            "ssh",
            &ssh_cmd_opts,
            RunArgs {
                verbose: verbose,
                hardfail: true,
                display: Some(ssh_out),
                onfail: rename_fail_file,
                ..RunArgs::default()
            },
        );
    }

    Ok(())
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
struct DevSetup {
    #[serde(rename = "dev_setup_cluster_name")]
    clustername: String,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
struct Dnsmasq {
    #[serde(rename = "dnsmasq_extra_local_domains")]
    domains: Vec<String>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
struct Host {
    #[serde(rename = "ip")]
    ip_address: String,

    #[serde(rename = "name")]
    hostname: String,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
struct K8sdefaults {
    #[serde(rename = "dev_setup_cluster_name")]
    name: String,

    #[serde(rename = "dev_setup_extra_hosts")]
    hosts: Option<Vec<Host>>,
}

fn run_status(_matches: &ArgMatches, _cwd: &PathBuf, _yaml: &PathBuf) -> Result<(), String> {
    eprintln!("Getting openstack server status...");
    let servers = os_servers();
    for s in &servers {
        let ss = "sms";
        let lus = "lustre";
        let server_name = format!("{}", s.name());
        if server_name.contains(ss) || server_name.contains(lus) {
            println!(
                "ID = {}, Name = {}, Status = {:?}, State = {:?}",
                s.id(),
                s.name(),
                s.status(),
                s.power_state()
            );
        } else {
            eprintln!("Skipping vm {} name: {}", s.id(), s.name());
        }
    }

    Ok(())
}

fn tf_workspace(tf_workspace: &str) -> () {
    let mut tf = std::process::Command::new("terraform");
    let tf_workspace_show = tf
        .args(&["workspace", "show"])
        .output()
        .expect("terraform workspace show didn't work");

    let tf_ws_s_stdout = String::from_utf8_lossy(&tf_workspace_show.stdout);

    let tf_ws_s = format!("{}\n", tf_workspace);

    if tf_ws_s_stdout != tf_ws_s {
        let mut tf = std::process::Command::new("terraform");
        let tf_workspace_list = tf
            .args(&["workspace", "list"])
            .output()
            .expect("terraform workspace list didn't work");
        let tf_ws_l_stdout = String::from_utf8_lossy(&tf_workspace_list.stdout);
        if tf_ws_l_stdout.contains(tf_workspace) {
            let mut tf = std::process::Command::new("terraform");
            let _tf_workspace_select = tf
                .args(&["workspace", "select", tf_workspace])
                .output()
                .expect("terraform workspace select didn't work");
        } else {
            let mut tf = std::process::Command::new("terraform");
            let _tf_workspace_new = tf
                .args(&["workspace", "new", tf_workspace])
                .output()
                .expect("terraform workspace new didn't work");
        }
    }
}

fn run_up(matches: &ArgMatches, _cwd: &PathBuf, _yaml: &PathBuf) -> Result<(), String> {
    let verbose = matches.is_present("verbose");
    let tf_ws = matches.value_of("workspace").unwrap_or("default");

    tf_workspace(&tf_ws);
    tf_prereqs();
    return run_command(
        "terraform",
        &["apply", "--auto-approve"],
        RunArgs {
            verbose: verbose,
            hardfail: true,
            ..RunArgs::default()
        },
    );
}

fn run_down(matches: &ArgMatches, _cwd: &PathBuf, _yaml: &PathBuf) -> Result<(), String> {
    let verbose = matches.is_present("verbose");
    let tf_ws = matches.value_of("workspace").unwrap_or("default");

    tf_workspace(&tf_ws);
    tf_prereqs();

    return run_command(
        "terraform",
        &["destroy", "--auto-approve"],
        RunArgs {
            verbose: verbose,
            ..RunArgs::default()
        },
    );
}

fn run_verify(matches: &ArgMatches, _cwd: &PathBuf, _yaml: &PathBuf) -> Result<(), String> {
    let os = openstack::Cloud::from_env()
        .expect("Failed to create an identity provider from the environment");

    let tf_ws = matches.value_of("workspace").unwrap_or("default");
    tf_workspace(&tf_ws);
    eprintln!("Validating openstack servers are setup and running...");

    let servers = os_servers();
    for s in &servers {
        let ss = "sms";
        let server_name = format!("{}", s.name());
        if server_name.contains(ss) {
            if s.status() == openstack::compute::ServerStatus::ShutOff {
                eprintln!("Powering up compute instance id {}", s.id());
                let mut server = os
                    .get_server(s.id())
                    .expect("Cannot get a server to poweron");
                server
                    .start()
                    .expect("Cannot power on the server!")
                    .wait()
                    .expect("Server failed to reach ACTIVE state on powerup");
                eprintln!("Poweron seems to have been accepted by openstack");
            } else {
                eprintln!(
                    "Looks ok: ID = {}, Name = {}, Status = {:?}, State = {:?}",
                    s.id(),
                    s.name(),
                    s.status(),
                    s.power_state()
                );
            }
        } else {
            eprintln!("Skipping vm {} name: {}", s.id(), s.name());
        }
    }

    let _ignored = run_command(
        "terraform",
        &["plan"],
        RunArgs {
            hardfail: true,
            ..RunArgs::default()
        },
    );

    Ok(())
}

fn apply_patch(patchfile: &PathBuf, patchdir: &PathBuf, verbose: bool) {
    let osdir = patchdir.clone().into_os_string();
    let ospatch = patchfile.clone().into_os_string();
    let dir = osdir
        .into_string()
        .expect("couldn't convert patch dir to a string? bummer");
    let file = ospatch
        .into_string()
        .expect("couldn't convert patch file to a string? bummer");

    let filepath;

    if let Ok(fullfilepath) = std::fs::canonicalize(PathBuf::from(&file[..])) {
        let tmp = fullfilepath.into_os_string();
        let fstr = tmp
            .into_string()
            .expect("couldn't convert full file path into string?");
        filepath = fstr;
    } else {
        eprintln!("couldn't canonicalize patch file path: {:?}", &patchfile);
        std::process::exit(1);
    }

    // Due to using -f with patch, we need to do a dry-run of the patch file
    // first to see if its already applied, only then do we try to apply the
    // patch file.

    // That means, if the dry run fails, there isn't a reversed patch already
    // applied and we can then apply our patch and have that command fail.
    //
    // If the dry run succeeds, don't patch.
    //
    // Looks like this in shell (much simpler invocation of patch)
    // if ! patch -R -p0 -s -f --dry-run <patchfile; then
    //   patch -p0 <patchfile
    // fi

    // Since this command is only to know if we apply things or not, run it
    // without any wrapper shenanigans. Should make the wrapper return
    // useful information some day.
    let mut applied = false;

    if let Ok(result) = std::process::Command::new("patch")
        .args(&[
            "-R",
            "-f",
            "-p1",
            "-s",
            "--dry-run",
            "-d",
            &dir[..],
            "-i",
            &filepath[..],
        ])
        .output()
    {
        if result.status.success() {
            applied = true;
        }
    }

    if !applied {
        let _ = run_command(
            "patch",
            &["-f", "-p1", "-d", &dir[..], "-i", &filepath[..]],
            RunArgs {
                verbose: verbose,
                hardfail: true,
                ..RunArgs::default()
            },
        );
    }
}

fn run_cleanup(_matches: &ArgMatches, _cwd: &PathBuf, _yaml: &PathBuf) -> Result<(), String> {
    let os = openstack::Cloud::from_env()
        .expect("Failed to create an identity provider from the environment");

    let servers = os_servers();

    if servers.len() > 0 {
        eprintln!("deleting {} servers", servers.len());

        for s in &servers {
            let server_name = format!("{}", s.name());
            eprintln!(
                "deleting compute instance id {} name {}",
                s.id(),
                server_name
            );
            let server = os
                .get_server(s.id())
                .expect("cannot get a server to delete");
            server.delete().expect("cannot delete server");
        }
    } else {
        eprintln!("no servers to delete");
    }

    let ports: Vec<_> = os
        .find_ports()
        .into_iter()
        .collect()
        .expect("cannot list ports");

    if ports.len() > 0 {
        eprintln!("deleting {} ports", ports.len());
        for p in &ports {
            let someport = os.get_port(p.id());
            if let Ok(port) = someport.clone() {
                eprintln!(
                    "deleting port id {} name {}",
                    port.id(),
                    p.name().clone().unwrap_or("unknown".to_string())
                );
                port.delete().expect("cannot delete port");
            }
            if let Err(e) = someport {
                eprintln!("note: couldn't delete port for reasons: {:?}", e);
            }
        }
    } else {
        eprintln!("no ports to delete");
    }

    let networks: Vec<openstack::network::Network> = os
        .find_networks()
        .into_iter()
        .collect()
        .expect("cannot list networks");

    // Cray_Network always shows up
    if networks.len() > 1 {
        eprintln!("deleting {} networks", networks.len());
        for n in &networks {
            let network = os
                .get_network(n.id())
                .expect("cannot get a network to delete");
            if network.name().clone().unwrap_or("unknown".to_string()) != "Cray_Network" {
                eprintln!(
                    "deleting network id {} name {}",
                    network.id(),
                    n.name().clone().unwrap_or("unknown".to_string())
                );
                network.delete().expect("cannot delete network");
            }
        }
    } else {
        eprintln!("no networks to delete");
    }
    Ok(())
}

fn default_yaml_file() -> String {
    let pwd = std::env::current_dir().expect("can't get cwd");
    let yaml = format!("{}/svm.yml", pwd.display());
    return yaml;
}

fn get_yaml_path(user_yaml: Option<&str>) -> PathBuf {
    let yaml = default_yaml_file();

    let ayaml = user_yaml.unwrap_or(&yaml[..]);
    let pyaml = std::path::PathBuf::from(&ayaml);
    let out = absolute_path(&pyaml).expect("Can't expand path");
    return out;
}

fn default_ssh_file() -> String {
    let home =
        dirs::home_dir().expect("cannot determine home directory or no $HOME env var present");
    let id_rsa = format!("{}/.ssh/id_rsa", home.to_string_lossy());
    return id_rsa;
}

fn get_ssh_file(sshkey: Option<&str>) -> String {
    let id_rsa = default_ssh_file();

    let ssh_key = sshkey.unwrap_or(&id_rsa[..]);
    let ssh_key_file_path = std::path::Path::new(&ssh_key[..])
        .canonicalize()
        .expect("Cannot expand ssh key to a full path");
    let _ssh_key_file = ssh_key_file_path
        .to_str()
        .expect("ssh key file can't be converted to a string");

    let value = ssh_key_file_path.into_os_string().into_string().unwrap();
    return value;
}

fn validate_env() {
    // Make sure that OS_ vars are present so that terraform can/will work

    let mut token = false;
    let mut tokens = 0;
    let mut pass = false;
    let mut passs = 0;

    let token_env = vec![
        "OS_AUTH_URL".to_string(),
        "OS_PROJECT_DOMAIN_ID".to_string(),
        "OS_REGION_NAME".to_string(),
        "OS_INTERFACE".to_string(),
        "OS_IDENTITY_API_VERSION".to_string(),
        "OS_TOKEN".to_string(),
        "OS_PROJECT_ID".to_string(),
        "OS_AUTH_TYPE".to_string(),
    ];

    let pass_env = vec![
        "OS_AUTH_URL".to_string(),
        "OS_PROJECT_ID".to_string(),
        "OS_PROJECT_NAME".to_string(),
        "OS_USERNAME".to_string(),
        "OS_PASSWORD".to_string(),
        "OS_REGION_NAME".to_string(),
        "OS_INTERFACE".to_string(),
        "OS_IDENTITY_API_VERSION".to_string(),
    ];
    // Token based env
    for (key, _value) in std::env::vars_os() {
        if let Ok(k) = key.into_string() {
            if token_env.contains(&k) {
                tokens = tokens + 1;
            }
        }
    }
    // regular env
    for (key, _value) in std::env::vars_os() {
        if let Ok(k) = key.into_string() {
            if pass_env.contains(&k) {
                passs = passs + 1;
            }
        }
    }

    if tokens == token_env.len() {
        token = true;
    }

    if passs == pass_env.len() {
        pass = true;
    }

    if !(pass || token) {
        eprintln!("openstack environment not present! terraform will not be able to run!");
        eprintln!("source bin/craystack_token.sh and then run os_token $USER");
        eprintln!(
            "you should end up with the following env vars:\n{}",
            token_env.join(", ")
        );
        eprintln!("or use an openrc v3 file from openstack before running");
        eprintln!(
            "you should end up with the following env vars:\n{}",
            pass_env.join(", ")
        );
        std::process::exit(1);
    }
}

// TODO: finish me
// // Just does the i/o of loading the key file
// fn validate_ssh_key_file(file: PathBuf) -> Result<(), String> {
//     if file.exists() {
//         if let Ok(content) = std::fs::read_to_string(&file) {
//             if validate_ssh_key_lacks_passphrase(content) {
//                 return Ok(())
//             } else {
//                 return Err("ssh key has a passphrase, generate a new ssh key via ssh-keygen and pass that key in for use")
//             }
//         }
//     }
//     Err("ssh key file input isn't valid")
// }

// fn validate_ssh_key_lacks_passphrase(key: String) -> bool {
//     if key.contains("ENCRYPTED") {
//         return false;
//     }
//     return true
// }

fn validate_runtime() {
    let patch = std::process::Command::new("patch")
        .arg("-v")
        .output()
        .expect("patch -v didn't work, is patch installed?");
    if !patch.status.success() {
        eprintln!("can't find patch in PATH, mvs cannot work without patch");
        std::process::exit(1);
    }
    let git = std::process::Command::new("git")
        .arg("--version")
        .output()
        .expect("git --version didn't work, is git installed?");
    if !git.status.success() {
        eprintln!("can't find git in PATH, mvs cannot work without git");
        std::process::exit(1);
    }
    let git_lfs = std::process::Command::new("git")
        .args(&["lfs", "version"])
        .output()
        .expect("git lfs version didn't work, is git-lfs installed?");
    if !git_lfs.status.success() {
        eprintln!("can't find git lfs in PATH, mvs cannot work without git lfs. ref: https://git-lfs.github.com");
        std::process::exit(1);
    }
    let git_config_list = std::process::Command::new("git")
        .args(&["config", "--list"])
        .output()
        .expect("git config --list didn't work, is git installed?");
    if !git_config_list.status.success() {
        eprintln!("git config --list didn't return a 0 exit code, is your .gitconfig valid?");
        std::process::exit(1);
    }
    let terraform = std::process::Command::new("terraform").arg("-v").output();
    if let Err(_) = terraform {
        eprintln!("can't find terraform in PATH, mvs cannot work without terraform. ref: https://www.terraform.io");
        std::process::exit(1);
    }
    // We're looking for these 4 lines to be present
    // $ git config --list | grep filter
    // filter.lfs.clean=git-lfs clean -- %f
    // filter.lfs.smudge=git-lfs smudge -- %f
    // filter.lfs.process=git-lfs filter-process
    // filter.lfs.required=true
    if let Ok(result) = String::from_utf8(git_config_list.stdout) {
        let result_s = format!("{}", result);
        if !(result_s.contains("filter.lfs.clean=git-lfs clean -- %f")
            && result_s.contains("filter.lfs.smudge=git-lfs smudge -- %f")
            && result_s.contains("filter.lfs.process=git-lfs filter-process")
            && result_s.contains("filter.lfs.required=true"))
        {
            eprintln!("can't find git lfs filter lines in git config --list, did you run git lfs install?");
            std::process::exit(1);
        }
    }
    return;
}

fn main() {
    let id_rsa = default_ssh_file();

    let ver = "1.1.0";

    let mvs_version_info = format!(
        "{} arch {} built on {} commit {}",
        ver,
        env!("VERGEN_TARGET_TRIPLE"),
        env!("VERGEN_BUILD_TIMESTAMP"),
        env!("VERGEN_SHA_SHORT")
    );
    let vinfostr = &mvs_version_info[..];
    let matches = App::new("mvs")
        .version(vinfostr)
        .setting(clap::AppSettings::TrailingVarArg)
        .setting(clap::AppSettings::UnifiedHelpMessage)
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .about("sms/name of the week automation tool, mvs as its svm backwards")
        .author("Mitch Tishmack <mitch.tishmack@cray.com>")
        .arg(
            Arg::with_name("yaml")
                .short("y")
                .long("yaml")
                .global(true)
                .help("yaml config file to use")
                .default_value("svm.yml")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .global(true)
                .help("don't log command output to a cmd.log file but dump it to stdout"),
        )
        .arg(
            Arg::with_name("workspace")
                .short("w")
                .long("workspace")
                .global(true)
                .help("terraform workspace to use")
                .default_value("default")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("dir")
                .long("dir")
                .global(true)
                .help("directory to checkout repos to")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("depth")
                .long("depth")
                .global(true)
                .help("set default git checkout depth for every git checkout")
                .takes_value(true)
                .validator(|p| match p.parse::<usize>() {
                    Err(_) => Err(String::from("not an integer")),
                    Ok(_) => Ok(()),
                })
        )
        .arg(
            Arg::with_name("sshkey")
                .short("s")
                .long("sshkey")
                .global(true)
                .help("ssh identity key file to use")
                .default_value(&id_rsa[..])
                .takes_value(true),
        )
        .arg(
            Arg::with_name("checkout-only")
                .long("checkout-only")
                .global(true)
                .help("only git checkout at the provision step")
                .conflicts_with("skip-checkout"),
        )
        .arg(
            Arg::with_name("skip-checkout")
                .long("skip-checkout")
                .global(true)
                .help("skip any checkout steps, useful if checkout-only was used before")
                .conflicts_with("checkout-only"),
        )
        .arg(
            Arg::with_name("increment")
                .short("i")
                .long("increment")
                .global(true)
                .help("specify test increment option for ct-driver")
                .takes_value(true)
                .default_value("smoke")
                .possible_values(&["smoke", "functional", "long", "destructive"]),
        )
        .arg(
            Arg::with_name("blacklist")
                .long("blacklist")
                .global(true)
                .help("blacklist a single test from running")
                .takes_value(false)
                .multiple(true)
                .min_values(1)
        )
        .arg(
            Arg::with_name("patch")
                .long("patch")
                .global(true)
                .help("try to apply a patch after checking out source")
                .takes_value(false)
                .multiple(true)
                .min_values(1)
        )
        .arg(
            Arg::with_name("compute-nodes")
                .long("compute-nodes")
                .global(true)
                .help("default number of compute nodes to build")
                .takes_value(true)
                .default_value("0")
                .validator(|p| match p.parse::<usize>() {
                    Err(_) => Err(String::from("not an integer")),
                    Ok(_) => Ok(()),
                })
        )
        .arg(
            Arg::with_name("sms-masters")
                .long("sms-masters")
                .global(true)
                .help("how many sms master nodes to allocate")
                .takes_value(true)
                .default_value("3")
                .validator(|p| match p.parse::<usize>() {
                    Err(_) => Err(String::from("not an integer")),
                    Ok(_) => Ok(()),
                })
        )
        .arg(
            Arg::with_name("sms-workers")
                .long("sms-workers")
                .global(true)
                .help("how many sms worker nodes to allocate")
                .takes_value(true)
                .default_value("0")
                .validator(|p| match p.parse::<usize>() {
                    Err(_) => Err(String::from("not an integer")),
                    Ok(_) => Ok(()),
                })
        )
        .arg(
            Arg::with_name("with-domain")
                .long("with-domain")
                .global(true)
                .help("domain name to use")
                .takes_value(true)
                .default_value("craystack.test")
        )
        .arg(
            Arg::with_name("without-ct")
                .long("without-ct")
                .global(true)
                .help("don't run ct-test functionality when the test function is called"),
        )
        .arg(
            Arg::with_name("with-lustre")
                .long("with-lustre")
                .short("l")
                .global(true)
                .help("build with a lustre server, default is to not build a lustre server"),
        )
        .arg(
            Arg::with_name("without-loftsman")
                .long("without-loftsman")
                .global(true)
                .help(
                    "build without loftsman enabled, unlikely you will ever want this unless testing",
                ),
        )
        .arg(
            Arg::with_name("without-cps")
                .long("without-cps")
                .global(true)
                .help("build without cps enabled, unlikely you will ever want this unless testing"),
        )
        .arg(
            Arg::with_name("without-issuer")
                .long("without-issuer")
                .global(true)
                .help("do not add sms1 to the default kong issuers, unlikely you will ever want this unless testing"),
        )
        .arg(
            Arg::with_name("with-macvlan")
                .long("with-macvlan")
                .global(true)
                .help("compute a network subnet to allocate to macvlan setup, unlikely you will ever want this unless testing"),
        )
        .arg(
            Arg::with_name("debug-edits")
                .long("debug-edits")
                .global(true)
                .help("only applicable to provisioning, halt provisioning after all file edits are made"),
        )
        .arg(
            Arg::with_name("kernel-server-uri")
                .long("kernel-server-uri")
                .global(true)
                .help("for centos kernel uri to use for a custom yum repo to install")
                .default_value(
                    "http://car.dev.cray.com/artifactory/internal/CDS/centos7/x86_64/predev/cds_1.0/",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mofed-server-uri")
                .long("mofed-server-uri")
                .global(true)
                .help("for centos mofed uri to use for a custom yum repo to install")
                .default_value(
                    "http://car.dev.cray.com/artifactory/internal/CDS/centos7/x86_64/predev/cds_1.0/",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("e2fsprogs-server-uri")
                .long("e2fsprogs-server-uri")
                .global(true)
                .help("for centos e2fsprogs uri to use for a custom yum repo to install")
                .default_value(
                    "http://car.dev.cray.com/artifactory/internal/CDS/centos7/x86_64/predev/cds_1.0/",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("lus-server-uri")
                .long("lus-server-uri")
                .global(true)
                .help("for centos lustre uri to use for a custom yum repo to install")
                .default_value(
                    "http://car.dev.cray.com/artifactory/internal/CDS/centos7/x86_64/predev/cds_1.1",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("lus-emitter-uri")
                .long("lus-emitter-uri")
                .global(true)
                .help("for centos lustre uri to use for a custom yum repo to install emitter")
                .default_value(
                    "http://car.dev.cray.com/artifactory/internal/CDS/centos7/x86_64/predev/cds_1.0/",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("lus-client-uri")
                .long("lus-client-uri")
                .global(true)
                .help("for sles sms nodes what uri to use for a custom zypper repo to install")
                .default_value(
                    "http://car.dev.cray.com/artifactory/internal/CDS/sle15_ncn/x86_64/predev/cds_1.0/",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cds-release-bundle")
                .long("cds-release-bundle")
                .short("B")
                .global(true)
                .help("URL of the CDS release bundle to install")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("playbook")
                .long("playbook")
                .global(true)
                .help("run a single repo's playbook, note this is the string under playbook->repos")
                .takes_value(true),
        )
        .subcommand(SubCommand::with_name("status").about("Get status of sms vm's"))
        .subcommand(SubCommand::with_name("verify").about("validate sms vm's and fix if possible"))
        .subcommand(SubCommand::with_name("up").about("bring a sms cluster online"))
        .subcommand(SubCommand::with_name("down").about("bring a sms cluster offline"))
        .subcommand(
            SubCommand::with_name("provision").about("run provisioner steps on first sms node"),
        )
        .subcommand(SubCommand::with_name("ci").about("down+up+provision+test"))
        .subcommand(SubCommand::with_name("redo").about("down+up"))
        .subcommand(SubCommand::with_name("daily").about("down+up+provision+test"))
        .subcommand(SubCommand::with_name("test").about("run ct-test on first sms node"))
        .subcommand(
            SubCommand::with_name("unbound")
                .about("print out unbound configuration entries for use in a script"),
        )
        .subcommand(SubCommand::with_name("ssh-config").about("print out ~/.ssh/config entries"))
        .subcommand(
            SubCommand::with_name("scp")
                .about("scp data from the first sms node, helper only")
                .arg(Arg::with_name("remote-source").multiple(false))
                .arg(Arg::with_name("local-dest").multiple(false)),
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("run a command on the first sms node, helper only")
                .arg(Arg::with_name("command").multiple(false)),
        )
        .subcommand(SubCommand::with_name("cleanup").about("cleanup all openstack configuration"))
        .get_matches();

    env_logger::init();

    if let Err(e) = run(matches) {
        eprintln!("Fatal application error: {}", e);
        std::process::exit(1);
    } else {
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use crate::extract_hostname;
    #[test]
    fn extract_hostnames() {
        assert_eq!(
            extract_hostname(r"lustre-01-stable-2deacee19d2184da"),
            Some(r"lustre-01")
        );
        assert_eq!(
            extract_hostname(r"stable-lustre-01-stable-2deacee19d2184da"),
            Some(r"stable-lustre-01")
        );
        assert_eq!(
            extract_hostname(r"sms-01-stable-2deacee19d2184da"),
            Some(r"sms-01")
        );
        assert_eq!(
            extract_hostname(r"sms-01-default-2deacee19d2184da"),
            Some(r"sms-01")
        );
    }
}
