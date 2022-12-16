use anyhow::{anyhow, Context as _};
use rand::random;
use std::env::current_exe;
use std::fs::OpenOptions;
use std::path::Path;
use std::process::Command;
use tracing::trace;

use ockam::identity::{Identity, PublicIdentity};
use ockam::{Context, TcpTransport};
use ockam_api::authenticator::direct::types::OneTimeCode;
use ockam_api::cli_state;
use ockam_api::config::cli;
use ockam_api::nodes::models::transport::{TransportMode, TransportType};
use ockam_api::nodes::service::{
    NodeManagerGeneralOptions, NodeManagerProjectsOptions, NodeManagerTransportOptions,
};
use ockam_api::nodes::{NodeManager, NodeManagerWorker, NODEMANAGER_ADDR};
use ockam_multiaddr::MultiAddr;
use ockam_vault::Vault;

use crate::project::ProjectInfo;
use crate::CommandGlobalOpts;
use crate::node::create::DEFAULT_TCP_LISTENER_ADDR;
use crate::OckamConfig;

/// For generating a new node name if it's not manually supplied.
pub fn random_node_name() -> String {
    hex::encode(random::<[u8; 4]>())
}

/// Starts an embedded node with no vault or identity
pub async fn start_embedded_node(
    ctx: &Context,
    opts: &CommandGlobalOpts,
) -> anyhow::Result<String> {
    start_embedded_node_with_vault_and_identity(ctx, opts, None, None).await
}

/// Uses the default parameters of the [crate::node::create::CreateCommand]
/// where applicable.
pub async fn start_embedded_node_with_vault_and_identity(
    ctx: &Context,
    opts: &CommandGlobalOpts,
    vault: Option<&String>,
    identity: Option<&String>,
) -> anyhow::Result<String> {
    let cfg = &opts.config;
    let node_name = random_node_name();

    // This node is not a child process, no need for if-statement
    init_node_state(ctx, opts, &node_name, vault, identity).await?;

    let tcp = TcpTransport::create(ctx).await?;
    let bind = DEFAULT_TCP_LISTENER_ADDR.to_string();
    tcp.listen(&bind).await?;

    let projects = cfg.inner().lookup().projects().collect();
    let node_man = NodeManager::create(
        ctx,
        NodeManagerGeneralOptions::new(node_name.clone(), false),
        NodeManagerProjectsOptions::new(
            Some(&cfg.authorities(&node_name)?.snapshot()),
            None,
            projects,
            None,
        ),
        NodeManagerTransportOptions::new((TransportType::Tcp, TransportMode::Listen, bind), tcp),
    )
    .await?;

    let node_manager_worker = NodeManagerWorker::new(node_man);

    ctx.start_worker(NODEMANAGER_ADDR, node_manager_worker)
        .await?;

    Ok(node_name)
}

pub(super) async fn init_node_state(
    ctx: &Context,
    opts: &CommandGlobalOpts,
    node_name: &str,
    vault: Option<&String>,
    identity: Option<&String>,
) -> anyhow::Result<()> {
    // Get vault specified in the argument, or get the default
    let vault_state = if let Some(v) = vault {
        opts.state.vaults.get(v)?
    }
    // Or get the default
    else if let Ok(v) = opts.state.vaults.default() {
        v
    } else {
        let n = hex::encode(random::<[u8; 4]>());
        let c = cli_state::VaultConfig::fs_default(&n, false)?;
        opts.state.vaults.create(&n, c).await?
    };

    // Get identity specified in the argument
    let identity_state = if let Some(idt) = identity {
        opts.state.identities.get(idt)?
    }
    // Or get the default
    else if let Ok(idt) = opts.state.identities.default() {
        idt
    } else {
        let vault = vault_state.config.get().await?;
        let identity_name = hex::encode(random::<[u8; 4]>());
        let identity = Identity::create(ctx, &vault).await?;
        let identity_config = cli_state::IdentityConfig::new(&identity).await;
        opts.state
            .identities
            .create(&identity_name, identity_config)?
    };

    // Create the node with the given vault and identity
    let node_config = cli_state::NodeConfigBuilder::default()
        .vault(vault_state.path)
        .identity(identity_state.path)
        .build(&opts.state)?;
    opts.state.nodes.create(node_name, node_config)?;

    Ok(())
}

pub(super) async fn add_project_authority(
    p: ProjectInfo<'_>,
    node: &str,
    cfg: &OckamConfig,
) -> anyhow::Result<()> {
    let m = p
        .authority_access_route
        .map(|a| MultiAddr::try_from(&*a))
        .transpose()?;
    let a = p
        .authority_identity
        .map(|a| hex::decode(a.as_bytes()))
        .transpose()?;
    if let Some((a, m)) = a.zip(m) {
        let v = Vault::default();
        let i = PublicIdentity::import(&a, &v).await?;
        let a = cli::Authority::new(a, m);
        cfg.authorities(node)?
            .add_authority(i.identifier().clone(), a)
    } else {
        Err(anyhow!("missing authority in project info"))
    }
}

pub async fn delete_embedded_node(opts: &CommandGlobalOpts, name: &str) {
    delete_node(opts, name, false)
}

pub fn delete_node(opts: &CommandGlobalOpts, name: &str, force: bool) {
    if let Ok(s) = opts.state.nodes.get(name) {
        trace!(%name, "Deleting node");
        let _ = s.delete(force);
    }
}

pub fn delete_all_nodes(opts: CommandGlobalOpts, force: bool) -> anyhow::Result<()> {
    let nodes_states = opts.state.nodes.list()?;
    for s in nodes_states {
        let _ = s.delete(force);
    }
    Ok(())
}

/// A utility function to spawn a new node into foreground mode
#[allow(clippy::too_many_arguments)]
pub fn spawn_node(
    opts: &CommandGlobalOpts,
    verbose: u8,
    name: &str,
    address: &str,
    project: Option<&Path>,
    invite: Option<&OneTimeCode>,
) -> crate::Result<()> {
    // On systems with non-obvious path setups (or during
    // development) re-executing the current binary is a more
    // deterministic way of starting a node.
    let ockam_exe = current_exe().unwrap_or_else(|_| "ockam".into());
    let node_state = opts.state.nodes.get(name)?;

    let (mlog, elog) = { (node_state.stdout_log(), node_state.stderr_log()) };

    let main_log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(mlog)
        .context("failed to open log path")?;

    let stderr_log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(elog)
        .context("failed to open stderr log path")?;

    let mut args = vec![
        match verbose {
            0 => "-vv".to_string(),
            v => format!("-{}", "v".repeat(v as usize)),
        },
        "--no-color".to_string(),
        "node".to_string(),
        "create".to_string(),
        "--tcp-listener-address".to_string(),
        address.to_string(),
        "--foreground".to_string(),
        "--child-process".to_string(),
    ];

    if let Some(path) = project {
        args.push("--project".to_string());
        let p = path
            .to_str()
            .unwrap_or_else(|| panic!("unsupported path {path:?}"));
        args.push(p.to_string())
    }

    if let Some(c) = invite {
        args.push("--enrollment-token".to_string());
        args.push(hex::encode(c.code()))
    }

    args.push(name.to_owned());

    let child = Command::new(ockam_exe)
        .args(args)
        .stdout(main_log_file)
        .stderr(stderr_log_file)
        .spawn()?;
    node_state.set_pid(child.id() as i32)?;

    Ok(())
}
