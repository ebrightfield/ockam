use crate::util::{api, exitcode, node_rpc, RpcBuilder};
use crate::{help, node::show::print_query_status, node::HELP_DETAIL, CommandGlobalOpts};
use anyhow::{anyhow, Context as _};
use clap::Args;
use ockam::{Context, TcpTransport};
use std::time::Duration;
use ockam_api::nodes::models::identity::LongIdentityResponse;

/// List nodes
#[derive(Clone, Debug, Args)]
#[command(after_long_help = help::template(HELP_DETAIL))]
pub struct ListCommand {
    #[arg(short, long)]
    full: bool,
}

impl ListCommand {
    pub fn run(self, options: CommandGlobalOpts) {
        node_rpc(run_impl, (options, self))
    }
}

async fn run_impl(
    ctx: Context,
    (opts, _cmd): (CommandGlobalOpts, ListCommand),
) -> crate::Result<()> {
    // TODO Node list verifies before printing. Should we do something similar here?
    let identity_names: Vec<_> = {
        let identity_states = opts.state.identities.list()?;
        if identity_states.is_empty() {
            return Err(crate::Error::new(
                exitcode::IOERR,
                anyhow!("No identities registered on this system!"),
            ));
        }
        identity_states.iter().map(|id| id.config.identifier.to_string()).collect()
    };
    // let tcp = TcpTransport::create(&ctx).await?;
    // verify_pids(&ctx, &opts, &tcp, &identity_names).await?;
    let response = LongIdentityResponse::new()

    // Print node states
    for node_name in &identity_names {
        let mut rpc = RpcBuilder::new(&ctx, &opts, node_name).tcp(&tcp)?.build();
        print_query_status(&mut rpc, node_name, false).await?;
    }

    Ok(())
}

/// Update the persisted configuration data with the pids
/// responded by nodes.
async fn verify_pids(
    ctx: &Context,
    opts: &CommandGlobalOpts,
    tcp: &TcpTransport,
    nodes: &Vec<String>,
) -> crate::Result<()> {
    for node_name in nodes {
        if let Ok(node_state) = opts.state.nodes.get(node_name) {
            let mut rpc = RpcBuilder::new(ctx, opts, node_name).tcp(tcp)?.build();
            if rpc
                .request_with_timeout(api::query_status(), Duration::from_millis(200))
                .await
                .is_ok()
            {
                let resp = rpc.parse_response::<NodeStatus>()?;
                if node_state.pid()? != Some(resp.pid) {
                    node_state
                        .set_pid(resp.pid)
                        .context("Failed to update pid for node {node_name}")?;
                }
            }
        }
    }
    Ok(())
}
