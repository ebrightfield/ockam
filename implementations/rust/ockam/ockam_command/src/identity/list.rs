use crate::util::{api, exitcode, extract_address_value, node_rpc, Rpc, RpcBuilder};
use crate::{help, node::show::print_query_status, node::HELP_DETAIL, CommandGlobalOpts};
use anyhow::{anyhow, Context as _};
use clap::Args;
use ockam::{Context, TcpTransport};
use std::time::Duration;
use ockam_api::nodes::models::identity::{LongIdentityResponse, ShortIdentityResponse};
use ockam_core::api::Request;

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
    let tcp = TcpTransport::create(&ctx).await?;
    // verify_pids(&ctx, &opts, &tcp, &identity_names).await?;

    // Print identity states
    let node_name = extract_address_value(&cmd.node_opts.api_node)?;
    for identity in &identity_names {
        let mut rpc = Rpc::background(&ctx, &opts, &node_name)?;
        if cmd.full {
            let req = Request::post("/node/identity/actions/show/long");
            rpc.request(req).await?;
            rpc.parse_and_print_response::<LongIdentityResponse>()?;
        } else {
            let req = Request::post("/node/identity/actions/show/short");
            rpc.request(req).await?;
            rpc.parse_and_print_response::<ShortIdentityResponse>()?;
        }
    }

    Ok(())
}
