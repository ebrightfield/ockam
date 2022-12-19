use crate::util::output::Output;
use crate::util::node_rpc;
use crate::{CommandGlobalOpts, OutputFormat};
use clap::Args;
use core::fmt::Write;
use ockam::Context;
use ockam_api::nodes::models::identity::{LongIdentityResponse, ShortIdentityResponse};
use ockam_identity::change_history::IdentityChangeHistory;
use ockam_identity::Identity;
use ockam_vault::Vault;

#[derive(Clone, Debug, Args)]
pub struct ShowCommand {
    name: String,
    #[arg(short, long)]
    full: bool,
}

impl ShowCommand {
    pub fn run(self, options: CommandGlobalOpts) {
        node_rpc(run_impl, (options, self))
    }
}

async fn run_impl(
    ctx: Context,
    (opts, cmd): (CommandGlobalOpts, ShowCommand),
) -> crate::Result<()> {
    let node = opts.state.nodes.get(&cmd.name)?;
    let identity = node.config.identity(&ctx).await?;
    print_identity(
        &identity,
        cmd.full,
        &opts.global_args.output_format,
    ).await?;
    Ok(())
}

impl Output for LongIdentityResponse<'_> {
    fn output(&self) -> anyhow::Result<String> {
        let mut w = String::new();
        let id: IdentityChangeHistory = serde_bare::from_slice(self.identity.0.as_ref())?;
        write!(w, "{}", id)?;
        Ok(w)
    }
}

impl Output for ShortIdentityResponse<'_> {
    fn output(&self) -> anyhow::Result<String> {
        let mut w = String::new();
        write!(w, "{}", self.identity_id)?;
        Ok(w)
    }
}

pub async fn print_identity(
    identity: &Identity<Vault>,
    full: bool,
    output_format: &OutputFormat,
) -> crate::Result<()> {
    let response = if full {
        let identity = identity.export().await?;
        LongIdentityResponse::new(identity).output()?
    } else {
        let identity = identity.identifier();
        ShortIdentityResponse::new(identity.to_string()).output()?
    };
    let o = match output_format {
        OutputFormat::Plain => response,
        OutputFormat::Json => {
            serde_json::to_string_pretty(&response)?
        }
    };
    println!("{}", o);
    Ok(())
}
