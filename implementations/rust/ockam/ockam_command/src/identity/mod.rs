mod create;
mod show;
mod list;

pub(crate) use create::CreateCommand;
pub(crate) use show::ShowCommand;
pub(crate) use list::ListCommand;

use crate::CommandGlobalOpts;
use clap::{Args, Subcommand};

/// Manage Identities
#[derive(Clone, Debug, Args)]
pub struct IdentityCommand {
    #[command(subcommand)]
    subcommand: IdentitySubcommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum IdentitySubcommand {
    /// Create Identity
    Create(CreateCommand),
    /// Print short existing identity, `--full` for long identity
    Show(ShowCommand),
    /// Print all existing identities, `--full` for long identities
    List(ListCommand),
}

impl IdentityCommand {
    pub fn run(self, options: CommandGlobalOpts) {
        match self.subcommand {
            IdentitySubcommand::Create(c) => c.run(options),
            IdentitySubcommand::Show(c) => c.run(options),
            IdentitySubcommand::List(c) => c.run(options),
        }
    }
}
