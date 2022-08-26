use crate::{
    secure_channel::BACKGROUND,
    util::{api, exitcode, get_final_element, node_rpc, stop_node},
    CommandGlobalOpts, OutputFormat, Result, HELP_TEMPLATE,
};

use atty::Stream;
use clap::Args;
use colorful::Colorful;
use const_str::replace as const_replace;
use serde_json::json;

use crate::util::api::CloudOpts;
use crate::util::RpcBuilder;
use ockam::{identity::IdentityIdentifier, route, Context, TcpTransport};
use ockam_api::config::lookup::ConfigLookup;
use ockam_api::{
    clean_multiaddr, nodes::models::secure_channel::CreateSecureChannelResponse, route_to_multiaddr,
};
use ockam_multiaddr::MultiAddr;

/// Create Secure Channels
#[derive(Clone, Debug, Args)]
#[clap(
    display_order = 900,
    help_template = const_replace!(HELP_TEMPLATE, "LEARN MORE", BACKGROUND)
)]
pub struct CreateCommand {
    /// Node from which to initiate the secure channel (required)
    #[clap(value_name = "NODE", long, display_order = 800)]
    pub from: String,

    /// Route to a secure channel listener (required)
    #[clap(value_name = "ROUTE", long, display_order = 800)]
    pub to: MultiAddr,

    /// Identifiers authorized to be presented by the listener
    #[clap(value_name = "IDENTIFIER", long, short, display_order = 801)]
    pub authorized: Option<Vec<IdentityIdentifier>>,

    /// Orchestrator address to resolve projects present in the `at` argument
    #[clap(flatten)]
    cloud_opts: CloudOpts,
}

impl CreateCommand {
    pub fn run(self, options: CommandGlobalOpts) {
        node_rpc(rpc, (options, self));
    }

    // Read the `to` argument and return a MultiAddr
    // or exit with and error if `to` can't be parsed.
    async fn parse_to_route(
        &self,
        ctx: &Context,
        opts: &CommandGlobalOpts,
        tcp: &TcpTransport,
        cloud_addr: &MultiAddr,
        api_node: &str,
    ) -> anyhow::Result<MultiAddr> {
        let config = &opts.config.get_lookup();
        let (to, meta) = clean_multiaddr(&self.to, config).unwrap_or_else(|| {
            eprintln!("Could not convert {} into route", &self.to);
            std::process::exit(exitcode::USAGE);
        });
        let projects_sc =
            crate::project::util::lookup_projects(ctx, opts, tcp, &meta, cloud_addr, api_node)
                .await?;
        crate::project::util::clean_projects_multiaddr(to, projects_sc)
    }

    // Read the `from` argument and return node name
    fn parse_from_node(&self, _config: &ConfigLookup) -> String {
        get_final_element(&self.from).to_string()
    }

    fn print_output(
        &self,
        parsed_from: &String,
        parsed_to: &MultiAddr,
        options: &CommandGlobalOpts,
        response: CreateSecureChannelResponse,
    ) {
        let route = &route![response.addr.to_string()];
        match route_to_multiaddr(route) {
            Some(multiaddr) => {
                // if stdout is not interactive/tty write the secure channel address to it
                // in case some other program is trying to read it as piped input
                if !atty::is(Stream::Stdout) {
                    println!("{}", multiaddr)
                }

                // if output format is json, write json to stdout.
                if options.global_args.output_format == OutputFormat::Json {
                    let json = json!([{ "address": multiaddr.to_string() }]);
                    println!("{}", json);
                }

                // if stderr is interactive/tty and we haven't been asked to be quiet
                // and output format is plain then write a plain info to stderr.
                if atty::is(Stream::Stderr)
                    && !options.global_args.quiet
                    && options.global_args.output_format == OutputFormat::Plain
                {
                    if options.global_args.no_color {
                        eprintln!("\n  Created Secure Channel:");
                        eprintln!("  • From: /node/{}", parsed_from);
                        eprintln!("  •   To: {} ({})", &self.to, &parsed_to);
                        eprintln!("  •   At: {}", multiaddr);
                    } else {
                        eprintln!("\n  Created Secure Channel:");

                        // From:
                        eprint!("{}", "  • From: ".light_magenta());
                        eprintln!("{}", format!("/node/{}", parsed_from).light_yellow());

                        // To:
                        eprint!("{}", "  •   To: ".light_magenta());
                        let t = format!("{} ({})", &self.to, &parsed_to);
                        eprintln!("{}", t.light_yellow());

                        // At:
                        eprint!("{}", "  •   At: ".light_magenta());
                        eprintln!("{}", multiaddr.to_string().light_yellow());
                    }
                }
            }
            None => {
                // if stderr is interactive/tty and we haven't been asked to be quiet
                // and output format is plain then write a plain info to stderr.
                if atty::is(Stream::Stderr)
                    && !options.global_args.quiet
                    && options.global_args.output_format == OutputFormat::Plain
                {
                    eprintln!(
                        "Could not convert returned secure channel address {} into a multiaddr",
                        route
                    );
                }

                // return the exitcode::PROTOCOL since if things are going as expected
                // a route in the response should be convertable to multiaddr.
                std::process::exit(exitcode::PROTOCOL);
            }
        };
    }
}

async fn rpc(ctx: Context, (options, command): (CommandGlobalOpts, CreateCommand)) -> Result<()> {
    let tcp = TcpTransport::create(&ctx).await?;

    let config = &options.config.get_lookup();
    let from = &command.parse_from_node(config);
    let to = &command
        .parse_to_route(
            &ctx,
            &options,
            &tcp,
            &command.cloud_opts.route_to_controller,
            from,
        )
        .await?;

    let authorized_identifiers = command.authorized.clone();

    // Delegate the request to create a secure channel to the from node.
    let mut rpc = RpcBuilder::new(&ctx, &options, from).tcp(&tcp).build()?;
    let request = api::create_secure_channel(to, authorized_identifiers);
    rpc.request(request).await?;
    let response = rpc.parse_response::<CreateSecureChannelResponse>()?;

    command.print_output(from, to, &options, response);
    stop_node(ctx).await?;
    Ok(())
}
