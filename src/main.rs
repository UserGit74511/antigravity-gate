//! antigravity-gate CLI executable.

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use antigravity_gate::http::run_http_server;
use antigravity_gate::patcher::{
    discover_antigravity_installs, find_binaries_in_install, inspect_binary, patch_binary,
    unpatch_binary, TargetStatus,
};
use antigravity_gate::pool::SniPool;
use antigravity_gate::router::Router;
use antigravity_gate::socks5::run_socks5_server;

#[derive(Parser, Debug)]
#[command(
    name = "antigravity-gate",
    author = "Antigravity Gate Contributors",
    version = "0.1.0",
    about = "Zero-patching smart proxy gateway and IDE patcher for developer AI tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    serve_args: ServeArgs,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the smart proxy gateway server (default mode)
    Serve(ServeArgs),

    /// Patch Antigravity IDE binaries to unlock all Google accounts and isolate proxy variables
    Patch {
        /// Optional custom Antigravity installation directory path
        #[arg(short, long)]
        path: Option<PathBuf>,
    },

    /// Restore Antigravity IDE binaries to their pristine/original state
    Unpatch {
        /// Optional custom Antigravity installation directory path
        #[arg(short, long)]
        path: Option<PathBuf>,
    },

    /// Check patch and eligibility status of installed Antigravity IDE binaries
    Status {
        /// Optional custom Antigravity installation directory path
        #[arg(short, long)]
        path: Option<PathBuf>,
    },
}

#[derive(clap::Args, Debug, Clone)]
pub struct ServeArgs {
    /// Inbound SOCKS5 bind address
    #[arg(
        short = 's',
        long = "socks5-bind",
        default_value = "127.0.0.1:1080",
        value_parser = antigravity_gate::upstream::parse_bind_addr_socks5
    )]
    pub socks5_bind: SocketAddr,

    /// Inbound HTTP CONNECT bind address
    #[arg(
        short = 'p',
        long = "http-bind",
        default_value = "127.0.0.1:1081",
        value_parser = antigravity_gate::upstream::parse_bind_addr_http
    )]
    pub http_bind: SocketAddr,

    /// Optional upstream SOCKS5 proxy (e.g. socks5://127.0.0.1:2080 or socks5://user:pass@127.0.0.1:10808) for Cursor/Claude
    #[arg(short = 'u', long = "upstream", value_parser = antigravity_gate::upstream::parse_upstream_config)]
    pub upstream: Option<antigravity_gate::upstream::UpstreamConfig>,

    /// Comma-separated list of additional domains to route through upstream proxy
    #[arg(long = "upstream-domains")]
    pub upstream_domains: Option<String>,

    /// Interval (in seconds) between background SNI pool health probes
    #[arg(long = "probe-interval", default_value = "60")]
    pub probe_interval: u64,

    /// Enable auto-fallback to alternative port if default bind address is in use
    #[arg(long = "auto-fallback", default_value = "true")]
    pub auto_fallback: bool,

    /// Enable verbose / debug logging
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Serve(args)) => run_serve(args).await,
        Some(Commands::Patch { path }) => {
            handle_patch(path);
            Ok(())
        }
        Some(Commands::Unpatch { path }) => {
            handle_unpatch(path);
            Ok(())
        }
        Some(Commands::Status { path }) => {
            handle_status(path);
            Ok(())
        }
        None => run_serve(cli.serve_args).await,
    }
}

fn print_banner() {
    println!(
        r#"
   ___        __  _                        _ __            ______      __     
  /   | ____  / /_(_)___ __________ __   __(_) /___  __    / ____/___ _/ /____ 
 / /| |/ __ \/ __/ / __ `/ ___/ __ `/ | / / / __/ / / /   / / __/ __ `/ __/ _ \
/ ___ / / / / /_/ / /_/ / /  / /_/ /| |/ / / /_/ /_/ /   / /_/ / /_/ / /_/  __/
/_/  |_\_/ /_/\__/_/\__, /_/   \__,_/ |___/_/\__/\__, /    \____/\__,_/\__/\___/ 
                   /____/                       /____/                         
        Smart AI Proxy Gateway & IDE Patcher | Antigravity Gate
"#
    );
}

fn handle_status(custom_path: Option<PathBuf>) {
    print_banner();
    println!("=== Antigravity IDE Status Inspection ===\n");

    let installs = discover_antigravity_installs(custom_path.as_deref());
    if installs.is_empty() {
        if let Some(p) = &custom_path {
            println!(
                "❌ Specified directory or binary does not exist: {}",
                p.display()
            );
        } else {
            println!("❌ Antigravity installation not found in default locations.");
            println!("   Try passing custom path with '--path <DIRECTORY>'.");
        }
        return;
    }

    for inst in installs {
        println!("📁 Found Installation: {}", inst.display());
        let binaries = find_binaries_in_install(&inst);
        if binaries.is_empty() {
            println!("   ⚠️  No target language_server binaries found in this directory.");
            continue;
        }

        for bin in binaries {
            let report = inspect_binary(&bin);
            let status_badge = match report.status {
                TargetStatus::Patched => "🟢 PATCHED (Eligible for all accounts)",
                TargetStatus::Unpatched => "🟡 UNPATCHED (Original account gating active)",
                TargetStatus::SignatureMissing => "⚪ SIGNATURE MISSING / INCOMPATIBLE BUILD",
                TargetStatus::NotFound => "🔴 FILE NOT FOUND",
                TargetStatus::Error(_) => "🔴 ERROR",
            };
            let proxy_badge = if report.proxy_renamed {
                "AG_LS_PROXY (Isolated)"
            } else {
                "https_proxy (Default)"
            };
            let bak_badge = if report.backup_present {
                "Present (.bak)"
            } else {
                "None"
            };

            println!("   File: {}", bin.display());
            println!("     Status:         {}", status_badge);
            println!("     Proxy Var:      {}", proxy_badge);
            println!("     Backup Copy:    {}\n", bak_badge);
        }
    }
}

fn handle_patch(custom_path: Option<PathBuf>) {
    print_banner();
    println!("=== Patching Antigravity IDE for Account Eligibility ===\n");

    let installs = discover_antigravity_installs(custom_path.as_deref());
    if installs.is_empty() {
        if let Some(p) = &custom_path {
            println!(
                "❌ Specified directory or binary does not exist: {}",
                p.display()
            );
        } else {
            println!("❌ Antigravity installation not found in default locations.");
            println!("   Try specifying the path: 'antigravity-gate patch --path <DIRECTORY>'\n");
        }
        return;
    }

    let mut total_patched = 0;

    for inst in installs {
        println!("📁 Processing Installation: {}", inst.display());
        let binaries = find_binaries_in_install(&inst);
        if binaries.is_empty() {
            println!("   ⚠️  No language_server binaries found.");
            continue;
        }

        for bin in binaries {
            print!(
                "   Patching {} ... ",
                bin.file_name().unwrap_or_default().to_string_lossy()
            );
            match patch_binary(&bin) {
                Ok(rep) => {
                    total_patched += 1;
                    println!("✅ OK");
                    println!(
                        "     -> Replaced {} ineligible signatures",
                        rep.eligibility_replaced
                    );
                    println!(
                        "     -> Replaced {} proxy variable literals",
                        rep.proxy_replaced
                    );
                    if rep.backup_created {
                        println!("     -> Backup created: {}.bak", bin.display());
                    }
                }
                Err(e) => {
                    println!("❌ FAILED: {}", e);
                }
            }
        }
    }

    if total_patched > 0 {
        println!("\n🎉 Successfully patched {} binaries!", total_patched);
        println!("   Now you can log in to Google Antigravity with ANY Google account!");
        println!("   To revert changes anytime: 'antigravity-gate unpatch'\n");
    } else {
        println!("\n⚠️  No binaries were modified.\n");
    }
}

fn handle_unpatch(custom_path: Option<PathBuf>) {
    print_banner();
    println!("=== Reverting Antigravity IDE to Pristine State ===\n");

    let installs = discover_antigravity_installs(custom_path.as_deref());
    if installs.is_empty() {
        if let Some(p) = &custom_path {
            println!(
                "❌ Specified directory or binary does not exist: {}",
                p.display()
            );
        } else {
            println!("❌ Antigravity installation not found.");
        }
        return;
    }

    let mut total_restored = 0;

    for inst in installs {
        println!("📁 Processing Installation: {}", inst.display());
        let binaries = find_binaries_in_install(&inst);
        for bin in binaries {
            print!(
                "   Reverting {} ... ",
                bin.file_name().unwrap_or_default().to_string_lossy()
            );
            match unpatch_binary(&bin) {
                Ok(rep) => {
                    total_restored += 1;
                    if rep.restored_from_backup {
                        println!("✅ RESTORED FROM BACKUP (.bak)");
                    } else {
                        println!("✅ REVERTED BYTES IN-PLACE");
                    }
                }
                Err(e) => {
                    println!("❌ FAILED: {}", e);
                }
            }
        }
    }

    if total_restored > 0 {
        println!(
            "\n🎉 Successfully restored {} binaries to original state!\n",
            total_restored
        );
    } else {
        println!("\n⚠️  No binaries needed restoration.\n");
    }
}

async fn run_serve(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let filter = if args.verbose {
        EnvFilter::new("antigravity_gate=debug,info")
    } else {
        EnvFilter::new("antigravity_gate=info")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    print_banner();

    let custom_domains = args
        .upstream_domains
        .map(|s| s.split(',').map(|d| d.trim().to_string()).collect())
        .unwrap_or_default();

    let sni_pool = SniPool::new();
    let total_endpoints = sni_pool.endpoints().len();
    let router = Router::new(sni_pool.clone(), args.upstream.clone(), custom_domains);

    let socks5_listener = match bind_with_fallback(
        args.socks5_bind,
        args.auto_fallback,
        &[10800, 10805, 53128, 53180],
    )
    .await
    {
        Ok(l) => l,
        Err(err) => {
            error!(
                addr = %args.socks5_bind,
                %err,
                "Failed to bind SOCKS5 listener. If port 1080 is in use, pass '--socks5-bind 127.0.0.1:<port>'"
            );
            return Err(err.into());
        }
    };

    let http_listener = match bind_with_fallback(
        args.http_bind,
        args.auto_fallback,
        &[10810, 10815, 53129, 53181],
    )
    .await
    {
        Ok(l) => l,
        Err(err) => {
            error!(
                addr = %args.http_bind,
                %err,
                "Failed to bind HTTP CONNECT listener. Pass '--http-bind 127.0.0.1:<port>'"
            );
            return Err(err.into());
        }
    };

    let actual_socks5 = socks5_listener.local_addr()?;
    let actual_http = http_listener.local_addr()?;

    info!("---------------------------------------------------------------");
    info!("  SOCKS5 Listener:       socks5://{}", actual_socks5);
    info!("  HTTP CONNECT Listener: http://{}", actual_http);
    info!(
        "  SNI Reverse-Proxy:     {} endpoints (geohide, dns-ai)",
        total_endpoints
    );
    if let Some(up) = &args.upstream {
        if let Some((user, _)) = &up.auth {
            info!(
                "  Upstream SOCKS5:       socks5://{} (user: '{}') (Cursor, Claude, OpenAI)",
                up.addr, user
            );
        } else {
            info!(
                "  Upstream SOCKS5:       socks5://{} (Cursor, Claude, OpenAI)",
                up.addr
            );
        }
    } else {
        info!("  Upstream SOCKS5:       Disabled (Google AI works out-of-the-box)");
    }
    info!("  Active Route Rules:    Google AI (*.googleapis.com) -> Built-in SNI Pool");
    info!("---------------------------------------------------------------");
    info!("Ready for traffic. Configure IDE/CLI proxy or export HTTP_PROXY / ALL_PROXY.");

    let pool_probe = sni_pool.clone();
    tokio::spawn(async move {
        pool_probe.probe_all(Duration::from_secs(3)).await;
    });

    if args.probe_interval > 0 {
        let pool_periodic = sni_pool.clone();
        let probe_interval = Duration::from_secs(args.probe_interval);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(probe_interval);
            interval.tick().await;
            loop {
                interval.tick().await;
                pool_periodic.probe_all(Duration::from_secs(3)).await;
            }
        });
    } else {
        info!("Periodic SNI pool background health check disabled (probe_interval=0)");
    }

    let socks5_task = tokio::spawn(run_socks5_server(socks5_listener, router.clone()));
    let http_task = tokio::spawn(run_http_server(http_listener, router.clone()));

    tokio::select! {
        res = socks5_task => {
            if let Err(e) = res {
                error!("SOCKS5 server terminated with error: {:?}", e);
            }
        }
        res = http_task => {
            if let Err(e) = res {
                error!("HTTP server terminated with error: {:?}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal (Ctrl+C), stopping antigravity-gate...");
        }
    }

    Ok(())
}

async fn bind_with_fallback(
    addr: SocketAddr,
    fallback: bool,
    fallback_ports: &[u16],
) -> std::io::Result<TcpListener> {
    match TcpListener::bind(addr).await {
        Ok(l) => Ok(l),
        Err(err)
            if fallback
                && (err.kind() == std::io::ErrorKind::AddrInUse
                    || err.raw_os_error() == Some(10048)) =>
        {
            warn!(
                occupied_addr = %addr,
                "Requested port is already in use by another application. Trying fallback ports..."
            );
            for &port in fallback_ports {
                let candidate = SocketAddr::new(addr.ip(), port);
                if let Ok(l) = TcpListener::bind(candidate).await {
                    info!(
                        original = %addr,
                        bound = %candidate,
                        "Successfully bound to fallback port"
                    );
                    return Ok(l);
                }
            }
            Err(err)
        }
        Err(err) => Err(err),
    }
}
