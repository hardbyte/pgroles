//! pgroles CLI — declarative PostgreSQL role policy manager.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sqlx::PgPool;
use tracing::info;

use pgroles_cli::{
    PlanSummary, apply_role_retirements, compute_plan, format_plan_json,
    format_plan_sql_with_context, format_role_graph_summary, format_validation_result,
    planned_role_drops, read_manifest_file, validate_manifest,
};
use pgroles_inspect::{InspectConfig, inspect_drop_role_safety};

// ---------------------------------------------------------------------------
// CLI argument definitions
// ---------------------------------------------------------------------------

/// pgroles — declarative PostgreSQL role & privilege manager.
///
/// Define roles, grants, default privileges, and memberships in a YAML manifest
/// and converge your database to match.
#[derive(Parser)]
#[command(name = "pgroles", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a manifest file (parse + expand). No database connection required.
    Validate {
        /// Path to the policy manifest YAML file.
        #[arg(short, long, default_value = "pgroles.yaml")]
        file: PathBuf,
    },

    /// Show the SQL changes needed to converge the database to the manifest.
    /// Alias: plan.
    #[command(alias = "plan")]
    Diff {
        /// Path to the policy manifest YAML file.
        #[arg(short, long, default_value = "pgroles.yaml")]
        file: PathBuf,

        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,

        /// Output format: "sql" for raw SQL, "summary" for a brief summary, "json" for machine-readable JSON.
        #[arg(long, default_value = "sql")]
        format: OutputFormat,

        /// Exit with code 2 when drift is detected (useful for CI gates).
        #[arg(long, default_value_t = true)]
        exit_code: bool,
    },

    /// Apply the changes to bring the database in sync with the manifest.
    Apply {
        /// Path to the policy manifest YAML file.
        #[arg(short, long, default_value = "pgroles.yaml")]
        file: PathBuf,

        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,

        /// Print the SQL that would be executed without actually running it.
        #[arg(long)]
        dry_run: bool,
    },

    /// Inspect the current database state for managed roles and privileges.
    Inspect {
        /// Path to the policy manifest YAML file (used to scope inspection).
        #[arg(short, long, default_value = "pgroles.yaml")]
        file: PathBuf,

        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Generate a manifest YAML from the current database state (brownfield adoption).
    ///
    /// Introspects all non-system roles, their grants, default privileges, and
    /// memberships, then emits a flat manifest that reproduces the current state.
    Generate {
        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum OutputFormat {
    Sql,
    Summary,
    Json,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> ExitCode {
    // Initialise tracing (respects RUST_LOG env var, defaults to info).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match run(cli).await {
        Ok(exit) => exit,
        Err(err) => {
            eprintln!("Error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Exit code 2 indicates drift was detected (used by `diff`/`plan`).
const EXIT_DRIFT: u8 = 2;

async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Commands::Validate { file } => {
            cmd_validate(&file)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Diff {
            file,
            database_url,
            format,
            exit_code,
        } => cmd_diff(&file, &database_url, &format, exit_code).await,
        Commands::Apply {
            file,
            database_url,
            dry_run,
        } => {
            cmd_apply(&file, &database_url, dry_run).await?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Inspect { file, database_url } => {
            cmd_inspect(&file, &database_url).await?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Generate { database_url } => {
            cmd_generate(&database_url).await?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

fn cmd_validate(file: &Path) -> Result<()> {
    let yaml = read_manifest_file(file)?;
    let validated = validate_manifest(&yaml)?;
    print!("{}", format_validation_result(&validated));
    Ok(())
}

async fn cmd_diff(
    file: &Path,
    database_url: &str,
    format: &OutputFormat,
    use_exit_code: bool,
) -> Result<ExitCode> {
    let yaml = read_manifest_file(file)?;
    let validated = validate_manifest(&yaml)?;

    let pool = connect_db(database_url).await?;
    let current = inspect_current(&pool, &validated).await?;

    let changes = apply_role_retirements(
        compute_plan(&current, &validated.desired),
        &validated.manifest.retirements,
    );
    let drop_safety = inspect_drop_safety(&pool, &changes, &validated.manifest.retirements).await?;
    let summary = PlanSummary::from_changes(&changes);

    match format {
        OutputFormat::Sql => {
            let sql_ctx = detect_sql_context(&pool).await?;
            if summary.is_empty() {
                println!("-- No changes needed. Database is in sync with manifest.");
            } else {
                print!("{}", format_plan_sql_with_context(&changes, &sql_ctx));
                eprintln!("\n{summary}");
                if !drop_safety.is_empty() {
                    eprintln!("\n{drop_safety}");
                }
            }
        }
        OutputFormat::Summary => {
            print!("{summary}");
            if !drop_safety.is_empty() {
                eprintln!("\n{drop_safety}");
            }
        }
        OutputFormat::Json => {
            println!("{}", format_plan_json(&changes)?);
        }
    }

    if use_exit_code && !summary.is_empty() {
        Ok(ExitCode::from(EXIT_DRIFT))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

async fn cmd_apply(file: &Path, database_url: &str, dry_run: bool) -> Result<()> {
    let yaml = read_manifest_file(file)?;
    let validated = validate_manifest(&yaml)?;

    let pool = connect_db(database_url).await?;
    let sql_ctx = detect_sql_context(&pool).await?;

    // Detect cloud provider privilege level and warn about unsupported operations.
    let privilege_level = pgroles_inspect::detect_privilege_level(&pool)
        .await
        .context("failed to detect privilege level")?;
    info!(level = %privilege_level, "detected privilege level");

    let current = inspect_current(&pool, &validated).await?;

    let changes = apply_role_retirements(
        compute_plan(&current, &validated.desired),
        &validated.manifest.retirements,
    );

    // Validate changes against privilege level.
    let priv_warnings =
        pgroles_inspect::cloud::validate_changes_for_privilege_level(&changes, &privilege_level);
    if !priv_warnings.is_empty() {
        for warning in &priv_warnings {
            eprintln!("Warning: {warning}");
        }
    }

    let drop_safety = inspect_drop_safety(&pool, &changes, &validated.manifest.retirements).await?;
    let summary = PlanSummary::from_changes(&changes);

    if summary.is_empty() {
        println!("No changes needed. Database is in sync with manifest.");
        return Ok(());
    }

    let sql_output = format_plan_sql_with_context(&changes, &sql_ctx);

    if dry_run {
        println!("-- DRY RUN: the following SQL would be executed:\n");
        print!("{sql_output}");
        eprintln!("\n{summary}");
        if !drop_safety.is_empty() {
            eprintln!("\n{drop_safety}");
        }
        return Ok(());
    }

    if drop_safety.has_blockers() {
        anyhow::bail!("{}", drop_safety.blockers);
    }

    if !drop_safety.warnings.is_empty() {
        eprintln!("\n{warnings}", warnings = drop_safety.warnings);
    }

    // Execute the entire plan in one transaction to avoid partial convergence.
    info!(changes = summary.total(), "applying changes");
    let mut transaction = pool.begin().await.context("failed to start transaction")?;
    for change in &changes {
        for statement in pgroles_core::sql::render_statements_with_context(change, &sql_ctx) {
            info!(sql = %statement, "executing");
            sqlx::query(&statement)
                .execute(transaction.as_mut())
                .await
                .with_context(|| format!("failed to execute: {statement}"))?;
        }
    }
    transaction
        .commit()
        .await
        .context("failed to commit transaction")?;

    println!(
        "Applied {total} change(s) successfully.",
        total = summary.total()
    );
    print!("{summary}");

    Ok(())
}

async fn cmd_inspect(file: &Path, database_url: &str) -> Result<()> {
    let yaml = read_manifest_file(file)?;
    let validated = validate_manifest(&yaml)?;

    let pool = connect_db(database_url).await?;
    let current = inspect_current(&pool, &validated).await?;

    print!("{}", format_role_graph_summary(&current));

    Ok(())
}

async fn cmd_generate(database_url: &str) -> Result<()> {
    let pool = connect_db(database_url).await?;

    // Introspect all non-system roles by using an unscoped inspect config.
    info!("introspecting all non-system roles for manifest generation");
    let graph = pgroles_inspect::inspect_all(
        &pool,
        &pgroles_inspect::InspectAllConfig {
            exclude_system_roles: true,
        },
    )
    .await
    .context("failed to introspect database for generation")?;

    let manifest = pgroles_core::export::role_graph_to_manifest(&graph);
    let yaml = serde_yaml::to_string(&manifest).context("failed to serialize manifest to YAML")?;
    print!("{yaml}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn connect_db(database_url: &str) -> Result<PgPool> {
    info!("connecting to database");
    PgPool::connect(database_url)
        .await
        .context("failed to connect to database")
}

async fn detect_sql_context(pool: &PgPool) -> Result<pgroles_core::sql::SqlContext> {
    let pg_version = pgroles_inspect::detect_pg_version(pool)
        .await
        .context("failed to detect PostgreSQL version")?;
    info!(
        pg_major = pg_version.major(),
        "detected PostgreSQL server version"
    );
    Ok(pgroles_core::sql::SqlContext::from_version_num(
        pg_version.version_num,
    ))
}

async fn inspect_current(
    pool: &PgPool,
    validated: &pgroles_cli::ValidatedManifest,
) -> Result<pgroles_core::model::RoleGraph> {
    // Determine whether the manifest has database-level grants.
    let has_database_grants = validated
        .expanded
        .grants
        .iter()
        .any(|g| g.on.object_type == pgroles_core::manifest::ObjectType::Database);

    let config = InspectConfig::from_expanded(&validated.expanded, has_database_grants)
        .with_additional_roles(
            validated
                .manifest
                .retirements
                .iter()
                .map(|retirement| retirement.role.clone()),
        );

    info!(
        managed_roles = config.managed_roles.len(),
        managed_schemas = config.managed_schemas.len(),
        "inspecting current database state"
    );

    pgroles_inspect::inspect(pool, &config)
        .await
        .context("failed to inspect database state")
}

async fn inspect_drop_safety(
    pool: &PgPool,
    changes: &[pgroles_core::diff::Change],
    retirements: &[pgroles_core::manifest::RoleRetirement],
) -> Result<pgroles_inspect::DropRoleSafetyAssessment> {
    let dropped_roles = planned_role_drops(changes);
    let report = inspect_drop_role_safety(pool, &dropped_roles)
        .await
        .context("failed to inspect role-drop safety")?;
    Ok(report.assess(retirements))
}
