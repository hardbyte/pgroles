//! pgroles CLI — declarative PostgreSQL role policy manager.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sqlx::PgPool;
use tracing::info;

use pgroles_cli::{
    PlanSummary, apply_role_retirements, compute_plan, format_bundle_plan_json,
    format_bundle_validation_result, format_managed_scope_summary, format_plan_json,
    format_plan_sql_with_context, format_role_graph_summary, format_validation_result,
    inject_password_changes, planned_role_drops, read_manifest_file, resolve_passwords,
    validate_bundle_file, validate_manifest,
};
use pgroles_core::diff::{ReconciliationMode, filter_changes};
use pgroles_core::ownership::validate_changes_against_managed_surface;
use pgroles_core::visual::{self, VisualManagedScope, VisualSource};
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
    /// Validate a manifest or bundle file. No database connection required.
    Validate {
        /// Path to the policy manifest YAML file.
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file.
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,
    },

    /// Show the SQL changes needed to converge the database to the manifest.
    /// Alias: plan.
    #[command(alias = "plan")]
    Diff {
        /// Path to the policy manifest YAML file.
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file.
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,

        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,

        /// Output format: "sql" for raw SQL, "summary" for a brief summary, "json" for machine-readable JSON.
        #[arg(long, default_value = "sql")]
        format: OutputFormat,

        /// Reconciliation mode: how aggressively to converge the database.
        ///
        /// - authoritative: full convergence — anything not in the manifest is revoked/dropped (default).
        /// - additive: only grant, never revoke — safe for incremental adoption.
        /// - adopt: manage declared roles fully, but never drop undeclared roles.
        #[arg(long, default_value = "authoritative")]
        mode: CliReconciliationMode,

        /// Exit with code 2 when drift is detected (useful for CI gates).
        #[arg(long, default_value_t = true, overrides_with = "no_exit_code")]
        exit_code: bool,

        /// Disable non-zero exit when drift is detected.
        #[arg(long, action = clap::ArgAction::SetTrue, overrides_with = "exit_code")]
        no_exit_code: bool,
    },

    /// Apply the changes to bring the database in sync with the manifest.
    Apply {
        /// Path to the policy manifest YAML file.
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file.
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,

        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,

        /// Print the SQL that would be executed without actually running it.
        #[arg(long)]
        dry_run: bool,

        /// Reconciliation mode: how aggressively to converge the database.
        ///
        /// - authoritative: full convergence — anything not in the manifest is revoked/dropped (default).
        /// - additive: only grant, never revoke — safe for incremental adoption.
        /// - adopt: manage declared roles fully, but never drop undeclared roles.
        #[arg(long, default_value = "authoritative")]
        mode: CliReconciliationMode,
    },

    /// Inspect the current database state for roles and privileges.
    Inspect {
        /// Path to policy manifest YAML. When provided, scopes output to roles
        /// and schemas declared in the manifest. When omitted, shows all
        /// non-system database roles and privileges.
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file. When provided, scopes output to
        /// the composed bundle ownership boundaries.
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,

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

        /// Write output to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Visualize the role graph structure.
    ///
    /// Renders roles, memberships, grants, and default privileges as a graph
    /// in various output formats.
    Graph {
        #[command(subcommand)]
        source: GraphSource,
    },
}

#[derive(Subcommand)]
enum GraphSource {
    /// Build the graph from a manifest file (desired state).
    Desired {
        /// Path to the policy manifest YAML file.
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file.
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,

        /// Output format.
        #[arg(long, default_value = "tree")]
        format: GraphFormat,

        /// Write output to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Build the graph from a live database (current state).
    Current {
        /// Path to the policy manifest YAML file (required when --scope=managed unless --bundle is used).
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file (required when --scope=managed unless --file is used).
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,

        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,

        /// Which roles to include: "managed" (requires -f) or "all".
        #[arg(long, default_value = "managed")]
        scope: GraphScope,

        /// Output format.
        #[arg(long, default_value = "tree")]
        format: GraphFormat,

        /// Write output to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum GraphFormat {
    Tree,
    Json,
    Dot,
    Mermaid,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum GraphScope {
    Managed,
    All,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum OutputFormat {
    Sql,
    Summary,
    Json,
}

/// CLI wrapper for `ReconciliationMode` — clap derives the `ValueEnum` from this.
#[derive(Clone, Debug, clap::ValueEnum)]
enum CliReconciliationMode {
    Authoritative,
    Additive,
    Adopt,
}

impl From<CliReconciliationMode> for ReconciliationMode {
    fn from(cli: CliReconciliationMode) -> Self {
        match cli {
            CliReconciliationMode::Authoritative => ReconciliationMode::Authoritative,
            CliReconciliationMode::Additive => ReconciliationMode::Additive,
            CliReconciliationMode::Adopt => ReconciliationMode::Adopt,
        }
    }
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
        Commands::Validate { file, bundle } => {
            cmd_validate(file.as_deref(), bundle.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Diff {
            file,
            bundle,
            database_url,
            format,
            mode,
            exit_code,
            no_exit_code,
        } => {
            cmd_diff(
                file.as_deref(),
                bundle.as_deref(),
                &database_url,
                &format,
                mode.into(),
                exit_code && !no_exit_code,
            )
            .await
        }
        Commands::Apply {
            file,
            bundle,
            database_url,
            dry_run,
            mode,
        } => {
            cmd_apply(
                file.as_deref(),
                bundle.as_deref(),
                &database_url,
                dry_run,
                mode.into(),
            )
            .await?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Inspect {
            file,
            bundle,
            database_url,
        } => {
            cmd_inspect(file.as_deref(), bundle.as_deref(), &database_url).await?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Generate {
            database_url,
            output,
        } => {
            cmd_generate(&database_url, output.as_deref()).await?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Graph { source } => match source {
            GraphSource::Desired {
                file,
                bundle,
                format,
                output,
            } => {
                cmd_graph_desired(
                    file.as_deref(),
                    bundle.as_deref(),
                    &format,
                    output.as_deref(),
                )?;
                Ok(ExitCode::SUCCESS)
            }
            GraphSource::Current {
                file,
                bundle,
                database_url,
                scope,
                format,
                output,
            } => {
                cmd_graph_current(
                    file.as_deref(),
                    bundle.as_deref(),
                    &database_url,
                    &scope,
                    &format,
                    output.as_deref(),
                )
                .await?;
                Ok(ExitCode::SUCCESS)
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

fn cmd_validate(file: Option<&Path>, bundle: Option<&Path>) -> Result<()> {
    if let Some(bundle_path) = bundle {
        let validated = validate_bundle_file(bundle_path)?;
        print!("{}", format_bundle_validation_result(&validated));
        return Ok(());
    }

    let file_path = file.unwrap_or_else(|| Path::new("pgroles.yaml"));
    let yaml = read_manifest_file(file_path)?;
    let validated = validate_manifest(&yaml)?;
    print!("{}", format_validation_result(&validated));
    Ok(())
}

async fn cmd_diff(
    file: Option<&Path>,
    bundle: Option<&Path>,
    database_url: &str,
    format: &OutputFormat,
    mode: ReconciliationMode,
    use_exit_code: bool,
) -> Result<ExitCode> {
    if let Some(bundle_path) = bundle {
        let validated = validate_bundle_file(bundle_path)?;
        let pool = connect_db(database_url).await?;
        let inspect_config = inspect_config_for_bundle(&validated);
        let current = inspect_current_with_config(&pool, &inspect_config).await?;
        let resolved_passwords = resolve_passwords(&validated.composed.expanded)
            .context("failed to resolve role passwords")?;
        info!(%mode, "reconciliation mode");
        let changes = inject_password_changes(
            filter_changes(
                apply_role_retirements(
                    compute_plan(&current, &validated.composed.desired),
                    &validated.composed.manifest.retirements,
                ),
                mode,
            ),
            &resolved_passwords,
        );
        validate_changes_against_managed_surface(
            &changes,
            &validated.composed.managed_change_surface,
        )?;
        let drop_safety =
            inspect_drop_safety(&pool, &changes, &validated.composed.manifest.retirements).await?;
        let summary = PlanSummary::from_changes(&changes);

        match format {
            OutputFormat::Sql => {
                let sql_ctx = detect_sql_context_with_config(&pool, &inspect_config).await?;
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
                println!(
                    "{}",
                    format_bundle_plan_json(&changes, &validated.composed)?
                );
            }
        }

        return if use_exit_code && summary.has_structural_changes() {
            Ok(ExitCode::from(EXIT_DRIFT))
        } else {
            Ok(ExitCode::SUCCESS)
        };
    }

    let file_path = file.unwrap_or_else(|| Path::new("pgroles.yaml"));
    let yaml = read_manifest_file(file_path)?;
    let validated = validate_manifest(&yaml)?;

    let pool = connect_db(database_url).await?;
    let current = inspect_current(&pool, &validated).await?;

    let resolved_passwords =
        resolve_passwords(&validated.expanded).context("failed to resolve role passwords")?;
    info!(%mode, "reconciliation mode");
    let changes = inject_password_changes(
        filter_changes(
            apply_role_retirements(
                compute_plan(&current, &validated.desired),
                &validated.manifest.retirements,
            ),
            mode,
        ),
        &resolved_passwords,
    );
    let drop_safety = inspect_drop_safety(&pool, &changes, &validated.manifest.retirements).await?;
    let summary = PlanSummary::from_changes(&changes);

    match format {
        OutputFormat::Sql => {
            let sql_ctx = detect_sql_context(&pool, &validated.expanded).await?;
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

    // Use structural changes for exit code — password-only changes don't
    // constitute drift because passwords can't be read back for comparison.
    if use_exit_code && summary.has_structural_changes() {
        Ok(ExitCode::from(EXIT_DRIFT))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

async fn cmd_apply(
    file: Option<&Path>,
    bundle: Option<&Path>,
    database_url: &str,
    dry_run: bool,
    mode: ReconciliationMode,
) -> Result<()> {
    if let Some(bundle_path) = bundle {
        let validated = validate_bundle_file(bundle_path)?;
        let pool = connect_db(database_url).await?;
        let inspect_config = inspect_config_for_bundle(&validated);
        let sql_ctx = detect_sql_context_with_config(&pool, &inspect_config).await?;

        // Detect cloud provider privilege level and warn about unsupported operations.
        let privilege_level = pgroles_inspect::detect_privilege_level(&pool)
            .await
            .context("failed to detect privilege level")?;
        info!(level = %privilege_level, "detected privilege level");

        let current = inspect_current_with_config(&pool, &inspect_config).await?;

        let resolved_passwords = resolve_passwords(&validated.composed.expanded)
            .context("failed to resolve role passwords")?;
        info!(%mode, "reconciliation mode");
        let changes = inject_password_changes(
            filter_changes(
                apply_role_retirements(
                    compute_plan(&current, &validated.composed.desired),
                    &validated.composed.manifest.retirements,
                ),
                mode,
            ),
            &resolved_passwords,
        );
        validate_changes_against_managed_surface(
            &changes,
            &validated.composed.managed_change_surface,
        )?;

        // Validate changes against privilege level.
        let priv_warnings = pgroles_inspect::cloud::validate_changes_for_privilege_level(
            &changes,
            &privilege_level,
        );
        if !priv_warnings.is_empty() {
            for warning in &priv_warnings {
                eprintln!("Warning: {warning}");
            }
        }

        let drop_safety =
            inspect_drop_safety(&pool, &changes, &validated.composed.manifest.retirements).await?;
        let summary = PlanSummary::from_changes(&changes);

        if summary.is_empty() {
            println!("No changes needed. Database is in sync with manifest.");
            return Ok(());
        }

        let sql_output = format_plan_sql_with_context(&changes, &sql_ctx);

        if dry_run {
            println!("-- DRY RUN: the following SQL would be executed:\n");
            print!("{sql_output}");
            eprintln!("\n{}", summary.format_plan());
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
            let is_sensitive = matches!(change, pgroles_core::diff::Change::SetPassword { .. });
            for statement in pgroles_core::sql::render_statements_with_context(change, &sql_ctx) {
                if is_sensitive {
                    info!("executing: ALTER ROLE ... PASSWORD [REDACTED]");
                } else {
                    info!(sql = %statement, "executing");
                }
                sqlx::query(&statement)
                    .execute(transaction.as_mut())
                    .await
                    .with_context(|| {
                        if is_sensitive {
                            "failed to execute: ALTER ROLE ... PASSWORD [REDACTED]".to_string()
                        } else {
                            format!("failed to execute: {statement}")
                        }
                    })?;
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
        print!("{}", summary.format_applied());

        return Ok(());
    }

    let file_path = file.unwrap_or_else(|| Path::new("pgroles.yaml"));
    let yaml = read_manifest_file(file_path)?;
    let validated = validate_manifest(&yaml)?;

    let pool = connect_db(database_url).await?;
    let sql_ctx = detect_sql_context(&pool, &validated.expanded).await?;

    // Detect cloud provider privilege level and warn about unsupported operations.
    let privilege_level = pgroles_inspect::detect_privilege_level(&pool)
        .await
        .context("failed to detect privilege level")?;
    info!(level = %privilege_level, "detected privilege level");

    let current = inspect_current(&pool, &validated).await?;

    let resolved_passwords =
        resolve_passwords(&validated.expanded).context("failed to resolve role passwords")?;
    info!(%mode, "reconciliation mode");
    let changes = inject_password_changes(
        filter_changes(
            apply_role_retirements(
                compute_plan(&current, &validated.desired),
                &validated.manifest.retirements,
            ),
            mode,
        ),
        &resolved_passwords,
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
        eprintln!("\n{}", summary.format_plan());
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
        let is_sensitive = matches!(change, pgroles_core::diff::Change::SetPassword { .. });
        for statement in pgroles_core::sql::render_statements_with_context(change, &sql_ctx) {
            if is_sensitive {
                info!("executing: ALTER ROLE ... PASSWORD [REDACTED]");
            } else {
                info!(sql = %statement, "executing");
            }
            sqlx::query(&statement)
                .execute(transaction.as_mut())
                .await
                .with_context(|| {
                    if is_sensitive {
                        "failed to execute: ALTER ROLE ... PASSWORD [REDACTED]".to_string()
                    } else {
                        format!("failed to execute: {statement}")
                    }
                })?;
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
    print!("{}", summary.format_applied());

    Ok(())
}

async fn cmd_inspect(file: Option<&Path>, bundle: Option<&Path>, database_url: &str) -> Result<()> {
    // Validate manifest or bundle before connecting so YAML errors fail fast.
    let validated_manifest = match (file, bundle) {
        (Some(path), None) => {
            let yaml = read_manifest_file(path)?;
            Some(validate_manifest(&yaml)?)
        }
        (None, Some(_)) | (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };
    let validated_bundle = match (file, bundle) {
        (None, Some(path)) => Some(validate_bundle_file(path)?),
        (Some(_), None) | (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };

    let pool = connect_db(database_url).await?;

    let current = if let Some(ref validated) = validated_manifest {
        inspect_current(&pool, validated).await?
    } else if let Some(ref validated) = validated_bundle {
        let inspect_config = inspect_config_for_bundle(validated);
        inspect_current_with_config(&pool, &inspect_config).await?
    } else {
        info!("no manifest provided, inspecting all non-system roles");
        pgroles_inspect::inspect_all(
            &pool,
            &pgroles_inspect::InspectAllConfig {
                exclude_system_roles: true,
            },
        )
        .await
        .context("failed to introspect database")?
    };

    if let Some(ref validated) = validated_bundle {
        print!(
            "{}",
            format_managed_scope_summary(&validated.composed.managed_scope)
        );
    };

    print!("{}", format_role_graph_summary(&current));

    // Query and display PUBLIC grants (informational only).
    let public_grants = pgroles_inspect::fetch_public_grants(&pool)
        .await
        .context("failed to query PUBLIC grants")?;
    let public_output = pgroles_inspect::format_public_grants(&public_grants);
    if !public_output.is_empty() {
        print!("{public_output}");
    }

    Ok(())
}

async fn cmd_generate(database_url: &str, output: Option<&Path>) -> Result<()> {
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

    match output {
        Some(path) => {
            std::fs::write(path, &yaml)
                .with_context(|| format!("failed to write output to {}", path.display()))?;
            info!(path = %path.display(), "manifest written");
        }
        None => print!("{yaml}"),
    }

    Ok(())
}

fn cmd_graph_desired(
    file: Option<&Path>,
    bundle: Option<&Path>,
    format: &GraphFormat,
    output: Option<&Path>,
) -> Result<()> {
    let visual = if let Some(bundle_path) = bundle {
        let validated = validate_bundle_file(bundle_path)?;
        let mut visual =
            visual::build_visual_graph(&validated.composed.desired, VisualSource::Desired);
        if matches!(format, GraphFormat::Json) {
            visual.meta.managed_scope =
                Some(VisualManagedScope::from(&validated.composed.managed_scope));
        }
        visual
    } else {
        let file_path = file.unwrap_or_else(|| Path::new("pgroles.yaml"));
        let yaml = read_manifest_file(file_path)?;
        let validated = validate_manifest(&yaml)?;
        visual::build_visual_graph(&validated.desired, VisualSource::Desired)
    };

    let rendered = render_graph(&visual, format);
    write_output(&rendered, output)
}

async fn cmd_graph_current(
    file: Option<&Path>,
    bundle: Option<&Path>,
    database_url: &str,
    scope: &GraphScope,
    format: &GraphFormat,
    output: Option<&Path>,
) -> Result<()> {
    // Validate file requirement before connecting to the database.
    if matches!(scope, GraphScope::Managed) && file.is_none() && bundle.is_none() {
        anyhow::bail!(
            "--file or --bundle is required when --scope=managed (to determine which roles are managed)"
        );
    }

    let pool = connect_db(database_url).await?;

    let graph = match scope {
        GraphScope::Managed => {
            if let Some(bundle_path) = bundle {
                let validated = validate_bundle_file(bundle_path)?;
                let inspect_config = inspect_config_for_bundle(&validated);
                let graph = inspect_current_with_config(&pool, &inspect_config).await?;
                let mut visual = visual::build_visual_graph(&graph, VisualSource::Current);
                if matches!(format, GraphFormat::Json) {
                    visual.meta.managed_scope =
                        Some(VisualManagedScope::from(&validated.composed.managed_scope));
                }
                let rendered = render_graph(&visual, format);
                return write_output(&rendered, output);
            } else {
                let file = file.expect("validated above");
                let yaml = read_manifest_file(file)?;
                let validated = validate_manifest(&yaml)?;
                inspect_current(&pool, &validated).await?
            }
        }
        GraphScope::All => {
            info!("introspecting all non-system roles");
            pgroles_inspect::inspect_all(
                &pool,
                &pgroles_inspect::InspectAllConfig {
                    exclude_system_roles: true,
                },
            )
            .await
            .context("failed to introspect database")?
        }
    };

    let visual = visual::build_visual_graph(&graph, VisualSource::Current);
    let rendered = render_graph(&visual, format);
    write_output(&rendered, output)
}

fn render_graph(visual: &visual::VisualGraph, format: &GraphFormat) -> String {
    match format {
        GraphFormat::Tree => visual::render_tree(visual),
        GraphFormat::Json => visual::render_json(visual),
        GraphFormat::Dot => visual::render_dot(visual),
        GraphFormat::Mermaid => visual::render_mermaid(visual),
    }
}

fn write_output(content: &str, output: Option<&Path>) -> Result<()> {
    match output {
        Some(path) => {
            std::fs::write(path, content)
                .with_context(|| format!("failed to write output to {}", path.display()))?;
            info!(path = %path.display(), "output written");
        }
        None => print!("{content}"),
    }
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

async fn detect_sql_context(
    pool: &PgPool,
    expanded: &pgroles_core::manifest::ExpandedManifest,
) -> Result<pgroles_core::sql::SqlContext> {
    let inspect_config = InspectConfig::from_expanded(expanded, false);
    detect_sql_context_with_config(pool, &inspect_config).await
}

async fn detect_sql_context_with_config(
    pool: &PgPool,
    inspect_config: &InspectConfig,
) -> Result<pgroles_core::sql::SqlContext> {
    let pg_version = pgroles_inspect::detect_pg_version(pool)
        .await
        .context("failed to detect PostgreSQL version")?;
    let privilege_schemas: Vec<&str> = inspect_config
        .privilege_schemas
        .iter()
        .map(|schema| schema.as_str())
        .collect();
    let relation_inventory = pgroles_inspect::fetch_relation_inventory(pool, &privilege_schemas)
        .await
        .context("failed to inspect relation inventory")?;
    info!(
        pg_major = pg_version.major(),
        "detected PostgreSQL server version"
    );
    Ok(
        pgroles_core::sql::SqlContext::from_version_num(pg_version.version_num)
            .with_relation_inventory(relation_inventory),
    )
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
        .any(|g| g.object.object_type == pgroles_core::manifest::ObjectType::Database);

    let config = InspectConfig::from_expanded(&validated.expanded, has_database_grants)
        .with_additional_roles(
            validated
                .manifest
                .retirements
                .iter()
                .map(|retirement| retirement.role.clone()),
        );

    inspect_current_with_config(pool, &config).await
}

fn inspect_config_for_bundle(validated: &pgroles_cli::ValidatedBundle) -> InspectConfig {
    InspectConfig::from_managed_scope(
        &validated.composed.managed_scope,
        &validated.composed.expanded,
        validated
            .composed
            .managed_change_surface
            .needs_database_privilege_inspection(),
    )
    .with_additional_roles(
        validated
            .composed
            .manifest
            .retirements
            .iter()
            .map(|retirement| retirement.role.clone()),
    )
}

async fn inspect_current_with_config(
    pool: &PgPool,
    config: &InspectConfig,
) -> Result<pgroles_core::model::RoleGraph> {
    info!(
        managed_roles = config.managed_roles.len(),
        managed_schemas = config.managed_schemas.len(),
        privilege_schemas = config.privilege_schemas.len(),
        "inspecting current database state"
    );

    pgroles_inspect::inspect(pool, config)
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

#[cfg(test)]
mod tests {
    use super::*;
    use pgroles_core::model::{RoleGraph, RoleState};

    fn sample_visual_graph() -> pgroles_core::visual::VisualGraph {
        let mut graph = RoleGraph::default();
        graph.roles.insert(
            "analytics".to_string(),
            RoleState {
                login: true,
                ..RoleState::default()
            },
        );
        visual::build_visual_graph(&graph, VisualSource::Desired)
    }

    #[test]
    fn render_graph_delegates_to_requested_format() {
        let visual = sample_visual_graph();

        assert_eq!(
            render_graph(&visual, &GraphFormat::Tree),
            visual::render_tree(&visual)
        );
        assert_eq!(
            render_graph(&visual, &GraphFormat::Json),
            visual::render_json(&visual)
        );
        assert_eq!(
            render_graph(&visual, &GraphFormat::Dot),
            visual::render_dot(&visual)
        );
        assert_eq!(
            render_graph(&visual, &GraphFormat::Mermaid),
            visual::render_mermaid(&visual)
        );
    }

    #[test]
    fn write_output_writes_file_when_path_provided() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let path = dir.path().join("graph.txt");

        write_output("graph output", Some(&path)).expect("write_output should succeed");

        let written = std::fs::read_to_string(&path).expect("failed to read output file");
        assert_eq!(written, "graph output");
    }

    #[test]
    fn graph_current_managed_requires_file_before_connecting() {
        let runtime = tokio::runtime::Runtime::new().expect("failed to create runtime");
        let error = runtime
            .block_on(cmd_graph_current(
                None,
                None,
                "postgres://unused",
                &GraphScope::Managed,
                &GraphFormat::Tree,
                None,
            ))
            .expect_err("managed graph without --file/--bundle should fail");

        assert!(
            error
                .to_string()
                .contains("--file or --bundle is required when --scope=managed"),
            "unexpected error: {error:#}"
        );
    }
}
