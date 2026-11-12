use anyhow::{Context, bail};
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use std::{env, path::PathBuf, str::FromStr};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let Some(group) = args.next() else { usage() };
    if group != "reports" {
        usage()
    }
    let Some(command) = args.next() else { usage() };
    let url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://ai-agent-permission-enforcer.db".into());
    let options = SqliteConnectOptions::from_str(&url)?.read_only(true);
    let db = SqlitePool::connect_with(options)
        .await
        .context("open AI Agent Permission Enforcer database")?;
    match command.as_str() {
        "list" => list(&db).await?,
        "export" => {
            let id = args.next().unwrap_or_else(|| usage());
            let mut output = None;
            while let Some(arg) = args.next() {
                if arg == "--output" {
                    output = args.next().map(PathBuf::from);
                } else {
                    usage()
                }
            }
            let output = output.unwrap_or_else(|| PathBuf::from(format!("report-{id}.json")));
            export(&db, &id, &output).await?;
            println!("Exported {id} to {}", output.display());
        }
        _ => usage(),
    }
    Ok(())
}

async fn list(db: &SqlitePool) -> anyhow::Result<()> {
    let rows = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id,tenant_id,status,created_at FROM simulation_reports ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await
    .context("query simulation reports")?;
    if rows.is_empty() {
        println!("No simulation reports found.");
    }
    for (id, tenant, status, created) in rows {
        println!("{id}\t{tenant}\t{status}\t{created}");
    }
    Ok(())
}

async fn export(db: &SqlitePool, id: &str, output: &PathBuf) -> anyhow::Result<()> {
    let raw =
        sqlx::query_scalar::<_, String>("SELECT report_json FROM simulation_reports WHERE id=?")
            .bind(id)
            .fetch_optional(db)
            .await
            .context("query simulation report")?;
    let Some(raw) = raw else {
        bail!("simulation report not found: {id}")
    };
    let parsed: serde_json::Value = serde_json::from_str(&raw).context("parse stored report")?;
    let pretty = serde_json::to_vec_pretty(&parsed)?;
    tokio::fs::write(output, pretty)
        .await
        .context("write exported report")?;
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "Usage:\n  ai-agent-permission-enforcer-cli reports list\n  ai-agent-permission-enforcer-cli reports export <report-id> [--output <path>]\n\nSet DATABASE_URL to select the SQLite database."
    );
    std::process::exit(2)
}
