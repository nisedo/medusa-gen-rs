use clap::{crate_authors, Parser};

#[derive(Parser)]
#[command(
    name = "medusa-gen",
    author = crate_authors!(",\n"),
    version,
    about = "Generate template for Medusa fuzzing campaigns",
    long_about = None,
)]
pub struct Args {
    /// Solidity version to emit (defaults to forge config solc_version)
    #[arg(short, long)]
    pub solc: Option<String>,

    /// Overwrite existing files
    #[arg(short, long, default_value_t = false)]
    pub overwrite: bool,
}
