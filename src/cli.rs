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
    /// Solidity version
    #[arg(short, long, default_value = "0.8.23")]
    pub solc: String,

    /// Exclude script contracts from parsed projects (e.g. Foundry script/)
    #[arg(long, default_value_t = true)]
    pub exclude_scripts: bool,

    /// Overwrite existing files
    #[arg(short, long, default_value_t = false)]
    pub overwrite: bool,
}
