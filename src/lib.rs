pub mod cli;
mod parser;
mod types;

use crate::cli::Args;
use crate::parser::{
    build_handler_body, build_property_body, parse_repo, render_property_table, ParsedContract,
    ParsedRepo,
};
use crate::types::{Contract, ContractBuilder, ContractType};

use anyhow::{Context, Result};
use fs_extra::dir::{copy, CopyOptions};
use serde_json::Value;
use std::fmt::Write;
use std::fs::{self, DirBuilder};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use std::{collections::HashSet};

/// Create the "HandlerA, HandlerB" in "contract HandlersParent is HandlerA, HandlerB"
/// the "is" statement is conditionnaly added in the template
fn parse_parents(parents: &[Contract]) -> String {
    parents
        .iter()
        .fold(String::new(), |mut output, b| {
            let _ = write!(output, "{}, ", b.name);
            output
        })
        .trim_end_matches(", ")
        .to_string()
}

/// Create imports for entry point from property contracts.
fn parse_entry_imports(properties: &[Contract]) -> String {
    properties.iter().fold(String::new(), |mut output, b| {
        let _ = writeln!(
            output,
            "import {{ {} }} from \"./properties/{}.t.sol\";",
            b.name, b.name
        );
        output
    })
}

fn build_setup_body(parsed: &ParsedRepo) -> String {
    let mut out = String::new();
    out.push_str("    // Target contracts\n");
    for contract in &parsed.contracts {
        let instance = contract_instance_name(&contract.name);
        out.push_str(&format!(
            "    {} internal {};\n",
            contract.name, instance
        ));
    }

    out.push_str("\n    function setUp() public virtual {\n");
    out.push_str("        // TODO: deploy and initialize target contracts\n");
    for contract in &parsed.contracts {
        let instance = contract_instance_name(&contract.name);
        let constructor_params = contract
            .constructor
            .as_ref()
            .map(|constructor| {
                constructor
                    .params
                    .iter()
                    .map(|param| param.decl.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|params| !params.is_empty());
        let can_autodeploy = parsed.from_abi && constructor_params.is_none();
        if can_autodeploy {
            out.push_str(&format!(
                "        {} = new {}();\n",
                instance, contract.name
            ));
            continue;
        }
        if let Some(params) = constructor_params {
            out.push_str(&format!(
                "        // {} = new {}(/* {} */);\n",
                instance, contract.name, params
            ));
        } else {
            out.push_str(&format!(
                "        // {} = new {}(/* ... */);\n",
                instance, contract.name
            ));
        }
    }
    if parsed
        .contracts
        .iter()
        .any(|contract| contract.functions.iter().any(|func| func.payable))
    {
        out.push_str("\n        // TODO: fund this contract for payable handlers\n");
        out.push_str("        // vm.deal(address(this), 10 ether);\n");
    }
    out.push_str("    }\n");

    out.trim_end().to_string()
}

fn build_setup_imports(parsed: &ParsedRepo) -> String {
    let mut seen = HashSet::new();
    let mut out = String::new();
    out.push_str("import {Test} from \"forge-std/Test.sol\";\n");
    for contract in &parsed.contracts {
        let Some(path) = &contract.source_path else {
            continue;
        };
        let line = format!("import {{ {} }} from \"{}\";\n", contract.name, path);
        if seen.insert(line.clone()) {
            out.push_str(&line);
        }
    }
    out
}

fn contract_instance_name(name: &str) -> String {
    let mut out = String::new();
    for (idx, ch) in name.chars().enumerate() {
        if idx == 0 {
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn detect_solc_version(root: &Path) -> Option<String> {
    let output = Command::new("forge")
        .arg("config")
        .arg("--json")
        .current_dir(root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value: Value = serde_json::from_slice(&output.stdout).ok()?;

    if let Some(version) = value.get("solc_version").and_then(Value::as_str) {
        let trimmed = version.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(version) = value.get("solcVersion").and_then(Value::as_str) {
        let trimmed = version.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(version) = value.get("solc").and_then(Value::as_str) {
        let trimmed = version.trim();
        if !trimmed.is_empty() && looks_like_version(trimmed) {
            return Some(trimmed.to_string());
        }
    }

    let out_dir = value
        .get("out")
        .and_then(Value::as_str)
        .unwrap_or("out");
    let out_path = root.join(out_dir);
    let artifact = find_first_artifact(&out_path)?;
    read_solc_version_from_artifact(&artifact)
}

fn find_first_artifact(root: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name == "build-info" {
                continue;
            }
            if let Some(found) = find_first_artifact(&path) {
                return Some(found);
            }
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            return Some(path);
        }
    }
    None
}

fn read_solc_version_from_artifact(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&content).ok()?;
    if let Some(version) = value
        .get("compiler")
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("version"))
        .and_then(Value::as_str)
    {
        return Some(normalize_solc_version(version));
    }
    let metadata = value.get("metadata")?;
    let metadata_value: Value = match metadata {
        Value::String(payload) => serde_json::from_str(payload).ok()?,
        other => other.clone(),
    };
    let version = metadata_value
        .get("compiler")
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("version"))
        .and_then(Value::as_str)?;
    Some(normalize_solc_version(version))
}

fn normalize_solc_version(version: &str) -> String {
    let trimmed = version.trim();
    match trimmed.find('+') {
        Some(pos) => trimmed[..pos].to_string(),
        None => trimmed.to_string(),
    }
}

fn looks_like_version(value: &str) -> bool {
    if value.contains('/') || value.contains('\\') {
        return false;
    }
    value
        .chars()
        .all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | '^' | '~' | '>' | '<' | '='))
}

fn find_medusa_json_child(root: &Path) -> Option<PathBuf> {
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let candidate = path.join("medusa.json");
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn update_medusa_json(path: &Path) -> Result<()> {
    let content = fs::read_to_string(path).context(format!("Failed to read {}", path.display()))?;
    let (updated, changed) = patch_medusa_json(&content);
    if changed {
        fs::write(path, updated).context("Failed to write medusa.json")?;
    }
    Ok(())
}

fn patch_medusa_json(content: &str) -> (String, bool) {
    let mut output: Vec<String> = Vec::new();
    let mut changed = false;
    let mut depth: i32 = 0;
    let mut compilation_depth: Option<i32> = None;
    let mut platform_depth: Option<i32> = None;
    let mut platform_indent = String::new();
    let mut saw_target = false;
    let mut saw_args = false;

    for raw_line in content.split_inclusive('\n') {
        let (line, line_ending) = split_line_ending(raw_line);
        let trimmed = line.trim();
        let depth_before = depth;

        if compilation_depth.is_none()
            && trimmed.starts_with("\"compilation\"")
            && trimmed.contains('{')
        {
            compilation_depth = Some(depth_before + 1);
        }

        if platform_depth.is_none()
            && compilation_depth.is_some()
            && trimmed.starts_with("\"platformConfig\"")
            && trimmed.contains('{')
        {
            platform_depth = Some(depth_before + 1);
            platform_indent = leading_whitespace(line);
            saw_target = false;
            saw_args = false;
        }

        if let Some(pdepth) = platform_depth {
            if depth_before == pdepth && trimmed.starts_with('}') && (!saw_target || !saw_args) {
                let mut inserts = Vec::new();
                if !saw_target {
                    inserts.push(format!("{}  \"target\": \".\"", platform_indent));
                }
                if !saw_args {
                    inserts.push(format!(
                        "{}  \"args\": [\"--compile-force-framework\", \"foundry\", \"--foundry-compile-all\"]",
                        platform_indent
                    ));
                }
                if let Some(last) = output.last_mut() {
                    let (last_line, last_ending) = split_line_ending(last);
                    let last_trim = last_line.trim_end();
                    if !last_trim.is_empty()
                        && !last_trim.ends_with(',')
                        && !last_trim.ends_with('{')
                        && !last_trim.ends_with('[')
                    {
                        let mut updated = String::new();
                        updated.push_str(last_line);
                        updated.push(',');
                        updated.push_str(last_ending);
                        *last = updated;
                    }
                }
                let insert_ending = if line_ending.is_empty() { "\n" } else { line_ending };
                let inserts_len = inserts.len();
                for (idx, insert_line) in inserts.into_iter().enumerate() {
                    let comma = if idx + 1 < inserts_len { "," } else { "" };
                    output.push(format!("{insert_line}{comma}{insert_ending}"));
                }
                changed = true;
            }
        }

        let mut updated_line = line.to_string();

        if trimmed.starts_with("\"corpusDirectory\"") {
            if let Some(replaced) = replace_empty_string_field(
                line,
                "\"corpusDirectory\"",
                "test/fuzzing/medusa-corpus",
            ) {
                updated_line = replaced;
                changed = true;
            }
        }

        if trimmed.starts_with("\"targetContracts\"") {
            if let Some(replaced) =
                replace_empty_array_field(line, "\"targetContracts\"", "[\"FuzzTest\"]")
            {
                updated_line = replaced;
                changed = true;
            }
        }

        if let Some(pdepth) = platform_depth {
            if depth_before >= pdepth && trimmed.starts_with("\"target\"") {
                let indent = leading_whitespace(line);
                saw_target = true;
                if trimmed.contains("\"test/fuzzing\"") || trimmed.contains(": \"\"") {
                    let comma = if trimmed.ends_with(',') { "," } else { "" };
                    let new_line = format!("{indent}\"target\": \".\"{comma}");
                    if new_line != updated_line {
                        updated_line = new_line;
                        changed = true;
                    }
                }
            }
            if depth_before >= pdepth && trimmed.starts_with("\"args\"") {
                saw_args = true;
                if let Some(replaced) = replace_empty_array_field(
                    line,
                    "\"args\"",
                    "[\"--compile-force-framework\", \"foundry\", \"--foundry-compile-all\"]",
                ) {
                    updated_line = replaced;
                    changed = true;
                }
            }
        }

        output.push(format!("{updated_line}{line_ending}"));

        depth += brace_delta(line);

        if let Some(cdepth) = compilation_depth {
            if depth < cdepth {
                compilation_depth = None;
            }
        }
        if let Some(pdepth) = platform_depth {
            if depth < pdepth {
                platform_depth = None;
                saw_target = false;
                saw_args = false;
            }
        }
    }

    (output.concat(), changed)
}

fn leading_whitespace(line: &str) -> String {
    line.chars().take_while(|c| c.is_whitespace()).collect()
}

fn split_line_ending(line: &str) -> (&str, &str) {
    if let Some(stripped) = line.strip_suffix("\r\n") {
        (stripped, "\r\n")
    } else if let Some(stripped) = line.strip_suffix('\n') {
        (stripped, "\n")
    } else {
        (line, "")
    }
}

fn replace_empty_string_field(line: &str, key: &str, value: &str) -> Option<String> {
    if !line.contains(key) {
        return None;
    }
    let (prefix, rest) = line.split_once(':')?;
    let rest_trim_start = rest.trim_start();
    let ws_len = rest.len() - rest_trim_start.len();
    let leading_ws = &rest[..ws_len];
    let mut rest_trim = rest_trim_start.trim_end();
    let comma = if rest_trim.ends_with(',') {
        rest_trim = rest_trim.trim_end_matches(',').trim_end();
        ","
    } else {
        ""
    };
    if rest_trim == "\"\"" {
        Some(format!("{prefix}:{leading_ws}\"{value}\"{comma}"))
    } else {
        None
    }
}

fn replace_empty_array_field(line: &str, key: &str, value: &str) -> Option<String> {
    if !line.contains(key) {
        return None;
    }
    let (prefix, rest) = line.split_once(':')?;
    let rest_trim_start = rest.trim_start();
    let ws_len = rest.len() - rest_trim_start.len();
    let leading_ws = &rest[..ws_len];
    let mut rest_trim = rest_trim_start.trim_end();
    let comma = if rest_trim.ends_with(',') {
        rest_trim = rest_trim.trim_end_matches(',').trim_end();
        ","
    } else {
        ""
    };
    let rest_no_ws: String = rest_trim.chars().filter(|c| !c.is_whitespace()).collect();
    if rest_no_ws == "[]" {
        Some(format!("{prefix}:{leading_ws}{value}{comma}"))
    } else {
        None
    }
}

fn brace_delta(line: &str) -> i32 {
    let mut delta = 0;
    let mut in_string = false;
    let mut prev_escape = false;
    for ch in line.chars() {
        if in_string {
            if prev_escape {
                prev_escape = false;
            } else if ch == '\\' {
                prev_escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            continue;
        }
        if ch == '{' {
            delta += 1;
        } else if ch == '}' {
            delta -= 1;
        }
    }
    delta
}

fn ensure_medusa_json(root: &Path) -> Result<()> {
    let root_path = root.join("medusa.json");
    if !root_path.is_file() {
        if let Some(child) = find_medusa_json_child(root) {
            fs::copy(&child, &root_path).context("Failed to copy medusa.json to repo root")?;
        } else {
            let status = std::process::Command::new("medusa")
                .arg("init")
                .current_dir(root)
                .status()
                .context("Failed to run medusa init")?;

            if !status.success() {
                return Err(anyhow::anyhow!("medusa init failed"));
            }

            if !root_path.is_file() {
                return Err(anyhow::anyhow!(
                    "medusa init did not create medusa.json in repo root"
                ));
            }
        }
    }

    update_medusa_json(&root_path)?;
    Ok(())
}

fn handler_name_for(contract_name: &str) -> String {
    if contract_name.starts_with("Handler") {
        contract_name.to_string()
    } else {
        format!("Handler{}", contract_name)
    }
}

fn entry_point_body() -> String {
    "    constructor() payable {\n        setUp();\n    }\n".to_string()
}

fn build_handler_contract_for(
    contract: &ParsedContract,
    handler_name: String,
    solc_version: &str,
) -> Contract {
    let imports = ContractType::Handler.import().to_string();
    let body = build_handler_body(contract);

    ContractBuilder::new()
        .with_type(&ContractType::Handler)
        .with_name(handler_name)
        .with_imports(imports)
        .with_body(body)
        .with_abstract(true)
        .with_solc(solc_version.to_string())
        .build()
}

fn create_handler_contracts_from_parsed(
    parsed: &ParsedRepo,
    solc_version: &str,
    path: &Path,
) -> Result<Vec<Contract>> {
    if parsed.contracts.is_empty() {
        return Err(anyhow::anyhow!(
            "No contracts found in current directory for handler generation"
        ));
    }

    DirBuilder::new()
        .recursive(true)
        .create(path)
        .context("Failed to create directory for handler contracts")?;

    let mut contracts = Vec::new();
    for contract in &parsed.contracts {
        let name = handler_name_for(&contract.name);
        let handler_contract = build_handler_contract_for(contract, name, solc_version);
        handler_contract
            .write_rendered_contract(path)
            .context("Failed to write rendered handler contract")?;

        contracts.push(handler_contract);
    }

    Ok(contracts)
}

fn create_property_contracts_from_parsed(
    parsed: &ParsedRepo,
    solc_version: &str,
    path: &Path,
) -> Result<Vec<Contract>> {
    if parsed.contracts.is_empty() {
        return Err(anyhow::anyhow!(
            "No contracts found in current directory for property generation"
        ));
    }

    DirBuilder::new()
        .recursive(true)
        .create(path)
        .context("Failed to create directory for property contracts")?;

    let mut contracts = Vec::new();
    for contract in &parsed.contracts {
        let name = format!("{}{}", ContractType::Property.name(), contract.name);
        let handler_name = handler_name_for(&contract.name);
        let imports = format!(
            "import {{ {} }} from \"../handlers/{}.t.sol\";\n",
            handler_name, handler_name
        );
        let property_contract = ContractBuilder::new()
            .with_type(&ContractType::Property)
            .with_name(name)
            .with_imports(imports)
            .with_parents(handler_name)
            .with_body(build_property_body(contract))
            .with_abstract(true)
            .with_solc(solc_version.to_string())
            .build();

        property_contract
            .write_rendered_contract(path)
            .context("Failed to write rendered property contract")?;

        contracts.push(property_contract);
    }

    Ok(contracts)
}

/// Move the content of a temp folder to the fuzz test folder
fn move_temp_contents(temp_dir: &TempDir, overwrite: bool) -> Result<()> {
    let path = Path::new("./test/fuzzing");
    if path.exists() {
        if !overwrite {
            return Err(anyhow::anyhow!(
                "Fuzz test folder already exists, did you mean --overwrite ?"
            ));
        }
    } else {
        DirBuilder::new()
            .recursive(true)
            .create(path)
            .context("Failed to create fuzz test folder")?;
    }

    let options = CopyOptions {
        overwrite,
        skip_exist: !overwrite,
        content_only: true,
        ..Default::default()
    };

    copy(temp_dir.path(), path, &options).context("Failed to copy temp directory contents")?;

    Ok(())
}

/// Generate and write the test suite
pub fn generate_test_suite(args: &Args) -> Result<()> {
    let temp_dir = TempDir::new().context("Failed creating temp dir")?; // will be deleted once dropped
    let current_dir = std::env::current_dir().context("Failed to determine current directory")?;

    ensure_medusa_json(current_dir.as_path()).context("Failed to ensure medusa.json")?;

    let parsed_repo = parse_repo(current_dir.as_path(), true)
        .context("Failed to parse current directory")?;

    let solc_version = args
        .solc
        .clone()
        .or_else(|| detect_solc_version(current_dir.as_path()))
        .unwrap_or_else(|| "0.8.23".to_string());

    let handler_contracts = create_handler_contracts_from_parsed(
        &parsed_repo,
        solc_version.as_str(),
        &temp_dir.path().join(ContractType::Handler.directory_name()),
    )
    .context("Failed to generate handler parents from parsed repo")?;

    let property_contracts = create_property_contracts_from_parsed(
        &parsed_repo,
        solc_version.as_str(),
        &temp_dir
            .path()
            .join(ContractType::Property.directory_name()),
    )
    .context("Failed to generate handler property")?;

    let entry_point = ContractBuilder::new()
        .with_type(&ContractType::EntryPoint)
        .with_imports(parse_entry_imports(&property_contracts))
        .with_parents(parse_parents(&property_contracts))
        .with_body(entry_point_body())
        .with_solc(solc_version.clone())
        .build();

    entry_point
        .write_rendered_contract(temp_dir.path())
        .context("Failed to write rendered entry point")?;

    let setup = ContractBuilder::new()
        .with_type(&ContractType::Setup)
        .with_imports(build_setup_imports(&parsed_repo))
        .with_parents("Test".to_string())
        .with_abstract(true)
        .with_body(build_setup_body(&parsed_repo))
        .with_solc(solc_version.clone())
        .build();

    setup
        .write_rendered_contract(temp_dir.path())
        .context("Failed to write rendered setup point")?;

    let table = render_property_table(&parsed_repo);
    std::fs::write(temp_dir.path().join("PROPERTIES.md"), table)
        .context("Failed to write PROPERTIES.md")?;

    move_temp_contents(&temp_dir, args.overwrite).context("Failed to move temp contents")?;

    println!("Generated Medusa fuzzing scaffold");
    println!("- contracts: {}", parsed_repo.contracts.len());
    println!("- handlers: {}", handler_contracts.len());
    println!("- properties: {}", property_contracts.len());
    println!("- output: ./test/fuzzing");
    println!("- medusa.json: patched");

    Ok(())
}

// TESTS //

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_parse_parents() {
        let parents = vec![Contract {
            licence: "MIT".to_string(),
            solc: "0.8.23".to_string(),
            imports: "".to_string(),
            name: "HandlerA".to_string(),
            parents: "HandlersParent".to_string(),
            body: "".to_string(),
            is_abstract: false,
        }];

        assert_eq!(parse_parents(parents.as_ref()), "HandlerA");
    }

    #[test]
    fn test_parse_parents_two() {
        let parents = vec![
            Contract {
                licence: "MIT".to_string(),
                solc: "0.8.23".to_string(),
                imports: "".to_string(),
                name: "HandlerA".to_string(),
                parents: "HandlersParent".to_string(),
                body: "".to_string(),
                is_abstract: false,
            },
            Contract {
                licence: "MIT".to_string(),
                solc: "0.8.23".to_string(),
                imports: "".to_string(),
                name: "HandlerB".to_string(),
                parents: "HandlersParent".to_string(),
                body: "".to_string(),
                is_abstract: false,
            },
        ];

        assert_eq!(parse_parents(parents.as_ref()), "HandlerA, HandlerB");
    }

    #[test]
    fn test_parse_parents_empty() {
        let parents = vec![];
        assert_eq!(parse_parents(parents.as_ref()), "");
    }

    #[test]
    fn test_parse_entry_imports() {
        let props = vec![Contract {
            licence: "MIT".to_string(),
            solc: "0.8.23".to_string(),
            imports: "".to_string(),
            name: "PropertiesA".to_string(),
            parents: "".to_string(),
            body: "".to_string(),
            is_abstract: false,
        }];

        assert_eq!(
            parse_entry_imports(props.as_ref()),
            "import { PropertiesA } from \"./properties/PropertiesA.t.sol\";\n"
        );
    }

    #[test]
    fn test_entry_point_body() {
        let body = entry_point_body();
        assert!(body.contains("constructor() payable"));
        assert!(body.contains("setUp();"));
    }

    // All the move_temp_contents are in serial to avoid having race conditions
    #[test]
    #[serial]
    fn test_move_temp_contents() -> Result<()> {
        let temp_dir = TempDir::new().context("Failed to create temp dir")?;

        // Create a test file in temp directory
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, "test content")?;

        let result = move_temp_contents(&temp_dir, true);
        assert!(result.is_ok());

        let dest_file = Path::new("./test/fuzzing/test.txt");
        assert!(dest_file.exists());
        assert_eq!(std::fs::read_to_string(dest_file)?, "test content");

        std::fs::remove_dir_all("./test/fuzzing")?;
        Ok(())
    }

    #[test]
    #[serial]
    fn test_move_temp_contents_no_overwrite() -> Result<()> {
        let temp_dir = TempDir::new().context("Failed to create temp dir")?;

        std::fs::create_dir_all("./test/fuzzing")?;

        let result = move_temp_contents(&temp_dir, false);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Fuzz test folder already exists, did you mean --overwrite ?"
        );

        std::fs::remove_dir_all("./test/fuzzing")?;
        Ok(())
    }

    #[test]
    #[serial]
    fn test_move_temp_contents_new_directory() -> Result<()> {
        let temp_dir = TempDir::new().context("Failed to create temp dir")?;

        // source directory with test file
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir(&source_dir)?;
        let test_file = source_dir.join("test.txt");
        std::fs::write(&test_file, "test content")?;

        // TempDir for source that will be moved
        let source_temp =
            TempDir::new_in(&source_dir).context("Failed to create source temp dir")?;
        std::fs::write(source_temp.path().join("test.txt"), "test content")?;

        // Set current directory to temp_dir
        let original_dir = std::env::current_dir()?;
        std::env::set_current_dir(&temp_dir)?;

        // Test moving to non-existent directory
        let result = move_temp_contents(&source_temp, false);
        if let Err(ref e) = result {
            println!("Error: {:#}", e);
        }
        assert!(result.is_ok());

        let fuzz_dir = Path::new("./test/fuzzing");
        assert!(fuzz_dir.exists());
        assert!(fuzz_dir.is_dir());
        let dest_file = fuzz_dir.join("test.txt");
        assert!(dest_file.exists());
        assert_eq!(std::fs::read_to_string(dest_file)?, "test content");

        std::env::set_current_dir(original_dir)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn test_generate_test_suite() -> Result<()> {
        let temp_dir = TempDir::new().context("Failed to create temp dir")?;
        let original_dir = std::env::current_dir()?;
        std::env::set_current_dir(&temp_dir)?;

        let source_dir = temp_dir.path().join("src");
        std::fs::create_dir_all(&source_dir)?;
        std::fs::write(
            source_dir.join("Sample.sol"),
            "pragma solidity ^0.8.0; contract Sample { function bump(uint256 x) public { } }",
        )?;
        std::fs::write(
            temp_dir.path().join("medusa.json"),
            r#"{
  "fuzzing": {
    "corpusDirectory": "",
    "targetContracts": []
  }
}"#,
        )?;

        let args = Args {
            overwrite: true,
            solc: Some("0.8.23".to_string()),
        };

        let result = generate_test_suite(&args);
        assert!(result.is_ok());

        let fuzz_dir = Path::new("test/fuzzing");
        assert!(fuzz_dir.join("handlers/HandlerSample.t.sol").exists());
        assert!(fuzz_dir.join("properties/PropertiesSample.t.sol").exists());
        assert!(fuzz_dir.join("Setup.t.sol").exists());
        assert!(fuzz_dir.join("FuzzTest.t.sol").exists());

        std::env::set_current_dir(original_dir)?;
        Ok(())
    }
}
