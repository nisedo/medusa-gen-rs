use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct ParsedRepo {
    pub contracts: Vec<ParsedContract>,
    pub from_abi: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedContract {
    pub name: String,
    pub functions: Vec<ParsedFunction>,
    pub constructor: Option<ParsedConstructor>,
    pub source_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedFunction {
    pub name: String,
    pub params: Vec<FunctionParam>,
    pub payable: bool,
    pub signature: String,
    pub raw_call: bool,
    pub origin: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FunctionParam {
    pub decl: String,
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone)]
pub struct ParsedConstructor {
    pub params: Vec<FunctionParam>,
}

pub fn parse_repo(root: &Path, exclude_scripts: bool) -> Result<ParsedRepo> {
    let parsed = parse_repo_from_abi(root, exclude_scripts)?;
    if parsed.contracts.is_empty() {
        return Err(anyhow::anyhow!(
            "No contracts found. medusa-gen only supports Foundry projects; make sure `forge build` succeeds and produces artifacts."
        ));
    }
    Ok(parsed)
}

struct ForgeConfig {
    src: String,
    out: String,
    test: String,
    script: String,
}

fn parse_repo_from_abi(root: &Path, exclude_scripts: bool) -> Result<ParsedRepo> {
    let config = read_forge_config(root)?;
    let status = Command::new("forge")
        .arg("build")
        .current_dir(root)
        .status()
        .context("Failed to run forge build")?;

    if !status.success() {
        return Err(anyhow::anyhow!("forge build failed"));
    }

    let out_dir = root.join(&config.out);
    if !out_dir.is_dir() {
        return Err(anyhow::anyhow!("forge out dir not found"));
    }

    let mut contracts = Vec::new();
    let mut seen = HashSet::new();
    visit_out_dir(
        &out_dir,
        root,
        &config,
        exclude_scripts,
        &mut contracts,
        &mut seen,
    )?;
    contracts.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(ParsedRepo {
        contracts,
        from_abi: true,
    })
}

fn read_forge_config(root: &Path) -> Result<ForgeConfig> {
    let output = Command::new("forge")
        .arg("config")
        .arg("--json")
        .current_dir(root)
        .output()
        .context("Failed to run forge config")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("forge config failed"));
    }

    let value: Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse forge config JSON")?;

    let src = value
        .get("src")
        .and_then(Value::as_str)
        .unwrap_or("src")
        .to_string();
    let out = value
        .get("out")
        .and_then(Value::as_str)
        .unwrap_or("out")
        .to_string();
    let test = value
        .get("test")
        .and_then(Value::as_str)
        .unwrap_or("test")
        .to_string();
    let script = value
        .get("script")
        .and_then(Value::as_str)
        .unwrap_or("script")
        .to_string();

    Ok(ForgeConfig {
        src,
        out,
        test,
        script,
    })
}

fn visit_out_dir(
    root: &Path,
    repo_root: &Path,
    config: &ForgeConfig,
    exclude_scripts: bool,
    contracts: &mut Vec<ParsedContract>,
    seen: &mut HashSet<String>,
) -> Result<()> {
    let entries =
        fs::read_dir(root).with_context(|| format!("Failed to read dir {}", root.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name == "build-info" {
                continue;
            }
            visit_out_dir(&path, repo_root, config, exclude_scripts, contracts, seen)?;
            continue;
        }

        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        if let Some(contract) = parse_abi_artifact(&path, repo_root, config, exclude_scripts)? {
            if seen.insert(contract.name.clone()) {
                contracts.push(contract);
            }
        }
    }

    Ok(())
}

fn parse_abi_artifact(
    path: &Path,
    repo_root: &Path,
    config: &ForgeConfig,
    exclude_scripts: bool,
) -> Result<Option<ParsedContract>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let value: Value = serde_json::from_str(&content).context("Failed to parse artifact JSON")?;

    let metadata = match value.get("metadata") {
        Some(Value::Object(obj)) => obj,
        _ => return Ok(None),
    };

    let settings = match metadata.get("settings") {
        Some(Value::Object(obj)) => obj,
        _ => return Ok(None),
    };

    let compilation_target = match settings.get("compilationTarget") {
        Some(Value::Object(obj)) => obj,
        _ => return Ok(None),
    };

    let (source_path, contract_name) = match compilation_target.iter().next() {
        Some((path, name)) => (path.as_str(), name.as_str().unwrap_or_default()),
        None => return Ok(None),
    };

    let src_prefix = format!("{}/", config.src);
    if !(source_path == config.src || source_path.starts_with(&src_prefix)) {
        return Ok(None);
    }

    if source_path.starts_with(&format!("{}/", config.test)) {
        return Ok(None);
    }

    if exclude_scripts
        && (source_path.starts_with(&format!("{}/", config.script))
            || contract_name.ends_with("Script"))
    {
        return Ok(None);
    }

    if is_library_contract(repo_root, source_path, contract_name) {
        return Ok(None);
    }

    let abi = match value.get("abi").and_then(Value::as_array) {
        Some(abi) => abi,
        None => return Ok(None),
    };

    let method_identifiers = parse_method_identifiers(&value);
    let order_map = function_order_from_ast(&value, contract_name);
    let base_contracts = base_contract_names_from_ast(&value, contract_name);
    let base_signatures = load_base_signatures(repo_root, config, &base_contracts);
    let functions = parse_abi_functions(
        abi,
        &method_identifiers,
        &order_map,
        &base_signatures,
    );
    let constructor = parse_abi_constructor(abi);
    Ok(Some(ParsedContract {
        name: contract_name.to_string(),
        functions,
        constructor,
        source_path: Some(source_path.to_string()),
    }))
}

fn parse_method_identifiers(value: &Value) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(obj) = value.get("methodIdentifiers").and_then(Value::as_object) else {
        return out;
    };
    for (signature, selector) in obj {
        if let Some(selector) = selector.as_str() {
            out.insert(signature.clone(), selector.to_lowercase());
        }
    }
    out
}

fn function_order_from_ast(value: &Value, contract_name: &str) -> HashMap<String, usize> {
    let mut out = HashMap::new();
    let Some(ast) = value.get("ast").and_then(Value::as_object) else {
        return out;
    };
    let Some(nodes) = ast.get("nodes").and_then(Value::as_array) else {
        return out;
    };

    let mut contract_nodes: Option<&Vec<Value>> = None;
    for node in nodes {
        if node.get("nodeType").and_then(Value::as_str) != Some("ContractDefinition") {
            continue;
        }
        if node.get("name").and_then(Value::as_str) != Some(contract_name) {
            continue;
        }
        if let Some(children) = node.get("nodes").and_then(Value::as_array) {
            contract_nodes = Some(children);
            break;
        }
    }

    let Some(contract_nodes) = contract_nodes else {
        return out;
    };

    let mut idx = 0usize;
    for node in contract_nodes {
        if node.get("nodeType").and_then(Value::as_str) != Some("FunctionDefinition") {
            continue;
        }
        if node.get("kind").and_then(Value::as_str) != Some("function") {
            continue;
        }
        let visibility = node.get("visibility").and_then(Value::as_str).unwrap_or("");
        if visibility != "public" && visibility != "external" {
            continue;
        }
        let state = node
            .get("stateMutability")
            .and_then(Value::as_str)
            .unwrap_or("");
        if state == "view" || state == "pure" {
            continue;
        }
        let selector = match node.get("functionSelector").and_then(Value::as_str) {
            Some(selector) if !selector.is_empty() => selector.to_lowercase(),
            _ => continue,
        };
        out.insert(selector, idx);
        idx += 1;
    }
    out
}

fn parse_abi_functions(
    abi: &[Value],
    method_identifiers: &HashMap<String, String>,
    order_map: &HashMap<String, usize>,
    base_signatures: &[(String, HashSet<String>)],
) -> Vec<ParsedFunction> {
    let mut ordered = Vec::new();
    for (abi_index, item) in abi.iter().enumerate() {
        let kind = match item.get("type").and_then(Value::as_str) {
            Some(kind) => kind,
            None => continue,
        };
        if kind != "function" {
            continue;
        }
        let name = match item.get("name").and_then(Value::as_str) {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => continue,
        };
        let state = item
            .get("stateMutability")
            .and_then(Value::as_str)
            .unwrap_or("");
        if state == "view" || state == "pure" {
            continue;
        }
        let payable = state == "payable"
            || item
                .get("payable")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        let inputs = match item.get("inputs").and_then(Value::as_array) {
            Some(inputs) => inputs.as_slice(),
            None => &[],
        };
        let raw_call = inputs.iter().any(abi_type_contains_tuple);
        let signature_types: Vec<String> = inputs.iter().filter_map(abi_type_signature).collect();
        let signature = format!("{}({})", name, signature_types.join(","));

        let params = if raw_call {
            vec![FunctionParam {
                decl: "bytes calldata data".to_string(),
                name: "data".to_string(),
                ty: "bytes".to_string(),
            }]
        } else {
            inputs
                .iter()
                .enumerate()
                .filter_map(|(idx, input)| {
                    let ty = input.get("type")?.as_str()?.to_string();
                    let name = input
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|n| !n.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("arg{}", idx));
                    let decl_type = if needs_calldata(&ty) {
                        format!("{} calldata", ty)
                    } else {
                        ty.clone()
                    };
                    Some(FunctionParam {
                        decl: format!("{} {}", decl_type, name),
                        name,
                        ty,
                    })
                })
                .collect()
        };

        let selector = method_identifiers
            .get(&signature)
            .and_then(|sel| order_map.get(sel))
            .copied();

        let origin = if selector.is_none() {
            base_signatures
                .iter()
                .find(|(_, sigs)| sigs.contains(&signature))
                .map(|(name, _)| name.clone())
                .or_else(|| Some("Inherited".to_string()))
        } else {
            None
        };

        ordered.push((
            selector,
            abi_index,
            ParsedFunction {
                name,
                params,
                payable,
                signature,
                raw_call,
                origin,
            },
        ));
    }

    ordered.sort_by(|a, b| match (a.0, b.0) {
        (Some(a_idx), Some(b_idx)) => a_idx.cmp(&b_idx),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.1.cmp(&b.1),
    });

    ordered.into_iter().map(|(_, _, f)| f).collect()
}

fn parse_abi_constructor(abi: &[Value]) -> Option<ParsedConstructor> {
    for item in abi {
        let kind = match item.get("type").and_then(Value::as_str) {
            Some(kind) => kind,
            None => continue,
        };
        if kind != "constructor" {
            continue;
        }
        let inputs = match item.get("inputs").and_then(Value::as_array) {
            Some(inputs) => inputs.as_slice(),
            None => &[],
        };
        let params: Vec<FunctionParam> = inputs
            .iter()
            .enumerate()
            .filter_map(|(idx, input)| {
                let ty = abi_type_signature(input)?;
                let name = input
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|n| !n.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("arg{}", idx));
                let decl = format!("{} {}", ty, name);
                Some(FunctionParam { decl, name, ty })
            })
            .collect();
        if params.is_empty() {
            return None;
        }
        return Some(ParsedConstructor { params });
    }
    None
}

fn abi_type_signature(input: &Value) -> Option<String> {
    let ty = input.get("type")?.as_str()?;
    if !ty.starts_with("tuple") {
        return Some(ty.to_string());
    }
    let components = input.get("components").and_then(Value::as_array);
    let inner = components
        .map(|items| {
            items
                .iter()
                .filter_map(abi_type_signature)
                .collect::<Vec<String>>()
                .join(",")
        })
        .unwrap_or_default();
    let suffix = ty.strip_prefix("tuple").unwrap_or("");
    Some(format!("({}){}", inner, suffix))
}

fn abi_type_contains_tuple(input: &Value) -> bool {
    input
        .get("type")
        .and_then(Value::as_str)
        .map(|ty| ty.starts_with("tuple"))
        .unwrap_or(false)
}

fn needs_calldata(ty: &str) -> bool {
    ty == "bytes" || ty == "string" || ty.contains('[')
}

fn base_contract_names_from_ast(value: &Value, contract_name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(ast) = value.get("ast").and_then(Value::as_object) else {
        return out;
    };
    let Some(nodes) = ast.get("nodes").and_then(Value::as_array) else {
        return out;
    };
    for node in nodes {
        if node.get("nodeType").and_then(Value::as_str) != Some("ContractDefinition") {
            continue;
        }
        if node.get("name").and_then(Value::as_str) != Some(contract_name) {
            continue;
        }
        let Some(bases) = node.get("baseContracts").and_then(Value::as_array) else {
            break;
        };
        for base in bases {
            let name = base
                .get("baseName")
                .and_then(Value::as_object)
                .and_then(|obj| obj.get("name"))
                .and_then(Value::as_str);
            if let Some(name) = name {
                out.push(name.to_string());
            }
        }
        break;
    }
    out
}

fn load_base_signatures(
    repo_root: &Path,
    config: &ForgeConfig,
    bases: &[String],
) -> Vec<(String, HashSet<String>)> {
    let out_dir = repo_root.join(&config.out);
    let mut out = Vec::new();
    for base in bases {
        let Some(path) = find_artifact_for_contract(&out_dir, base) else {
            continue;
        };
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&content) else {
            continue;
        };
        let identifiers = parse_method_identifiers(&value);
        if identifiers.is_empty() {
            continue;
        }
        let sigs: HashSet<String> = identifiers.keys().cloned().collect();
        out.push((base.clone(), sigs));
    }
    out
}

fn find_artifact_for_contract(root: &Path, name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let dir_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if dir_name == "build-info" {
                continue;
            }
            if let Some(found) = find_artifact_for_contract(&path, name) {
                return Some(found);
            }
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name == format!("{name}.json") {
            return Some(path);
        }
    }
    None
}

fn is_library_contract(root: &Path, source_path: &str, contract_name: &str) -> bool {
    let path = root.join(source_path);
    let source = match fs::read_to_string(&path) {
        Ok(source) => source,
        Err(_) => return false,
    };
    let stripped = strip_comments(&source);
    let mut idx = 0usize;
    while let Some(pos) = find_keyword(&stripped, idx, "library") {
        let mut i = pos + "library".len();
        i = skip_whitespace(stripped.as_bytes(), i);
        let name_start = i;
        while i < stripped.len() && is_ident_char(stripped.as_bytes()[i]) {
            i += 1;
        }
        if name_start == i {
            idx = pos + "library".len();
            continue;
        }
        let name = stripped[name_start..i].trim();
        if name == contract_name {
            return true;
        }
        idx = i;
    }
    false
}

fn strip_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_line = false;
    let mut in_block = false;
    let mut in_string = false;
    let mut string_delim = '\0';

    while let Some(c) = chars.next() {
        if in_line {
            if c == '\n' {
                in_line = false;
                out.push(c);
            } else {
                out.push(' ');
            }
            continue;
        }
        if in_block {
            if c == '*' && matches!(chars.peek(), Some('/')) {
                chars.next();
                in_block = false;
                out.push(' ');
                out.push(' ');
            } else {
                out.push(' ');
            }
            continue;
        }
        if in_string {
            if c == '\\' {
                out.push(' ');
                if chars.next().is_some() {
                    out.push(' ');
                }
                continue;
            }
            if c == string_delim {
                in_string = false;
            }
            out.push(' ');
            continue;
        }

        if c == '/' && matches!(chars.peek(), Some('/')) {
            chars.next();
            in_line = true;
            out.push(' ');
            out.push(' ');
            continue;
        }
        if c == '/' && matches!(chars.peek(), Some('*')) {
            chars.next();
            in_block = true;
            out.push(' ');
            out.push(' ');
            continue;
        }
        if c == '"' || c == '\'' {
            in_string = true;
            string_delim = c;
            out.push(' ');
            continue;
        }
        out.push(c);
    }

    out
}

fn find_keyword(haystack: &str, start: usize, keyword: &str) -> Option<usize> {
    let mut idx = start;
    while let Some(pos) = haystack[idx..].find(keyword) {
        let abs = idx + pos;
        if is_token_boundary(haystack, abs, keyword.len()) {
            return Some(abs);
        }
        idx = abs + keyword.len();
    }
    None
}

fn is_token_boundary(haystack: &str, start: usize, len: usize) -> bool {
    let bytes = haystack.as_bytes();
    let before = if start == 0 {
        None
    } else {
        Some(bytes[start - 1])
    };
    let after = if start + len >= bytes.len() {
        None
    } else {
        Some(bytes[start + len])
    };

    let before_ok = match before {
        None => true,
        Some(b) => !is_ident_char(b),
    };
    let after_ok = match after {
        None => true,
        Some(b) => !is_ident_char(b),
    };
    before_ok && after_ok
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn skip_whitespace(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    idx
}

pub fn render_property_table(parsed: &ParsedRepo) -> String {
    let mut lines = vec!["# Handled Functions".to_string(), String::new()];

    for contract in &parsed.contracts {
        lines.push(format!("## {}", contract.name));
        lines.push(String::new());
        lines.push("| Handler | Signature |".to_string());
        lines.push("| --- | --- |".to_string());

        let mut name_counts: HashMap<String, usize> = HashMap::new();
        for func in &contract.functions {
            *name_counts
                .entry(handler_name_key(&func.name, func.origin.as_deref()))
                .or_insert(0) += 1;
        }
        let mut name_seen: HashMap<String, usize> = HashMap::new();

        for func in &contract.functions {
            let handler = handler_function_name(
                &contract.name,
                &func.name,
                func.origin.as_deref(),
                &name_counts,
                &mut name_seen,
            );
            lines.push(format!("| `{}` | `{}` |", handler, func.signature));
        }

        lines.push(String::new());
    }

    lines.join("\n")
}

pub fn build_handler_body(contract: &ParsedContract) -> String {
    let mut out = String::new();
    let target_name = contract_instance_name(&contract.name);

    let mut name_counts: HashMap<String, usize> = HashMap::new();
    for func in &contract.functions {
        *name_counts
            .entry(handler_name_key(&func.name, func.origin.as_deref()))
            .or_insert(0) += 1;
    }
    let mut name_seen: HashMap<String, usize> = HashMap::new();

    for func in &contract.functions {
        let params: Vec<String> = func.params.iter().map(|p| p.decl.clone()).collect();
        let args: Vec<String> = func.params.iter().map(|p| p.name.clone()).collect();
        let payable = if func.payable { " payable" } else { "" };
        let value = if func.payable {
            "{value: msg.value}"
        } else {
            ""
        };
        let handler_name = handler_function_name(
            &contract.name,
            &func.name,
            func.origin.as_deref(),
            &name_counts,
            &mut name_seen,
        );
        out.push_str(&format!(
            "    function {}({}) public{} {{\n",
            handler_name,
            params.join(", "),
            payable
        ));
        out.push_str("        vm.prank(msg.sender);\n");
        if !args.is_empty() {
            out.push_str("        // TODO: add vm.assume(...) to constrain inputs\n");
            for param in &func.params {
                if let Some(uint_ty) = uint_type_for_bound(&param.ty) {
                    out.push_str(&format!(
                        "        // {} = bound({}, 0, type({}).max);\n",
                        param.name, param.name, uint_ty
                    ));
                }
            }
        }
        if func.raw_call {
            let data_name = func
                .params
                .first()
                .map(|param| param.name.as_str())
                .unwrap_or("data");
            out.push_str(&format!(
                "        (bool ok, ) = address({}).call{}(abi.encodePacked(bytes4(keccak256(\"{}\")), {}));\n",
                target_name, value, func.signature, data_name
            ));
            out.push_str("        require(ok, \"handler call failed\");\n");
            out.push_str("    }\n\n");
            continue;
        }
        if args.is_empty() {
            out.push_str(&format!("        {}.{}{}();\n", target_name, func.name, value));
        } else {
            out.push_str(&format!(
                "        {}.{}{}({});\n",
                target_name,
                func.name,
                value,
                args.join(", ")
            ));
        }
        out.push_str("    }\n\n");
    }

    out.trim_end().to_string()
}

pub fn build_property_body(contract: &ParsedContract) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "    // TODO: add invariants for {}\n",
        contract.name
    ));
    out.push_str(&format!(
        "    function property_{}_TODO() public returns (bool) {{\n",
        contract.name
    ));
    out.push_str("        // TODO: implement invariants\n");
    out.push_str("        return true;\n");
    out.push_str("    }\n");
    out.trim_end().to_string()
}

fn handler_function_name(
    contract_name: &str,
    func_name: &str,
    origin: Option<&str>,
    name_counts: &HashMap<String, usize>,
    name_seen: &mut HashMap<String, usize>,
) -> String {
    let fn_suffix = to_pascal_case(func_name);
    let key = handler_name_key(func_name, origin);
    let seen = name_seen.entry(key.clone()).or_insert(0);
    *seen += 1;
    let overload_suffix = if name_counts.get(&key).copied().unwrap_or(0) > 1 {
        format!("_{}", seen)
    } else {
        String::new()
    };
    let base = match origin {
        Some(origin) if !origin.is_empty() => format!("{contract_name}{origin}"),
        _ => contract_name.to_string(),
    };
    format!("handle{}{}{}", base, fn_suffix, overload_suffix)
}

fn handler_name_key(func_name: &str, origin: Option<&str>) -> String {
    format!("{}|{}", func_name, origin.unwrap_or(""))
}

fn uint_type_for_bound(ty: &str) -> Option<String> {
    let canonical = canonicalize_type(ty);
    if canonical.contains('[') {
        return None;
    }
    let rest = canonical.strip_prefix("uint")?;
    if rest.is_empty() {
        return Some("uint256".to_string());
    }
    if rest.chars().all(|ch| ch.is_ascii_digit()) {
        return Some(format!("uint{}", rest));
    }
    None
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

fn to_pascal_case(input: &str) -> String {
    let mut out = String::new();
    let mut upper = true;
    for ch in input.chars() {
        if ch == '_' {
            upper = true;
            continue;
        }
        if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

fn canonicalize_type(ty: &str) -> String {
    let mut parts = Vec::new();
    for token in ty.split_whitespace() {
        if matches!(token, "memory" | "calldata" | "storage" | "payable") {
            continue;
        }
        parts.push(token);
    }
    parts.join("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_build_property_body_returns_bool() {
        let contract = ParsedContract {
            name: "Sample".to_string(),
            functions: Vec::new(),
            constructor: None,
            source_path: None,
        };
        let body = build_property_body(&contract);
        assert!(body.contains("returns (bool)"));
        assert!(body.contains("return true;"));
    }

    #[test]
    fn test_parse_abi_functions_orders_by_ast() {
        let abi = vec![
            json!({
                "type": "function",
                "name": "b",
                "stateMutability": "nonpayable",
                "inputs": []
            }),
            json!({
                "type": "function",
                "name": "a",
                "stateMutability": "nonpayable",
                "inputs": []
            }),
        ];

        let mut method_identifiers = HashMap::new();
        method_identifiers.insert("a()".to_string(), "aaaaaaaa".to_string());
        method_identifiers.insert("b()".to_string(), "bbbbbbbb".to_string());

        let mut order_map = HashMap::new();
        order_map.insert("aaaaaaaa".to_string(), 0);
        order_map.insert("bbbbbbbb".to_string(), 1);

        let functions = parse_abi_functions(&abi, &method_identifiers, &order_map, &[]);
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "a");
        assert_eq!(functions[1].name, "b");
    }

    #[test]
    fn test_parse_abi_functions_marks_inherited_origin() {
        let abi = vec![json!({
            "type": "function",
            "name": "withdraw",
            "stateMutability": "nonpayable",
            "inputs": [
                {"type": "uint256"},
                {"type": "address"},
                {"type": "address"}
            ]
        })];

        let method_identifiers = HashMap::new();
        let order_map = HashMap::new();
        let mut sigs = HashSet::new();
        sigs.insert("withdraw(uint256,address,address)".to_string());
        let base_signatures = vec![("ERC4626".to_string(), sigs)];

        let functions = parse_abi_functions(&abi, &method_identifiers, &order_map, &base_signatures);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].origin.as_deref(), Some("ERC4626"));
    }

    #[test]
    fn test_handler_function_name_with_origin() {
        let mut counts = HashMap::new();
        counts.insert(handler_name_key("transfer", Some("ERC4626")), 1);
        let mut seen = HashMap::new();
        let name = handler_function_name(
            "BriVault",
            "transfer",
            Some("ERC4626"),
            &counts,
            &mut seen,
        );
        assert_eq!(name, "handleBriVaultERC4626Transfer");
    }
}
