use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct ParsedRepo {
    pub contracts: Vec<ParsedContract>,
}

#[derive(Debug, Clone)]
pub struct ParsedContract {
    pub name: String,
    pub functions: Vec<ParsedFunction>,
}

#[derive(Debug, Clone)]
pub struct ParsedFunction {
    pub name: String,
    pub params: Vec<FunctionParam>,
    pub payable: bool,
    pub signature: String,
    pub raw_call: bool,
}

#[derive(Debug, Clone)]
pub struct FunctionParam {
    pub decl: String,
    pub name: String,
    pub ty: String,
}

const SKIP_DIRS: [&str; 11] = [
    ".git",
    "node_modules",
    "lib",
    "test",
    "tests",
    "out",
    "cache",
    "artifacts",
    "build",
    "dist",
    "target",
];

pub fn parse_repo(root: &Path, exclude_scripts: bool) -> Result<ParsedRepo> {
    match parse_repo_from_abi(root, exclude_scripts) {
        Ok(parsed) if !parsed.contracts.is_empty() => return Ok(parsed),
        Ok(_) => {
            eprintln!("ABI parsing returned no contracts; falling back to source parsing.");
        }
        Err(err) => {
            eprintln!("ABI parsing failed ({err}); falling back to source parsing.");
        }
    }
    parse_repo_from_source(root, exclude_scripts)
}

fn parse_repo_from_source(root: &Path, exclude_scripts: bool) -> Result<ParsedRepo> {
    let mut contracts = Vec::new();
    let mut seen = HashSet::new();
    let source_root = pick_source_root(root);
    visit_dir(
        source_root.as_path(),
        &mut contracts,
        &mut seen,
        exclude_scripts,
    )?;
    contracts.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ParsedRepo { contracts })
}

fn pick_source_root(root: &Path) -> PathBuf {
    let src = root.join("src");
    if src.is_dir() && dir_contains_sol(&src) {
        return src;
    }
    root.to_path_buf()
}

fn dir_contains_sol(root: &Path) -> bool {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return false,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if SKIP_DIRS.iter().any(|skip| skip == &name) {
                continue;
            }
            if dir_contains_sol(&path) {
                return true;
            }
            continue;
        }

        if path.extension().and_then(|e| e.to_str()) == Some("sol") {
            return true;
        }
    }

    false
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

    Ok(ParsedRepo { contracts })
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

    let functions = parse_abi_functions(abi);
    Ok(Some(ParsedContract {
        name: contract_name.to_string(),
        functions,
    }))
}

fn parse_abi_functions(abi: &[Value]) -> Vec<ParsedFunction> {
    let mut functions = Vec::new();
    for item in abi {
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

        functions.push(ParsedFunction {
            name,
            params,
            payable,
            signature,
            raw_call,
        });
    }
    functions
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

fn visit_dir(
    root: &Path,
    contracts: &mut Vec<ParsedContract>,
    seen: &mut HashSet<String>,
    exclude_scripts: bool,
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
            if SKIP_DIRS.iter().any(|skip| skip == &name) {
                continue;
            }
            if exclude_scripts && (name == "script" || name == "scripts") {
                continue;
            }
            visit_dir(&path, contracts, seen, exclude_scripts)?;
            continue;
        }

        if path.extension().and_then(|e| e.to_str()) != Some("sol") {
            continue;
        }

        for contract in parse_sol_file(&path)? {
            if exclude_scripts && contract.name.ends_with("Script") {
                continue;
            }
            if seen.insert(contract.name.clone()) {
                contracts.push(contract);
            }
        }
    }

    Ok(())
}

fn parse_sol_file(path: &Path) -> Result<Vec<ParsedContract>> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("Failed to read solidity file {}", path.display()))?;
    let stripped = strip_comments(&source);

    let mut contracts = Vec::new();
    let mut idx = 0usize;
    while idx < stripped.len() {
        let contract_pos = find_keyword(&stripped, idx, "contract");
        let library_pos = find_keyword(&stripped, idx, "library");
        let interface_pos = find_keyword(&stripped, idx, "interface");
        let mut next: Option<(usize, &str)> = None;
        for (pos, keyword) in [
            (contract_pos, "contract"),
            (library_pos, "library"),
            (interface_pos, "interface"),
        ] {
            if let Some(pos) = pos {
                let should_take = match &next {
                    None => true,
                    Some((best, _)) => pos < *best,
                };
                if should_take {
                    next = Some((pos, keyword));
                }
            }
        }
        let (pos, keyword) = match next {
            Some(next) => next,
            None => break,
        };
        let keyword_len = keyword.len();

        if keyword == "interface" {
            idx = pos + keyword_len;
            continue;
        }

        let mut i = pos + keyword_len;
        i = skip_whitespace(stripped.as_bytes(), i);
        let name_start = i;
        while i < stripped.len() && is_ident_char(stripped.as_bytes()[i]) {
            i += 1;
        }
        if name_start == i {
            idx = pos + keyword_len;
            continue;
        }

        let name = stripped[name_start..i].trim().to_string();
        if let Some(body) = extract_block(&stripped, i) {
            let functions = parse_functions(body);
            contracts.push(ParsedContract { name, functions });
        }
        idx = i;
    }

    Ok(contracts)
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

fn extract_block(source: &str, start_idx: usize) -> Option<&str> {
    let brace_pos = source[start_idx..].find('{')? + start_idx;
    let mut depth = 0usize;
    let mut end_idx = None;
    for (offset, ch) in source[brace_pos..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end_idx = Some(brace_pos + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    end_idx.map(|end| &source[brace_pos + 1..end])
}

fn parse_functions(body: &str) -> Vec<ParsedFunction> {
    let mut functions = Vec::new();
    let mut idx = 0usize;
    let body_bytes = body.as_bytes();

    while let Some(pos) = find_keyword(body, idx, "function") {
        let mut i = pos + "function".len();
        i = skip_whitespace(body_bytes, i);
        if i >= body_bytes.len() {
            break;
        }
        if body_bytes[i] == b'(' {
            idx = i + 1;
            continue;
        }
        let name_start = i;
        while i < body_bytes.len() && is_ident_char(body_bytes[i]) {
            i += 1;
        }
        if name_start == i {
            idx = i + 1;
            continue;
        }
        let name = body[name_start..i].trim().to_string();
        if name == "constructor" || name == "fallback" || name == "receive" {
            idx = i + 1;
            continue;
        }
        i = skip_whitespace(body_bytes, i);
        if i >= body_bytes.len() || body_bytes[i] != b'(' {
            idx = i + 1;
            continue;
        }

        let (params_str, after_params) = match extract_parens(body, i) {
            Some(v) => v,
            None => {
                idx = i + 1;
                continue;
            }
        };

        let (modifiers, after_modifiers) = extract_modifiers(body, after_params);
        let (is_public, is_external, is_internal_private, is_view_pure, is_payable) =
            analyze_modifiers(&modifiers);

        if is_internal_private || (!is_public && !is_external) || is_view_pure {
            idx = after_modifiers;
            continue;
        }

        let params = parse_params(params_str);
        let signature = signature_from_params(&name, &params);
        functions.push(ParsedFunction {
            name,
            params,
            payable: is_payable,
            signature,
            raw_call: false,
        });

        idx = after_modifiers;
    }

    functions
}

fn analyze_modifiers(modifiers: &str) -> (bool, bool, bool, bool, bool) {
    let mut is_public = false;
    let mut is_external = false;
    let mut is_internal_private = false;
    let mut is_view_pure = false;
    let mut is_payable = false;

    for token in modifiers.split_whitespace() {
        match token {
            "public" => is_public = true,
            "external" => is_external = true,
            "internal" | "private" => is_internal_private = true,
            "view" | "pure" | "constant" => is_view_pure = true,
            "payable" => is_payable = true,
            _ => {}
        }
    }

    (
        is_public,
        is_external,
        is_internal_private,
        is_view_pure,
        is_payable,
    )
}

fn parse_params(params: &str) -> Vec<FunctionParam> {
    let parts = split_params(params);
    let mut params_out = Vec::new();

    for (idx, param) in parts.into_iter().enumerate() {
        if let Some(parsed) = parse_param(&param, idx) {
            params_out.push(parsed);
        }
    }

    params_out
}

fn split_params(params: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (i, ch) in params.char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if paren_depth == 0 && bracket_depth == 0 => {
                parts.push(params[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = params[start..].trim();
    if !tail.is_empty() {
        parts.push(tail.to_string());
    }
    parts
}

fn parse_param(param: &str, idx: usize) -> Option<FunctionParam> {
    let param = param.trim();
    if param.is_empty() {
        return None;
    }

    let data_location = ["memory", "calldata", "storage", "payable"];
    let mut name: Option<String> = None;

    if param.chars().any(|c| c.is_whitespace()) {
        if let Some(last) = param.split_whitespace().last() {
            if !data_location.contains(&last) && !param.ends_with(')') && !param.ends_with(']') {
                name = Some(last.to_string());
            }
        }
    }

    let (ty, name) = if let Some(name) = name {
        let name_pos = param.rfind(&name).unwrap_or(param.len());
        let ty = param[..name_pos].trim_end().to_string();
        let ty = if ty.is_empty() { param.to_string() } else { ty };
        (ty, name)
    } else {
        (param.to_string(), format!("arg{}", idx))
    };

    let decl = if ty.is_empty() {
        name.clone()
    } else {
        format!("{} {}", ty, name)
    };

    Some(FunctionParam { decl, name, ty })
}

fn signature_from_params(name: &str, params: &[FunctionParam]) -> String {
    let types: Vec<String> = params.iter().map(|p| canonicalize_type(&p.ty)).collect();
    format!("{}({})", name, types.join(","))
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

fn extract_parens(source: &str, open_idx: usize) -> Option<(&str, usize)> {
    let mut depth = 0usize;
    let mut end_idx = None;
    for (offset, ch) in source[open_idx..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end_idx = Some(open_idx + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end_idx?;
    Some((&source[open_idx + 1..end], end + 1))
}

fn extract_modifiers(source: &str, start_idx: usize) -> (String, usize) {
    let mut depth = 0usize;
    let mut end = source.len();
    for (offset, ch) in source[start_idx..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            '{' | ';' if depth == 0 => {
                end = start_idx + offset;
                break;
            }
            _ => {}
        }
    }
    (source[start_idx..end].trim().to_string(), end)
}

pub fn render_property_table(parsed: &ParsedRepo) -> String {
    let mut lines = vec![
        "# Handled Functions".to_string(),
        String::new(),
        "| Contract | Function | Signature |".to_string(),
        "| --- | --- | --- |".to_string(),
    ];

    for contract in &parsed.contracts {
        for func in &contract.functions {
            lines.push(format!(
                "| {} | {} | `{}` |",
                contract.name, func.name, func.signature
            ));
        }
    }

    lines.join("\n")
}

pub fn build_handler_interface(contract: &ParsedContract) -> String {
    let mut out = String::new();
    let iface_name = format!("I{}", contract.name);
    out.push_str(&format!("interface {} {{\n", iface_name));
    for func in &contract.functions {
        if func.raw_call {
            continue;
        }
        let params: Vec<String> = func.params.iter().map(|p| p.decl.clone()).collect();
        let payable = if func.payable { " payable" } else { "" };
        out.push_str(&format!(
            "    function {}({}) external{};\n",
            func.name,
            params.join(", "),
            payable
        ));
    }
    out.push_str("}\n");
    out
}

pub fn build_handler_body(contract: &ParsedContract) -> String {
    let mut out = String::new();
    let iface_name = format!("I{}", contract.name);
    let target_name = format!("target{}", contract.name);
    let set_target_name = format!("setTarget{}", contract.name);
    out.push_str(&format!("    {} internal {};\n\n", iface_name, target_name));
    out.push_str(&format!(
        "    function {}({} _target) public {{\n",
        set_target_name, iface_name
    ));
    out.push_str(&format!("        {} = _target;\n", target_name));
    out.push_str("    }\n\n");

    let mut name_counts: HashMap<String, usize> = HashMap::new();
    for func in &contract.functions {
        *name_counts.entry(func.name.clone()).or_insert(0) += 1;
    }
    let mut name_seen: HashMap<String, usize> = HashMap::new();

    for func in &contract.functions {
        let fn_suffix = to_pascal_case(&func.name);
        let seen = name_seen.entry(func.name.clone()).or_insert(0);
        *seen += 1;
        let overload_suffix = if name_counts.get(&func.name).copied().unwrap_or(0) > 1 {
            format!("_{}", seen)
        } else {
            String::new()
        };
        let params: Vec<String> = func.params.iter().map(|p| p.decl.clone()).collect();
        let args: Vec<String> = func.params.iter().map(|p| p.name.clone()).collect();
        let payable = if func.payable { " payable" } else { "" };
        let value = if func.payable {
            "{value: msg.value}"
        } else {
            ""
        };
        out.push_str(&format!(
            "    function handle{}{}{}({}) public{} {{\n",
            contract.name,
            fn_suffix,
            overload_suffix,
            params.join(", "),
            payable
        ));
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
            out.push_str(&format!(
                "        {}.{}{}();\n",
                target_name, func.name, value
            ));
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
