# Medusa Template Generator

Generate a Medusa fuzzing scaffold in `./test/fuzzing` for the repository you run it in.

Made with ♥ by Wonderland (https://defi.sucks)

## Description

The following contracts are generated in `./test/fuzzing`:

```
test/fuzzing/
  FuzzTest.t.sol
  Setup.t.sol
  PROPERTIES.md
  handlers/
    HandlersParent.t.sol
    Handler<ContractName>.t.sol
  properties/
    PropertiesParent.t.sol
    Properties<ContractName>.t.sol
```

Inheritance tree:

- `FuzzTest` inherits `PropertiesParent`.
- `PropertiesParent` inherits each `Properties<ContractName>`.
- Each `Properties<ContractName>` inherits `HandlersParent`.
- `HandlersParent` inherits each `Handler<ContractName>`.
- Each `Handler<ContractName>` inherits `Setup`.

## Installation

Build from source:

```bash
cargo install --git https://github.com/nisedo/medusa-gen-rs --force
```

Or from a local checkout:

```bash
cargo install --path . --force
```

## Usage

Run from the root of the target repo:

```bash
medusa-gen --overwrite
```

## Options

- `--solc`: Solidity pragma version to emit (default: `0.8.23`).
- `--exclude-scripts` / `--no-exclude-scripts`: Exclude `script/` directories and `*Script` contracts (default: exclude).
- `--overwrite`: Overwrite `./test/fuzzing` if it already exists.

Legacy flags `--nb-handlers` and `--nb-properties` are ignored (kept for compatibility).

## Parsing and ABI

By default, `medusa-gen` runs `forge build` and reads ABIs from `out/` to discover public/external state-changing functions, including inherited ones. If ABI parsing fails, it falls back to a lightweight source parser and logs the fallback.

If a function has tuple types, the handler uses a raw calldata wrapper:

- Handler signature uses `bytes data`.
- The call is `address(target).call(abi.encodePacked(selector, data))`.

## Medusa config

If `medusa.json` is not found in the repo root (or one level below), `medusa-gen` runs `medusa init` and then patches the root config, preserving formatting:

- `"corpusDirectory": "test/fuzzing/medusa-corpus"`
- `"targetContracts": ["FuzzTest"]`
- `compilation.platformConfig.target = "test/fuzzing"`

## Output summary

On success, `medusa-gen` prints a summary (contracts, handlers, properties, output path, and config status).
