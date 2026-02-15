# Medusa Template Generator

Generate a Medusa fuzzing scaffold in `./test/fuzzing` for the repository you run it in.
Foundry-only (requires `forge`).

Made with ♥ by Wonderland (https://defi.sucks)

## Description

The following contracts are generated in `./test/fuzzing`:

```
test/fuzzing/
├── FuzzTest.t.sol
├── Setup.t.sol
├── PROPERTIES.md
├── handlers/
│   └── Handler<ContractName>.t.sol
└── properties/
    └── Properties<ContractName>.t.sol
```

Inheritance tree:

- `FuzzTest` inherits each `Properties<ContractName>`.
- Each `Properties<ContractName>` inherits its `Handler<ContractName>`.
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

- `--solc`: Solidity pragma version to emit (default: detected from `forge config --json` `solc_version`, fallback `0.8.23`).
- `--overwrite`: Overwrite `./test/fuzzing` if it already exists.

## Fuzz Cheat Sheet

Common helpers used in fuzz scaffolds (from `forge-std`):

- `vm.assume(condition)`: Discard input if condition is false (constraint filtering).
- `bound(x, min, max)`: Clamp input to a range (wraps `vm.assume` internally).
- `vm.prank(addr)`: Next call uses `addr` as `msg.sender`.
- `vm.startPrank(addr)` / `vm.stopPrank()`: Prank multiple calls.
- `hoax(addr)`: `deal(addr, 1 ether)` + `vm.prank(addr)` (or current `msg.value`).
- `startHoax(addr)` / `stopHoax()`: Like `hoax` but for multiple calls.
- `deal(tokenOrAddr, who, amount)`: Set ETH/ERC20 balance.
- `vm.warp(timestamp)`: Set `block.timestamp`.
- `vm.roll(blockNumber)`: Set `block.number`.

Docs:

```
https://getfoundry.sh/reference/cheatcodes/overview/
https://getfoundry.sh/reference/forge-std/std-cheats/
https://raw.githubusercontent.com/foundry-rs/forge-std/master/src/StdUtils.sol
```

## Parsing and ABI

`medusa-gen` runs `forge build` and reads ABIs from `out/` to discover public/external state-changing functions, including inherited ones. This requires a Foundry project.

If a function has tuple types, the handler uses a raw calldata wrapper:

- Handler signature uses `bytes data`.
- The call is `address(target).call(abi.encodePacked(selector, data))`.

## Medusa config

If `medusa.json` is not found in the repo root (or one level below), `medusa-gen` runs `medusa init` and then patches the root config:

- `"corpusDirectory": "test/fuzzing/medusa-corpus"`
- `"targetContracts": ["FuzzTest"]`
- `compilation.platformConfig.target = "."`
- `compilation.platformConfig.args = ["--compile-force-framework", "foundry", "--foundry-compile-all"]` (if empty)

## Output summary

On success, `medusa-gen` prints a summary (contracts, handlers, properties, output path, and config status).
