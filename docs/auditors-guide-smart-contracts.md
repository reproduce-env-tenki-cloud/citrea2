# Auditors Guide: Smart Contracts

This guide is designed for security auditors examining the Citrea repository, with a focus on smart contracts, critical components, testing infrastructure, and security considerations.

## Overview

Citrea is the first rollup that enhances Bitcoin blockspace capabilities with zero-knowledge technology. It uses Bitcoin as its data availability layer and settlement layer, with zero-knowledge proofs ensuring transaction validity.

### Repository Structure

The repository is organized into several key crates under `crates/`:

```
crates/
├── evm/                     # EVM implementation and smart contracts
├── citrea-stf/             # State transition function
├── bitcoin-da/             # Bitcoin data availability layer
├── batch-prover/           # Batch proving services
├── light-client-prover/    # Light client proving
├── sequencer/              # Transaction sequencing
├── prover-services/        # Proving infrastructure
├── sovereign-sdk/          # Forked Sovereign SDK components
└── [other crates...]
```

## Critical Smart Contracts

### System Contracts (`crates/evm/src/evm/system_contracts/`)

These are the core smart contracts that power the Citrea rollup, located in `crates/evm/src/evm/system_contracts/src/`:

#### **Bridge.sol** (Critical - Cross-chain Security)
- **Purpose**: Handles cross-chain asset transfers between Bitcoin and Citrea
- **Key Components**:
  - Bitcoin transaction validation using bitcoin-spv
  - Schnorr signature verification precompile integration
  - UTXO management and tracking
  - Witness data processing
- **Security Focus**: 
  - Asset custody and withdrawal mechanisms
  - Bitcoin SPV proof validation
  - Schnorr signature verification (address(0x200))
  - Re-entrancy protection
  - UTXO double-spend prevention
- **Constants**: 
  - `LIGHT_CLIENT`: address(0x3100000000000000000000000000000000000001)
  - `SYSTEM_CALLER`: address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD)

#### **BitcoinLightClient.sol** (Critical - Consensus Security)
- **Purpose**: Stores Bitcoin block hashes and witness root hashes for L1 blocks
- **Key Components**:
  - Block number tracking and initialization
  - Block hash storage mapping
  - Witness root storage and validation
  - Coinbase depth tracking
- **Security Focus**:
  - Proper block number initialization (only once)
  - Sequential block processing (no skips/overwrites)
  - System caller authorization
  - Block hash and witness root integrity
- **Events**: `BlockInfoAdded(uint256 blockNumber, bytes32 blockHash, bytes32 merkleRoot, uint256 coinbaseDepth)`

#### **Fee Vault Contracts**
- **BaseFeeVault.sol**: Manages base fee collection
- **L1FeeVault.sol**: Handles L1 (Bitcoin) fee payments
- **PriorityFeeVault.sol**: Manages priority fee distribution
- **FeeVault.sol**: Base fee vault implementation
- **Security Focus**:
  - Fee calculation accuracy
  - Withdrawal permissions and access controls
  - Economic security parameters
  - Fee distribution mechanisms

#### **WCBTC9.sol** (Critical - Asset Security)
- **Purpose**: Wrapped Bitcoin implementation with 9 decimal places
- **Key Features**:
  - 9 decimal places to match Bitcoin satoshi precision
  - Standard ERC20 implementation with extensions
- **Security Focus**:
  - Minting/burning mechanisms
  - Total supply tracking and verification
  - Access controls for minting/burning operations
  - Decimal precision handling

#### **FailedDepositVault.sol**
- **Purpose**: Handles failed deposit recovery mechanisms
- **Security Focus**:
  - Recovery procedures and authorization
  - Time locks and delays for security
  - Proper authorization checks

### System Contract Deployment and Genesis

The system contracts use Foundry for compilation and deployment:

```bash
# Generate genesis state from system contracts
make genesis        # Development genesis
make genesis-prod   # Production genesis
```

These commands run Foundry scripts that compile and deploy the system contracts to generate the initial state.

### Test Contracts (`crates/evm/src/smart_contracts/`)

These contracts are used for testing EVM functionality:

- **SimpleStorageContract**: Basic storage operations testing
- **PayableContract**: Payment functionality testing
- **LogsContract**: Event emission testing
- **SelfDestructorContract**: Contract destruction testing
- **CallerContract**: Cross-contract call testing
- **Various precompile test contracts**: P256, Schnorr verification, etc.

**Note**: While these are test contracts, they help verify the correctness of the EVM implementation.

## Key Crates for Security Review

### 1. citrea-evm (`crates/evm/`)
- **Description**: EVM implementation for Citrea rollup
- **Key Files**:
  - `src/evm/`: Core EVM execution logic
  - `src/smart_contracts/`: Test contract implementations
  - `src/evm/system_contracts/`: System contract sources
- **Security Focus**:
  - EVM execution correctness
  - Gas metering accuracy
  - Precompile implementations
  - State transition validity

### 2. citrea-stf (`crates/citrea-stf/`)
- **Description**: State transition function implementing rollup logic
- **Key Files**:
  - `src/lib.rs`: Main STF implementation
  - `src/verifier.rs`: ZK proof verification logic
- **Security Focus**:
  - State transition correctness
  - ZK proof verification
  - Cross-module interactions

### 3. bitcoin-da (`crates/bitcoin-da/`)
- **Description**: Bitcoin data availability layer implementation
- **Security Focus**:
  - Bitcoin transaction parsing
  - Data extraction from Bitcoin blocks
  - Consensus rule compliance

### 4. batch-prover & light-client-prover
- **Description**: Zero-knowledge proof generation
- **Security Focus**:
  - Proof generation correctness
  - Circuit constraints
  - Trusted setup parameters

## Testing Infrastructure

### Environment Variables

Key environment variables used in testing:

```bash
# Core testing variables
RISC0_DEV_MODE=1              # Enable development mode for RISC0
PARALLEL_PROOF_LIMIT=1        # Limit parallel proof generation
SKIP_GUEST_BUILD=1           # Skip guest code builds (for linting)

# End-to-end testing
CITREA_CLI_E2E_TEST_BINARY   # Path to CLI binary for E2E tests
CITREA_E2E_TEST_BINARY       # Path to main binary for E2E tests

# Ethereum Foundation tests
EF_TESTS_DIR=crates/evm/ethereum-tests  # Location of EF test suite
```

### Running Tests

#### Full Test Suite
```bash
make test
```
This runs the complete test suite with:
- `RISC0_DEV_MODE=1 PARALLEL_PROOF_LIMIT=1`
- `cargo nextest run -j15 --locked --workspace --all-features --no-fail-fast`

#### Ethereum Foundation Tests
```bash
make ef-tests
```
Downloads and runs Ethereum Foundation test suite to verify EVM compatibility.

#### System Contract Tests (Foundry)
```bash
cd crates/evm/src/evm/system_contracts
forge test -vvv
```
Runs Foundry tests for system contracts with verbose output.

#### Test with Output
```bash
make test-nocapture
```
Runs tests with output visible for debugging.

#### Coverage Analysis
```bash
make coverage        # Generate LCOV coverage report
make coverage-html   # Generate HTML coverage report
```

#### Linting and Code Quality
```bash
make lint           # Run all linting checks
make lint-fix       # Auto-fix linting issues
```

#### Smart Contract Specific Commands
```bash
# Build system contracts
cd crates/evm/src/evm/system_contracts && forge build

# Test system contracts
cd crates/evm/src/evm/system_contracts && forge test

# Generate gas snapshots
cd crates/evm/src/evm/system_contracts && forge snapshot
```

### Test Categories

1. **Unit Tests**: Test individual components in isolation
   - Located throughout `crates/*/src/` directories
   - Focus on individual function and module correctness

2. **Integration Tests**: Test module interactions
   - Located in `crates/*/tests/` directories
   - Test cross-module communication and state transitions

3. **End-to-End Tests**: Full system testing
   - Located in `bin/citrea/tests/`
   - Test complete workflows from user transactions to finalization

4. **EF Tests**: Ethereum compatibility testing
   - Downloads Ethereum Foundation test vectors
   - Verifies EVM execution compatibility

5. **System Contract Tests**: Foundry-based smart contract tests
   - Located in `crates/evm/src/evm/system_contracts/test/`
   - Test system contract functionality and edge cases

6. **Fuzz Tests**: Property-based testing (where applicable)
   - Uses `cargo-fuzz` or property-based testing frameworks
   - Tests invariants and edge cases

### Key Test Utilities

#### TestContract Trait (`crates/evm/src/smart_contracts/mod.rs`)
```rust
pub trait TestContract: Default {
    fn byte_code(&self) -> Vec<u8>;
}
```
- Used by all test smart contracts
- Provides standardized interface for contract deployment in tests

#### Test Smart Contracts
- **SimpleStorageContract**: Basic storage operations
- **PayableContract**: Payment functionality
- **LogsContract**: Event emission testing
- **CallerContract**: Cross-contract calls
- **SelfDestructorContract**: Contract destruction
- **Precompile test contracts**: P256, Schnorr, KZG verification

These contracts help verify EVM execution correctness and can reveal issues in:
- Gas metering
- State management
- Precompile implementations
- Event emission
- Contract interaction patterns

## Security Audit Focus Areas

### 1. Smart Contract Security

#### System Contracts (Priority: Critical)
- **Bridge.sol**:
  - Bitcoin SPV proof validation correctness
  - Schnorr signature verification integration
  - UTXO tracking and double-spend prevention
  - Cross-chain message validation
  - Access control for system operations
  - Withdrawal delay and security mechanisms

- **BitcoinLightClient.sol**:
  - Block hash storage integrity
  - Witness root validation
  - Sequential block processing enforcement
  - System caller authorization
  - Block number initialization security

- **WCBTC9.sol**:
  - Minting/burning authorization
  - Decimal precision handling (9 decimals)
  - Total supply accounting
  - ERC20 compliance and security

- **Fee Vaults**:
  - Fee calculation accuracy
  - Withdrawal authorization mechanisms
  - Economic attack vectors
  - Fee distribution fairness

#### EVM Implementation Security
- **Gas Metering**: Ensure accurate gas calculations prevent DoS
- **Precompiles**: Verify cryptographic implementations (especially custom ones)
- **State Management**: Check state root calculations and persistence
- **Execution Correctness**: Verify EVM opcode implementations match Ethereum

#### Common Vulnerability Patterns to Check
- Re-entrancy vulnerabilities in cross-contract calls
- Integer overflow/underflow in fee calculations
- Access control bypasses
- Front-running attacks in fee mechanisms
- Signature replay attacks
- Time-based attacks using block timestamps

### 2. Zero-Knowledge Proof System

#### Circuit Security
- **Constraint System**: Verify all state transitions are properly constrained
- **Arithmetization**: Check arithmetic circuits for completeness
- **Proof Verification**: Validate proof verification logic in STF
- **Public Inputs**: Ensure all public inputs are properly validated

#### Integration Points
- **STF Integration**: Verify state transition function correctly uses ZK proofs
- **Batch Proof Aggregation**: Check aggregation logic for security
- **Proof Generation**: Verify proof generation doesn't leak sensitive data

### 3. Bitcoin Integration Security

#### Consensus Rules
- **Block Validation**: Verify Bitcoin consensus rule compliance
- **Transaction Parsing**: Check all Bitcoin transaction types are handled
- **SPV Security**: Validate SPV proof verification logic
- **Chain Reorganization**: Verify proper handling of Bitcoin reorgs

#### Data Availability
- **Data Extraction**: Verify data is correctly extracted from Bitcoin transactions
- **Inclusion Proofs**: Check Merkle proof verification
- **Finality**: Review finality mechanisms and assumptions

### 4. Economic Security

#### Fee Mechanisms
- **Base Fee Calculation**: Verify EIP-1559 style fee calculation
- **Priority Fees**: Check priority fee distribution
- **L1 Fee Estimation**: Verify Bitcoin fee estimation accuracy
- **Fee Market**: Review fee market manipulation resistance

#### Incentive Alignment
- **Validator Incentives**: Check prover/validator economic incentives
- **MEV Protection**: Review MEV mitigation strategies
- **Economic Attacks**: Verify resistance to economic griefing

### 5. State Transition Function (STF)

#### Critical Functions (`crates/citrea-stf/src/`)
- **State Root Calculation**: Verify Merkle tree operations
- **Cross-Module Calls**: Check module interaction security
- **Witness Processing**: Validate ZK witness handling
- **Rollback Mechanisms**: Verify state rollback on proof failures

## Configuration and Setup

### Development Environment Setup

1. **Install Dependencies**:
   ```bash
   make install-dev-tools
   ```

2. **Build Project**:
   ```bash
   make build
   ```

3. **Clean Environment**:
   ```bash
   make clean-all    # Clean all artifacts and databases
   ```

### Key Configuration Files

- `Cargo.toml`: Workspace dependencies and features
- `Makefile`: Build and test commands
- `foundry.toml`: Solidity contract configuration
- `.github/workflows/`: CI/CD pipeline definitions

## Common Security Patterns

### 1. State Validation
- All state transitions must be validated by ZK proofs
- State roots must be properly calculated and verified
- Cross-module state access must be properly authorized

### 2. Bitcoin Integration
- Bitcoin header validation follows Bitcoin consensus rules
- Transaction parsing handles all Bitcoin transaction types
- Chain reorganizations are properly handled

### 3. Economic Incentives
- Fee calculations prevent economic attacks
- Withdrawal delays provide security buffers
- Proof generation costs are properly incentivized

## Audit Methodology and Tools

### Recommended Audit Tools

#### Smart Contract Analysis
- **Foundry**: For system contract testing and analysis
  ```bash
  cd crates/evm/src/evm/system_contracts
  forge test --gas-report  # Gas usage analysis
  forge coverage          # Coverage analysis
  ```

- **Slither**: Static analysis for Solidity contracts
  ```bash
  pip install slither-analyzer
  slither crates/evm/src/evm/system_contracts/src/
  ```

- **Mythril**: Security analysis tool
  ```bash
  myth analyze crates/evm/src/evm/system_contracts/src/Bridge.sol
  ```

#### Rust Code Analysis
- **Clippy**: Rust linter (already integrated in `make lint`)
- **Cargo Audit**: Security vulnerability scanner
  ```bash
  cargo audit
  ```

- **Cargo Outdated**: Check for outdated dependencies
  ```bash
  cargo outdated
  ```

#### ZK Circuit Analysis
- **Custom verification**: Check circuit constraints manually
- **Proof verification**: Verify proof generation and verification logic
- **Public input validation**: Ensure all public inputs are properly constrained

### Audit Checklist

### Smart Contracts
- [ ] **Bridge.sol Security**
  - [ ] Bitcoin SPV proof validation logic
  - [ ] Schnorr signature verification precompile usage
  - [ ] UTXO double-spend prevention
  - [ ] Cross-chain message validation
  - [ ] Access control for system operations
  - [ ] Re-entrancy protection in critical functions
- [ ] **BitcoinLightClient.sol Security**
  - [ ] Block number initialization (only once)
  - [ ] Sequential block processing enforcement
  - [ ] System caller authorization checks
  - [ ] Block hash and witness root integrity
- [ ] **WCBTC9.sol Security**
  - [ ] Minting/burning authorization mechanisms
  - [ ] Decimal precision handling (9 decimals)
  - [ ] Total supply accounting accuracy
  - [ ] ERC20 standard compliance
- [ ] **Fee Vault Security**
  - [ ] Fee calculation accuracy and overflow protection
  - [ ] Withdrawal authorization and delays
  - [ ] Economic attack resistance
  - [ ] Access control mechanisms
- [ ] **General Smart Contract Security**
  - [ ] Standard vulnerability patterns (re-entrancy, overflow, etc.)
  - [ ] Access control bypasses
  - [ ] Signature replay attacks
  - [ ] Front-running attack vectors

### ZK System
- [ ] **Circuit Security**
  - [ ] Verify circuit constraints completeness
  - [ ] Check arithmetic circuit correctness
  - [ ] Validate public input constraints
  - [ ] Review constraint system soundness
- [ ] **Proof System Integration**
  - [ ] Proof verification logic in STF
  - [ ] Batch proof aggregation mechanisms
  - [ ] Proof generation correctness
  - [ ] ZK witness handling security
- [ ] **RISC0 Integration**
  - [ ] Guest program security
  - [ ] Host-guest communication
  - [ ] Proof verification parameters

### Bitcoin Integration
- [ ] **Consensus Rule Compliance**
  - [ ] Bitcoin header validation logic
  - [ ] Transaction parsing for all types
  - [ ] SPV proof verification correctness
  - [ ] Difficulty adjustment handling
- [ ] **Chain Reorganization Handling**
  - [ ] Bitcoin reorg detection
  - [ ] State rollback mechanisms
  - [ ] Finality assumptions
- [ ] **Data Availability**
  - [ ] Data extraction from Bitcoin transactions
  - [ ] Merkle proof verification
  - [ ] Inclusion proof validation

### Testing and Quality Assurance
- [ ] **Test Coverage**
  - [ ] Run full test suite (`make test`)
  - [ ] Verify all tests pass
  - [ ] Check test coverage reports (`make coverage`)
  - [ ] Run Ethereum Foundation tests (`make ef-tests`)
  - [ ] Execute Foundry tests for system contracts
- [ ] **Code Quality**
  - [ ] Run linting checks (`make lint`)
  - [ ] Review static analysis results
  - [ ] Check dependency vulnerabilities (`cargo audit`)
- [ ] **Manual Testing**
  - [ ] Test critical user workflows
  - [ ] Verify edge case handling
  - [ ] Test failure scenarios and recovery

## Additional Resources

- [Citrea Documentation](https://docs.citrea.xyz)
- [Sovereign SDK Documentation](https://github.com/Sovereign-Labs/sovereign-sdk)
- [RISC0 Documentation](https://dev.risczero.com/)
- [Repository Contributing Guidelines](../CONTRIBUTING.md)

## Contact

For questions or clarifications during the audit process, please:
1. Check existing documentation in the `docs/` directory
2. Review GitHub issues for known concerns
3. Contact the development team through official channels

---

**Note**: This guide focuses on the smart contract aspects of Citrea. For a complete security audit, also review the broader system architecture, networking components, and operational security measures.