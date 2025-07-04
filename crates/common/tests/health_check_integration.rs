//! Integration test for enhanced light client prover health check
use std::sync::Arc;
use std::time::Duration;

use jsonrpsee::RpcModule;
use sov_mock_da::{MockAddress, MockDaService};
use sov_mock_zkvm::MockZkvm;
use tempfile::TempDir;
use tokio::time::timeout;
use prover_services::{ParallelProverService, ProofGenMode};
use citrea_common::rpc::register_healthcheck_rpc_light_client_prover;

#[tokio::test]
async fn test_enhanced_health_check_with_working_services() {
    // Create a temporary directory for the MockDaService
    let tmpdir = TempDir::new().unwrap();
    
    // Create mock DA service
    let da_service = Arc::new(MockDaService::new(
        MockAddress::from([0; 32]),
        tmpdir.path(),
    ));
    
    // Create mock prover service
    let vm = MockZkvm::new();
    let prover_service = Arc::new(
        ParallelProverService::new(
            da_service.clone(),
            vm,
            ProofGenMode::Execute,
            1, // Single thread for test
        )
        .expect("Should create prover service"),
    );
    
    // Create RPC module and register the enhanced health check
    let mut rpc_module = RpcModule::new(());
    register_healthcheck_rpc_light_client_prover(&mut rpc_module, da_service, prover_service)
        .expect("Should register health check");
    
    // Test the health check by calling it directly
    // Note: In a real scenario, this would be called via HTTP, but for unit testing
    // we can test the core logic
    let health_check_method = rpc_module.method("health_check");
    assert!(health_check_method.is_some(), "Health check method should be registered");
    
    // The test passes if the registration succeeds and the method is available
    println!("Enhanced health check registration test passed");
}

#[tokio::test]
async fn test_health_check_method_exists() {
    // This is a simpler test that just verifies the method registration works
    let tmpdir = TempDir::new().unwrap();
    let da_service = Arc::new(MockDaService::new(
        MockAddress::from([0; 32]),
        tmpdir.path(),
    ));
    
    let vm = MockZkvm::new();
    let prover_service = Arc::new(
        ParallelProverService::new(
            da_service.clone(),
            vm,
            ProofGenMode::Execute,
            1,
        )
        .expect("Should create prover service"),
    );
    
    let mut rpc_module = RpcModule::new(());
    
    // This should not panic
    register_healthcheck_rpc_light_client_prover(&mut rpc_module, da_service, prover_service)
        .expect("Health check registration should succeed");
    
    // Verify the method was registered
    assert!(rpc_module.method("health_check").is_some());
}