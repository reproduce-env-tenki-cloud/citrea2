TEST_DIR=bin/citrea/tests/proving-stats
OUT_FILE_NAME="$1"

docker compose -f $TEST_DIR/docker-compose.regtest.yml up -d
sleep 10

docker exec bitcoin-regtest bitcoin-cli -regtest -rpcuser=citrea -rpcpassword=citrea loadwallet sequencer
docker exec bitcoin-regtest bitcoin-cli -regtest -rpcuser=citrea -rpcpassword=citrea loadwallet batch-prover

target/debug/citrea --dev --da-layer bitcoin --rollup-config-path $TEST_DIR/configs/sequencer_rollup_config.toml --sequencer $TEST_DIR/configs/sequencer_config.toml --genesis-paths bin/citrea/tests/bitcoin/test-data/gen-proof-input-genesis >> sequencer.log &
PARALLEL_PROOF_LIMIT=2 target/debug/citrea --dev --da-layer bitcoin --rollup-config-path $TEST_DIR/configs/batch_prover_rollup_config.toml --batch-prover $TEST_DIR/configs/batch_prover_config.toml --genesis-paths bin/citrea/tests/bitcoin/test-data/gen-proof-input-genesis >> batch-prover.log &

mkdir -p $TEST_DIR/results
python3 bin/citrea/tests/proving-stats/get-proving-stats.py batch-prover.log $TEST_DIR/results/$OUT_FILE_NAME

pkill citrea
docker compose -f $TEST_DIR/docker-compose.regtest.yml down

sleep 2 # Give some time for the processes to terminate

git reset --hard
git clean -fd