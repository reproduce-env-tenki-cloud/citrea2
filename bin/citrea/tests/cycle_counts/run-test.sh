TEST_DIR=bin/citrea/tests/cycle_counts
OUT_FILE_NAME="$1"
bitcoind -regtest -rpcuser=citrea -rpcpassword=citrea -txindex=1 -addresstype=bech32m -fallbackfee=0.0001 -datadir=$TEST_DIR/bitcoin --daemon
sleep 1

bitcoin-cli loadwallet sequencer
bitcoin-cli loadwallet batch-prover

target/debug/citrea --dev --da-layer bitcoin --rollup-config-path $TEST_DIR/configs/sequencer_rollup_config.toml --sequencer $TEST_DIR/configs/sequencer_config.toml --genesis-paths bin/citrea/tests/bitcoin/test-data/gen-proof-input-genesis >> sequencer.log &
PARALLEL_PROOF_LIMIT=2 target/debug/citrea --dev --da-layer bitcoin --rollup-config-path $TEST_DIR/configs/batch_prover_rollup_config.toml --batch-prover $TEST_DIR/configs/batch_prover_config.toml --genesis-paths bin/citrea/tests/bitcoin/test-data/gen-proof-input-genesis >> batch-prover.log &

source bin/citrea/tests/cycle_counts/.venv/bin/activate
python bin/citrea/tests/cycle_counts/get_proving_stats.py batch-prover.log $TEST_DIR/results/$OUT_FILE_NAME

pkill citrea
pkill bitcoind

sleep 2 # Give some time for the processes to terminate

git reset --hard
git clean -fd