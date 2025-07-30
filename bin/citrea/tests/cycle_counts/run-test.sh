TEST_DIR=bin/citrea/tests/cycle_counts
bitcoind -regtest -rpcuser=citrea -rpcpassword=citrea -txindex=1 -addresstype=bech32m -fallbackfee=0.0001 -datadir=$TEST_DIR/bitcoin --daemon
sleep 1

bitcoin-cli loadwallet sequencer
bitcoin-cli loadwallet batch-prover

target/debug/citrea --dev --da-layer bitcoin --rollup-config-path $TEST_DIR/configs/sequencer_rollup_config.toml --sequencer $TEST_DIR/configs/sequencer_config.toml --genesis-paths bin/citrea/tests/bitcoin/test-data/gen-proof-input-genesis >> sequencer.log &
PARALLEL_PROOF_LIMIT=2 target/debug/citrea --dev --da-layer bitcoin --rollup-config-path $TEST_DIR/configs/batch_prover_rollup_config.toml --batch-prover $TEST_DIR/configs/batch_prover_config.toml --genesis-paths bin/citrea/tests/bitcoin/test-data/gen-proof-input-genesis >> batch-prover.log &

source bin/citrea/tests/cycle_counts/.venv/bin/activate
python3 bin/citrea/tests/cycle_counts/get_proving_stats.py $TEST_DIR/results/out.json batch-prover.log

pkill citrea
pkill bitcoind

git reset --hard
git clean -fd