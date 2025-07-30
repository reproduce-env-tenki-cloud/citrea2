MAIN_BRANCH=ege/mock-nightly-2
TEST_DIR=bin/citrea/tests/cycle_counts

bash $TEST_DIR/run-test.sh patch-stats.json
git checkout $MAIN_BRANCH

cargo build --features testing
bash $TEST_DIR/run-test.sh nightly-stats.json

python3 $TEST_DIR/compare-results.py $TEST_DIR/results/patch-stats.json $TEST_DIR/results/nightly-stats.json
