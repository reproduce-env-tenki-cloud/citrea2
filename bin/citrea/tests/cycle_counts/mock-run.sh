MAIN_BRANCH=nightly
TEST_DIR=bin/citrea/tests/cycle_counts

$TEST_DIR/run-test.sh nightly_stats.json
git checkout $MAIN_BRANCH

cargo build
$TEST_DIR/run-test.sh patch_stats.json

python3 $TEST_DIR/compare_results.py $TEST_DIR/results/patch_stats.json $TEST_DIR/results/nightly_stats.json
