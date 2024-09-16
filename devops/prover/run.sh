#!/bin/bash

echo "rollup.toml.template"
#cat rollup.toml
envsubst < rollup.toml > rollup.toml.new
mv rollup.toml.new rollup.toml
echo "rollup.toml"
#cat rollup.toml

echo "prover.toml.template"
#cat prover.toml
envsubst < prover.toml > prover.toml.new
mv prover.toml.new prover.toml
echo "prover.toml"
#cat prover.toml

exec ./citrea \
--da-layer bitcoin \
--rollup-config-path rollup.toml \
--prover-config-path prover.toml \
--genesis-paths genesis
