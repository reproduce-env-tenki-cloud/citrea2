#!/bin/bash

echo "rollup.toml.template"
#cat rollup.toml
envsubst < rollup.toml > rollup.toml.new
mv rollup.toml.new rollup.toml
echo "rollup.toml"
#cat rollup.toml

echo "sequencer.toml.template"
#cat sequencer.toml
envsubst < sequencer.toml > sequencer.toml.new
mv sequencer.toml.new sequencer.toml
echo "sequencer.toml"
#cat sequencer.toml

exec ./citrea \
--da-layer bitcoin \
--rollup-config-path rollup.toml \
--sequencer-config-path sequencer.toml \
--genesis-paths genesis
