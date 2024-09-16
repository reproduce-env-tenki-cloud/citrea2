#!/bin/bash

echo "rollup.toml.template"
#cat rollup.toml
envsubst < rollup.toml > rollup.toml.new
mv rollup.toml.new rollup.toml
echo "rollup.toml"
#cat rollup.toml

exec ./citrea \
--da-layer bitcoin \
--rollup-config-path rollup.toml \
--genesis-paths genesis
