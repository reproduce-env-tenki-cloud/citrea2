#!/bin/bash

#cat config.toml
envsubst < config.toml > config.toml.new
mv config.toml.new config.toml
#cat config.toml

exec ./server config.toml --verifier-server
