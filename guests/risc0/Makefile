.PHONY: all
all: batch-proof-mock batch-proof-bitcoin light-client-mock light-client-mock

.PHONY: build-batch-proof-mock
batch-proof-mock:
	cd ../../ && \
	cargo risczero build --manifest-path guests/risc0/batch-proof-mock/Cargo.toml

.PHONY: batch-proof-bitcoin
batch-proof-bitcoin:
	cd ../../ && \
	cargo risczero build --manifest-path guests/risc0/batch-proof-bitcoin/Cargo.toml

.PHONY: light-client-mock
batch-proof-mock:
	cd ../../ && \
	cargo risczero build --manifest-path guests/risc0/light-client-proof-mock/Cargo.toml

.PHONY: light-client-bitcoin
batch-proof-bitcoin:
	cd ../../ && \
	cargo risczero build --manifest-path guests/risc0/light-client-proof-bitcoin/Cargo.toml
