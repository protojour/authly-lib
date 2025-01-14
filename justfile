test:
    cargo hack --workspace --feature-powerset --exclude-features unstable-doc-cfg test

lint:
    cargo hack --workspace --feature-powerset --exclude-features unstable-doc-cfg clippy
