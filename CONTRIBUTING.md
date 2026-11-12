# Contributing

Contributions are welcome through GitHub issues and pull requests. Report bugs and suggest enhancements through the issue tracker. For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development setup

Install stable Rust, Node.js 20 or later, and pnpm, then install the web dependencies:

```bash
pnpm install
pnpm --prefix apps/web install
```

Run the checks relevant to your change before opening a pull request:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm --prefix apps/web lint
pnpm --prefix apps/web test
pnpm --prefix apps/web build
pnpm --prefix apps/web test:e2e
```

Include tests for behavior changes, update documentation when behavior or setup changes, and describe the motivation and impact in the pull request. Keep credentials and local database files out of commits.
