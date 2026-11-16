# Local serde_yaml patch

Base: crates.io serde_yaml 0.9.34+deprecated, original MIT/Apache-2.0 licenses retained.

Parser behavior modification: the three anchor-definition branches in src/loader.rs allocate IDs from document.aliases.len() instead of anchors.len(). The name-to-ID map can retain the same length after an anchor name is rebound; using its length then reuses an ID and lets a later anchor overwrite earlier alias targets. The ID-to-event map is append-only and produces a unique ID for each definition.

This preserves YAML's nearest-preceding-definition alias semantics, including references before a redefinition. Billow's repeated_anchor_names_do_not_rebind_urls_to_an_unrelated_mapping regression reproduces the provider URL becoming a mapping on the unpatched version. No regex rewriting of subscription content, dependency API migration, or extra runtime preprocessing is introduced.

Upstream source: https://github.com/dtolnay/serde-yaml/tree/0.9.34
YAML alias semantics: https://yaml.org/spec/1.2.2/#3222-anchors-and-aliases

Remove this local patch only after the replacement parser passes the duplicate-anchor and existing configuration tests.

Rust toolchain compatibility: make the existing raw-pointer field borrows explicit in src/libyaml/error.rs and src/libyaml/parser.rs, as required by the dangerous_implicit_autorefs lint when compiled as a local dependency. The equivalent implicit borrows in registry builds were lint-capped.
