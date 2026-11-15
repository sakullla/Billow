# Repository Guidelines

## Project Structure & Module Organization

Billow is a Vue 3 and Tauri 2 client for Mihomo, targeting desktop and Android.

- `src/views/` contains page components; `src/components/` holds reusable UI elements.
- `src/lib/` contains backend bindings, shared types, state, formatting helpers, and the demo backend. Global styles live in `src/styles.css`.
- `src-tauri/src/` contains Rust modules for profiles, kernel management, networking, diagnostics, and shell behavior.
- `src-tauri/gen/android/` includes Android Kotlin integration. Tauri permissions, capabilities, and icons have dedicated directories under `src-tauri/`.
- Frontend tests sit beside source files as `*.test.ts`; Rust tests live inside modules. Product requirements are in `docs/requirements/`.

## Build, Test, and Development Commands

Run commands from the repository root. Install Node.js/npm and Rust 1.90 or newer; native builds also need platform-specific Tauri prerequisites.

- `npm install`: install frontend dependencies.
- `npm run dev`: start Vite on port 1420.
- `npm run tauri -- dev`: launch the native app with the development frontend.
- `npm run build`: type-check Vue/TypeScript and generate `dist/`.
- `npm test`: run frontend tests once.
- `cargo test --manifest-path src-tauri/Cargo.toml`: run Rust tests.
- `npm run build:windows`, `npm run build:macos`, `npm run build:linux`, or `npm run build:android`: package for the corresponding platform with its required toolchain.

## Coding Style & Naming Conventions

Use two-space indentation, single quotes, and no semicolons in TypeScript. Prefer Vue `<script setup lang="ts">`, PascalCase component filenames, and camelCase functions and variables. Preserve backend payload field names at the binding boundary. TypeScript strict checking is enabled.

Use four-space indentation and snake_case functions/modules in Rust. No ESLint or Prettier configuration is checked in; follow surrounding code.

## Testing Guidelines

Frontend tests use Vitest, Vue Test Utils, and happy-dom. Name files `*.test.ts` and describe observable behavior in test cases. Use the demo backend and controlled timers for UI scenarios. Rust uses `#[cfg(test)]` modules and `#[test]` functions. Add regression coverage for changed behavior; no numeric coverage threshold is configured. Run relevant tests and the frontend build before submitting.

## Commit & Pull Request Guidelines

Recent history uses `feat:` and `fix:` prefixes, often with Chinese descriptions. Keep commits focused and summaries specific. Pull requests should explain behavior changes, link relevant issues or requirements, report validation commands/results, and include screenshots for UI changes. Identify affected platforms and any untested native behavior.
