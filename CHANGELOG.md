# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project uses Semantic Versioning.

## [Unreleased]

- No unreleased changes yet.

## [1.0.0] - 2026-03-24

- Reorganized the project into a packaged CLI with a `src/` layout and console entry points.
- Added the top-level `main.py` dispatcher and packaging regression tests.
- Moved runtime configuration into `config/`, added `LICENSE`, and standardized repository structure for distribution.
- Refreshed the documentation set and simplified the README with the workflow comparison diagram.

## [0.4.0] - 2026-01-20

- Improved browser bearer-token handling and configuration defaults for more reliable key renewal.
- Added UI design assets and updated the README to better explain the workflow and setup steps.

## [0.3.0] - 2025-11-14

- Reorganized the documentation into the `docs/` directory and refined the architecture and standalone guides.
- Renamed the secret manager sync command and tightened related CLI and logging behavior.
- Updated the renewal/check flow and added the workflow diagram asset used in project docs.

## [0.2.0] - 2025-10-10

- Introduced centralized logging and expanded environment and renewal diagnostics.
- Added broader agent tooling and ignore rules for local automation artifacts.
- Cleaned up repository-generated files and aligned script naming for secret manager updates.

## [0.1.0] - 2025-09-09

- Initial project import with installer, renewal scripts, reporting tools, configuration template, and docs.
- Added macOS-focused browser token extraction, key rotation, security analysis, and reporting utilities.
- Added the first README, packaging metadata, and screenshot assets for the toolkit.
