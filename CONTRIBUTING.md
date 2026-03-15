# Contributing to luducat Bridge

## What This Repo Is

This is a Playnite plugin that enables remote game launching from
[luducat](https://github.com/luducat/luducat). It is not the luducat
application itself.

For contributions to luducat (plugins, themes, translations, bug fixes),
see the [main repository](https://github.com/luducat/luducat).

## How You Can Help

### Bug Reports

File issues at
[github.com/luducat/luducat-bridge/issues](https://github.com/luducat/luducat-bridge/issues)
with:

- Playnite version
- luducat version (Help > About)
- Steps to reproduce
- Expected vs actual behavior

### Feature Requests

Open an issue describing the use case. The bridge intentionally has a narrow
scope (launch games by library and ID), so not every feature request will fit,
but we want to hear them.

### Pull Requests

Pull requests are welcome for bug fixes. Please describe what and why in the
PR description. For larger changes, open an issue first to discuss the approach.

### Building

The plugin targets .NET Framework 4.6.2 and requires the Playnite SDK. See
`build.bat` for the build process.

## AI-Assisted Development

This plugin was developed with AI-assisted tooling (Claude Code), following
the same methodology as the main luducat project:

- **Human designs and directs** — architecture, scope, and technical decisions
  are human-driven
- **AI assists with implementation** — code generation, protocol design,
  boilerplate
- **Human reviews and signs off** — every change is read, understood, and
  approved before commit

See the main project's
[CONTRIBUTING.md](https://github.com/luducat/luducat/blob/main/CONTRIBUTING.md)
for the full development philosophy.

## License

By contributing to this repository, you agree that your contributions will be
licensed under [MIT](LICENSE).
