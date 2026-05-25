<p align="center">
  <img src="https://github.com/bhangun/repo-assets/raw/master/iket-logo.png" alt="Iket logo" width="168">
</p>

<p align="center">
  <a href="https://github.com/bhangun/iket/actions"><img src="https://github.com/bhangun/iket/actions/workflows/ci.yml/badge.svg" alt="Build Status"></a>
  <a href="https://goreportcard.com/report/github.com/bhangun/iket"><img src="https://goreportcard.com/badge/github.com/bhangun/iket" alt="Go Report Card"></a>
  <a href="https://github.com/bhangun/iket/releases"><img src="https://img.shields.io/github/v/tag/bhangun/iket?label=release" alt="GitHub release"></a>
  <a href="https://github.com/bhangun/iket/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
  <a href="https://hub.docker.com/r/bhangun/iket"><img src="https://img.shields.io/docker/pulls/bhangun/iket" alt="Docker Pulls"></a>
</p>

# Iket API Gateway

Iket is a lightweight, extensible API gateway written in Go with secure remote administration, plugin support, and modern rollout tooling.

## Start here

- Website: https://iket-gateway.github.io
- Full documentation: https://iket-gateway.github.io/docs/
- GitHub repository: https://github.com/bhangun/iket
- Releases: https://github.com/bhangun/iket/releases

## Quickstart

```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash
iket server run
iket setup
iket gateway status
```

## Repository docs

- [Documentation home](https://iket-gateway.github.io/docs/)
- [Installation Guide](https://iket-gateway.github.io/docs/install/)
- [CLI Command Reference](https://iket-gateway.github.io/docs/cli-commands/)
- [API Key Management](https://iket-gateway.github.io/docs/api-key-management/)
- [Plugin Quickstart](https://iket-gateway.github.io/docs/plugin-quickstart/)
- [Config Storage](https://iket-gateway.github.io/docs/config-storage/)
- [Editions & Capabilities](https://iket-gateway.github.io/docs/editions/)
- [API Reference](https://iket-gateway.github.io/docs/api-specification/)

## Contributor guidance

If you are working inside the repository as a maintainer or coding agent:

- [AGENT.md](./AGENT.md) explains current architecture assumptions, operational gotchas, and preferred validation flow.
- [SKILLS.md](./SKILLS.md) lists repo-specific workflows for server lifecycle, routing, TLS, Docker UX, config storage, and CLI/admin surface work.

## License

This project is licensed under the Apache License 2.0, which allows open source and commercial use. See the `LICENSE` file for details.
