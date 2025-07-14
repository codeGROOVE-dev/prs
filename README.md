# GitHub PR Notifier CLI

A fast, minimal command-line tool for tracking GitHub pull requests that need your attention.

## Installation

```bash
go install github.com/ready-to-review/github-pr-notifier-cli@latest
```

Requires: Go 1.21+ and GitHub CLI (`gh`) authenticated

## Usage

```bash
# Show PRs awaiting your review (default)
github-pr-notifier-cli

# Show all PRs you're involved with  
github-pr-notifier-cli --all

# Watch mode - refreshes every 10 minutes
github-pr-notifier-cli --watch

# Notify mode - alerts on newly blocking PRs
github-pr-notifier-cli --notify
```

## Output

```
3 PRs awaiting your review

  • Fix authentication bug • 3h • https://github.com/org/repo/pull/123
  • Add user preferences • 1d • https://github.com/org/repo/pull/456
```

## Options

- `--all`: Show all PRs, not just those blocking on you
- `--watch`: Continuously watch for updates (10 min intervals)
- `--watch-interval N`: Set watch interval in minutes
- `--notify`: Only show newly blocking PRs
- `--verbose`: Show API call logs

## Design

Built with Go best practices: minimal dependencies, fast execution, secure authentication via GitHub CLI.