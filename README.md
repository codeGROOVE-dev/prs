# GitHub PR Notifier CLI

A fast, minimal command-line tool for viewing GitHub pull requests with a focus on simplicity and efficiency.

## Features

- **Default Mode**: Shows all PRs you're involved with and exits
- **Refresh Mode** (`--refresh`): Auto-refreshes every 10 minutes
- **Notify Mode** (`--notify`): Only shows PRs that are blocking on you
- **Colorized Output**: Clear visual indicators for PR status
- **Minimal Dependencies**: Only uses standard library (no external dependencies)
- **Secure**: Uses `gh auth token` for authentication

## Installation

```bash
go install github.com/ready-to-review/github-pr-notifier-cli@latest
```

Or build from source:

```bash
git clone https://github.com/ready-to-review/github-pr-notifier-cli
cd github-pr-notifier-cli
go build
```

## Prerequisites

- Go 1.21 or later
- GitHub CLI (`gh`) installed and authenticated

## Usage

```bash
# Show all PRs and exit
github-pr-notifier-cli

# Auto-refresh mode (updates every 10 minutes)
github-pr-notifier-cli --refresh

# Notify mode (only shows PRs blocking on you)
github-pr-notifier-cli --notify

# Combination: refresh + notify
github-pr-notifier-cli --refresh --notify
```

## Output Format

Each PR is displayed in 2 lines:

```
● org/repo#123 Fix critical bug in authentication...
  @author 3h ago 💬 5 ✓ 2 ⚡ awaiting your review
```

### Status Indicators

- `●` Yellow: PR is blocking on your review
- `◆` Blue: You authored this PR
- `◐` Gray: Draft PR
- `○` Gray: Other PRs you're involved with

### Information Shown

- Repository and PR number
- PR title (truncated to 50 chars)
- Author
- Time since last update
- Comment count
- Review comment count
- Review status

## Color Support

Colors are automatically disabled when:
- `TERM=dumb` is set
- `NO_COLOR` environment variable is set

## Testing

```bash
go test
```

## Design Philosophy

This tool follows Go best practices and design principles:
- Simple, clear code without unnecessary abstractions
- Minimal external dependencies
- Fast startup and execution
- Clear error messages
- Testable components
- Security-first approach using GitHub CLI for authentication