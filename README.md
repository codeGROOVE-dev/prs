# 🚀 CLI Dash

> Your personal GitHub PR dashboard that actually fits in your terminal

A blazingly fast CLI tool that cuts through the noise to show you the PRs that matter. No more endless GitHub notifications or tab-switching madness.

## Quick Start

```bash
go install github.com/ready-to-review/github-pr-notifier-cli@latest
```

**Prerequisites:** Go 1.23+ and GitHub CLI (`gh`) authenticated

## Usage

```bash
# The essentials - what needs your eyeballs?
github-pr-notifier-cli

# Everything you're involved with
github-pr-notifier-cli --all

# Set it and forget it (refreshes every 10 min)
github-pr-notifier-cli --watch

# Just the new stuff (notifications currently unavailable)
github-pr-notifier-cli --notify
```

## What You'll See

```
🔥 2 PRs awaiting your review

⬇️  Incoming PRs

  ● 🚧 Fix authentication bug ⚡
     3h • https://github.com/org/repo/pull/123

  ● ✅ Add user preferences
     1d • https://github.com/org/repo/pull/456

⬆️  Your PRs

  ● 📝 Update documentation
     2h • https://github.com/org/repo/pull/789
```

## Options

- `--all` - Show all your PRs, not just review requests
- `--watch` - Keep watching for updates (10 min intervals)
- `--watch-interval N` - Customize refresh rate (minutes)
- `--notify` - New PR alerts (⚠️ currently disabled)
- `--verbose` - Debug mode for the curious

## Why This Exists

Because checking GitHub every 5 minutes is not a sustainable lifestyle choice. Built with Go for speed and your sanity.