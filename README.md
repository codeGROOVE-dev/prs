# 🚀 prs

> Only shows PRs waiting on YOU - preserving your focus time and sanity

A blazingly fast CLI tool that filters out all the noise to show only the PRs that need your action. No more context switching through dozens of PRs that don't need you right now.

## Quick Start

```bash
go install github.com/ready-to-review/prs@latest
```

**Prerequisites:** Go 1.23+ and GitHub CLI (`gh`) authenticated

## Usage

```bash
# The default - shows ONLY PRs waiting on your input
prs

# See everything you're involved with (if you really want to)
prs --all

# Stay focused - auto-refresh what needs your attention (every 10 min)
prs --watch

# Get alerted to newly blocking PRs (notifications currently unavailable)
prs --notify
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

**Focus is precious.** This tool shows ONLY the PRs blocked on your input - nothing else. No PRs waiting on CI, no PRs waiting on other reviewers, no PRs you've already reviewed. Just the ones that need you, right now.

Built with Go for speed, because waiting for your tools is another focus killer.