# prs

GitHub CLI tool that shows which PRs that are actually waiting on you. That's it.

Designed to be easily used for embedded low-power displays, or your shell initialization.

## Install

```bash
go install github.com/codeGROOVE-dev/prs@latest
```

## Prereqs

-  [go](https://go.dev/) 1.23.4 or higher
- [gh](https://cli.github.com/) (aka, the GitHub CLI)

To verify that your gh command is authenticated properly:

```
gh auth status || gh auth login
```

## Usage

```bash
prs                        # PRs you're involved with
prs --blocked              # Only PRs waiting for you
prs --include-stale        # Include ancient PRs
prs --watch                # Live updates
prs --exclude-orgs google  # Skip an organization (comma-separated)
```

![Default View](media/default.png)

![Watch Mode](media/watch_blocked.png)

Colors disabled with `NO_COLOR=1`.

## Real-time support

Due to GitHub webhook limitations, real-time updates are only available for GitHub orgs that install the [Ready to Review](https://github.com/apps/ready-to-review-beta) GitHub app.

Without the app, PRs are updated every minute, which should be enough for anyone TBH.

## GUI

Prefer a menu-bar UI? Check out https://github.com/codeGROOVE-dev/goose
