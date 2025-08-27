# prs

GitHub CLI tool that shows which PRs that are actually waiting on you. That's it.

Designed to be easily used for embedded low-power displays, or your shell initialization.

## Install

```bash
go install github.com/codeGROOVE-dev/prs@latest
```

Requires Go 1.23+ and `gh` auth.

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
