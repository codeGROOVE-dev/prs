# prs

GitHub PR filtering for people who don't have time for GitHub's nonsense.

Shows only PRs that are actually waiting on you. That's it.

## Install

```bash
go install github.com/ready-to-review/prs@latest
```

Requires Go 1.23+ and `gh` auth.

## Usage

```bash
prs                    # PRs you're involved with
prs --blocked          # Only PRs waiting for you
prs --include-stale    # Include ancient PRs
prs --watch            # Live updates
```

![Default View](media/default.png)

![Watch Mode](media/watch_blocked.png)

## Flags

```
--blocked         PRs blocking on you
--include-stale   Show old garbage too
--watch           Real-time updates via WebSocket
--exclude-orgs    Skip organizations (comma-separated)
--verbose         More noise
```

Colors disabled with `NO_COLOR=1`.

## Status

Draft, ready, approved, conflicted, stale, failing, or regular. You'll figure it out.

## Why

Because clicking through GitHub tabs is for people with too much time.
