# Recovering a conflicted generated pull request

Do not copy complete versions of every conflicted file into GitHub's conflict
editor. That can silently discard fixes already merged into `main`.

## Safest workflow

1. Cancel the GitHub conflict editor without committing its contents.
2. Close the conflicted pull request. Closing it does not remove code already
   merged into `main`.
3. Update a normal Git clone and create a fresh branch from the latest `main`:

   ```bash
   git switch main
   git pull --ff-only origin main
   git switch -c fix/qwen-provider
   ```

4. Apply only the Qwen fixes to that fresh branch. Do not merge the old feature
   branch because it contains older copies of the API, UI, tests, and tribunal.
5. Run the checks, commit, and push:

   ```bash
   python -m compileall -q .
   set OFFLINE_MODE=true
   python -m pytest -q
   git add .
   git commit -m "Configure and verify Qwen provider integration"
   git push -u origin fix/qwen-provider
   ```

6. Open a new pull request from `fix/qwen-provider` to `main`. GitHub should
   report that the branch can be merged automatically.

## Why not resolve all six files in the browser?

The conflicted branch and `main` both changed the same core files. Selecting an
entire "ours" or "theirs" version would remove changes from the other side.
Starting from current `main` and applying only the small provider fix produces a
reviewable diff and preserves the already-deployed application.

