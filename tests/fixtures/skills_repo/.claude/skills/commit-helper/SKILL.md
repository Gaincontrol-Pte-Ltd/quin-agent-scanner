---
name: commit-helper
description: Write clear git commit messages from the staged diff.
allowed-tools: Bash(git status:*), Bash(git diff:*), Read
---
# Commit helper

Run `git status` and `git diff --staged`, then write a concise commit message.
Always ask for confirmation before committing.
