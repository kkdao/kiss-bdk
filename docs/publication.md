# Before any external submission

Never put a tool or agent name in a public branch, tag, commit identity,
commit message, PR title/body, issue, comment, or project prose. Use a neutral
branch name describing the change. This rule overrides branch-name defaults.

Run `sh tools/install_hooks.sh` after cloning. The installed commit hook
checks message text and identities; the pre-push hook checks both source and
destination refs and every newly outgoing commit, including a change reverted
later in the same push. Branch deletions remain allowed. Existing history is
not rewritten. The release documentation check remains in place.

Before any push or PR API mutation, prepare a JSON review file outside the
repository containing exactly these nonempty string fields:

- `account`: the verified publishing account
- `destination`: the exact repository or recipient
- `branch`: the full source branch, including its owner when relevant
- `base`: the destination branch
- `title`: exact proposed title
- `body`: exact proposed body
- `diff`: the actual Git diff to publish

Run `python3 tools/hooks/publication_guard.py review /path/to/review.json`.
Show the entire output to the owner, including the branch and diff, and wait
for explicit approval. Re-check the same file immediately before submission.
A changed field changes the printed digest and requires new approval. A
passing check is never approval and the checker cannot verify human consent.

Only explicit policy files are exempt from the added-content name scan because
those files contain the detection patterns and regression cases. Paths,
identities and message metadata have no exemption. Deletions/context are not
new-content findings, but remain visible in the required full diff review.
Binary payloads are not scanned. Ordinary source-code cursor variables are
not treated as attribution; naming the corresponding tool is checked in prose
and metadata.

Hooks do not intercept browser actions, direct API requests, or bypass flags.
The review step is mandatory for those paths too. CI checks branch and PR
metadata as a backstop, after publication; it cannot prevent disclosure.
Do not bypass a failed check. No script here sends a request or grants approval.

Validation: `PYTHONDONTWRITEBYTECODE=1 python3 tools/hooks/test_publication_guard.py`.
The regressions push only to a temporary local bare repository.
