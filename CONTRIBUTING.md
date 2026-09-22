# Contributing

## AI-Assisted Contributions

AI coding tools may be used to prepare contributions, under these conditions:

1. **Disclose it.** A commit containing substantial AI-generated code or text
   carries a trailer naming the tool, for example
   `Co-Authored-By: Claude <noreply@anthropic.com>`. Alternatively, state in the
   pull request which parts were AI-assisted and with which tool.
2. **The human submitter is responsible.** You must understand, review, and test
   every line you submit. "The tool wrote it" is not a justification in review,
   and AI-assisted changes meet the same review bar as any other change.
3. **Security invariants still apply.** Everything in [`security.md`](security.md)
   holds regardless of how code was produced. Changes to rule verification,
   parsing, evaluation, storage, or transport need negative and failure-path
   tests.
4. **Never share secrets with AI tools.** Do not paste credentials, private keys,
   enrollment tokens, or non-public endpoint data into prompts.

Repository guidance for coding agents lives in [`AGENTS.md`](AGENTS.md).
