---
name: ideate
description: Decide with the maintainer what Vortix builds next — review open proposals one by one, or explore a new idea (evidence, options, smallest useful version, cost), and leave each decision on GitHub as an `approved` issue with testable acceptance criteria, a `proposal`, or a `deferred` issue with the reason. Use whenever the maintainer wants to brainstorm, asks "what should we build next", "is X worth building", "review the proposals", or scopes a feature, even without the word "ideate".
---

# Ideate

This is one of the two points where the maintainer decides; autopilot does everything
else. The outcome of the session is labels and issue text that autopilot can build from with
no further questions.

## 1. Pick the topic

- No topic given: list the open `proposal` issues, oldest first, each with one line on its
  problem and the recommendation. Go through them with the maintainer.
- A topic or issue given: work on that.

## 2. For each idea, bring evidence

Give short points, not prose:
- **The problem, and who has it.** Link the issues, reactions, comments and discussions
  showing that real users hit it. Say plainly if nobody has.
- **How others solve it.** Look at WireGuard's and OpenVPN's own tools and the nearest
  competitors, only when that informs the scope.
- **Two or three options, each with its cost:** code and files touched, TUI density at 80×24
  (CLAUDE.md "TUI density"), upkeep, and what it rules out later. Recommend one, or
  recommend not building it.
- **Items in "Removed on purpose" (CLAUDE.md):** say so. Reviving one is a product decision
  for the maintainer.

## 3. Record the decision on the issue

The maintainer chooses; nothing is labelled `approved` without their yes in this session.

- **Build:** rewrite the issue body so a builder needs nothing else:
  - **Problem:** one or two lines.
  - **Scope:** in, and explicitly out.
  - **Acceptance criteria:** observable, testable statements, each mapped to where its test
    goes: `plan.rs`/`state.rs`, a render test, `tests/suite/`, or P0 if only a live machine
    can show it.
  - **Surfaces:** CLI flags, keys, JSON fields, settings and docs that change.

  Label it `approved`, and remove `proposal` and `deferred`.
- **Not now:** label it `deferred`, remove `proposal`, and comment the reason plus what would
  change the answer.
- **Undecided:** leave it as `proposal`, with the open question in a comment.

End with the decisions in one line each, with links.
