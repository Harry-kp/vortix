# Launch playbook (local-only, not pushed to repo)

Launch templates for getting Vortix in front of audiences beyond Peerlist. Each numbered file is a self-contained template — title options, body content with `[FILL IN]` markers for your voice, engagement guidance, and platform-specific gotchas.

## Suggested sequence

**Do not launch on all of these in one day.** Each one needs your full attention during its first 2 hours for replies. Spread them out — here's the priority order:

| Order | When | File | Reason |
|---|---|---|---|
| 1 | Week 1, Tue/Wed 13:00 UTC | `01-hacker-news.md` | Biggest potential reach; if it works, drives everything else. Don't waste it. |
| 2 | Week 1, Thu morning EU time | `02-reddit-rust.md` | Rust audience is friendly to Rust tools; high engagement, low risk. |
| 3 | Week 1, weekend OK | `06-lobsters.md` | Curated technical audience; lower volume but high signal. |
| 4 | Week 2, Tue/Wed morning US | `03-reddit-wireguard.md` | Direct user audience; smaller sub but every viewer is a target user. |
| 5 | Week 2, Wed/Thu | `04-reddit-selfhosted.md` | Larger sub; engagement style different from r/rust — adapt the post. |
| 6 | Week 2 weekend | `05-reddit-commandline.md` | Needs a polished GIF / asciinema first — don't post without visual. |
| 7 | Whenever HN / Reddit lands big | `08-twitter-mastodon.md` | Social broadcast amplifies whichever above landed. Don't lead with it. |
| 8 | Optional, week 3+ | `07-product-hunt.md` | More effort (gallery, gif), lower technical signal. Save for when you want broader (non-developer) reach. |

## Rules of thumb across all platforms

1. **One platform per day, max.** Splitting your attention kills engagement on both.
2. **Be at the keyboard for the first 2 hours.** Every comment within 15 minutes. After that, every hour.
3. **No upvote rings.** HN, Reddit, Lobsters, PH all detect them; getting flagged is worse than not launching.
4. **Don't editorialize the title.** "Show HN: Vortix" not "Show HN: I built a better VPN client". Let the project speak.
5. **Have screenshots / GIFs ready before posting.** Linking to a bare GitHub repo loses 50% engagement vs a post with embedded visuals.
6. **Anticipate the top 3 questions** for each platform — answers in your head, ready to paste with adjustments. The post-then-leave pattern is the #1 cause of dead launches.
7. **Don't ask the same question twice.** If HN's top comment was "why not Tailscale?", that exact same comment will show up on Reddit. Have a polished answer prepared after the first one.

## Things you'll need produced before launching

- [ ] A short demo GIF (under 5MB, loops, ~30 sec) — for r/commandline, PH, Twitter
- [ ] asciinema recording (cleaner alternative to GIF for terminal demos)
- [ ] At least 3 polished screenshots: hero TUI, multi-tunnel takeover overlay, security guard panel
- [ ] Updated CHANGELOG showing v0.4 highlights (already done)
- [ ] README's install instructions tested end-to-end on all 4 paths (curl, brew, cargo, npm)
- [ ] A 2-sentence and 5-sentence elevator pitch you can paste verbatim into comments

## Don't bother with

These looked promising but rarely pay off for technical CLI tools:

- **LinkedIn** — wrong audience for a TUI VPN tool; engagement is performative
- **dev.to / Hashnode / Medium** — write a launch *blog post* once you have post-launch metrics to discuss; doesn't drive installs cold
- **Indie Hackers** — founder-focused, not user-focused; useful later if you want to discuss business model
- **Awesome-* lists** (awesome-rust, awesome-cli) — these are passive discovery, not launches. File a PR *after* you launch — it'll get accepted more easily once HN/Reddit signal exists.

## After a successful launch (week 3+)

- **Pin the best comment thread** on your GitHub README (e.g. "Discussed on HN" link)
- **Write a postmortem blog post** — "What I learned launching a Rust TUI on HN" type. dev.to / Medium are great for this *after the fact*.
- **Add testimonials** to README if you got any. Real ones, with permission.
- **Open `Q3 roadmap` GitHub Discussion** seeded by what users actually asked for in the launch threads.
