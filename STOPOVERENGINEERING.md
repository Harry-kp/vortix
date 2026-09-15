# Engineering Constraints — Rust

## Prime directive

Write the smallest change that fully solves the stated problem. Rust's type system makes
it cheap to build elaborate abstractions and expensive to remove them. Default to
concrete types, owned data, and plain functions. Reach for generics, traits, and
lifetimes only when a concrete signature has already failed.

---

## Step 1 — Search before you write (mandatory)

Before adding any function, trait, type, or dependency, search for what already exists.

```bash
# 1. The concept, by name
rg -i "parse_config|load_config|from_toml" --type rust

# 2. Existing impls and traits
rg "^impl " -n src/ | rg -i "config"
rg "^pub (fn|struct|enum|trait)" -n src/

# 3. What the crate already re-exports
cat src/lib.rs          # pub use / pub mod — the real public surface
rg "pub use" -n src/

# 4. Dependencies you already have (use these before writing anything)
cat Cargo.toml
cargo tree --depth 1

# 5. Every call site, before you touch a signature
rg "fn_name\s*\(" -n
```

State the result explicitly:

> Searched: `<queries>`. Found `src/util/time.rs:42` — reusing / not reusing because `<reason>`.

### Check in this order, and stop at the first hit

1. **`std`** — it is much larger than people assume. Before writing a loop, check for
   `windows`, `chunks`, `split_*`, `retain`, `dedup`, `partition`, `zip`, `scan`,
   `flat_map`, `filter_map`, `try_fold`, `Entry::or_insert_with`, `saturating_*`,
   `checked_*`, `matches!`, `Option`/`Result` combinators.
2. **Crates already in `Cargo.toml`** — if `itertools`, `serde`, `regex`, `chrono`,
   `rayon`, or `anyhow` is already there, use it.
3. **This crate's own helpers** — `utils/`, `common/`, `internal/`, plus whatever
   `lib.rs` re-exports.
4. **Then, and only then**, write something new.

**Never add a dependency without asking.** New crates mean compile time, audit surface,
MSRV risk, and licence review. If you believe one is needed, name it, name the
alternative (std or an existing dep), and wait.

---

## Rust-specific over-engineering — do not do these unless asked

### Traits and generics

- A trait with **one** implementor. Use the concrete type. Introduce the trait on the
  third implementor, or when a test genuinely cannot be written otherwise.
- `Box<dyn Trait>` where the concrete type is known at the call site.
- Generic parameters used at exactly one instantiation: `fn f<T: AsRef<str>>(s: T)` when
  every caller passes `&str`. Write `fn f(s: &str)`.
- `impl Trait` in argument position purely for aesthetics.
- Blanket impls, marker traits, sealed-trait patterns, extension traits on foreign types.
- `async-trait` when the trait has one impl, or when the function isn't actually async.
- Const generics, GATs, or typestate/`PhantomData` builders. These need an explicit
  requirement, not a hunch.

### Ownership and lifetimes

- Do not contort a signature with explicit lifetimes to avoid one `.clone()` outside a
  hot loop. **`.clone()` is a legitimate engineering decision.** Take `String`, return
  `String`, move on.
- No `Cow<'_, str>` until there is a measured allocation problem.
- No zero-copy parsing / borrowed-struct design unless the task says performance matters.
- Do not add lifetime parameters to a struct so it can hold a `&` to something it could
  simply own.
- `Rc`/`Arc<Mutex<_>>` only when shared mutable ownership is actually required. Try
  passing `&mut` through the call stack first.

### Errors

- **Binary / application code:** `anyhow::Result<T>` with `.context("...")`. That is
  usually the whole error story. Do not build an enum.
- **Library code:** one `thiserror` enum per crate, with variants callers actually
  `match` on. Not one enum per module, not a variant per failure site.
- No `Box<dyn Error>` layered on top of a typed error, and no double wrapping.
- No custom `trait MyError` hierarchy. No error codes, no severity levels, no
  backtrace plumbing unless asked.
- Do not add `From` impls speculatively — add one when a `?` actually fails to compile.
- **Never** paper over a failure with `unwrap_or_default()`, `let _ =`, or a swallowed
  `Err(_) => {}`. If you can't handle it, propagate it.

### Types and structure

- No newtype wrapper unless it prevents a real, plausible mix-up (`UserId` vs `OrderId`,
  yes; `Name(String)` used once, no).
- No builder pattern for a struct with fewer than ~5 fields or no optional fields. Use a
  struct literal, or `#[derive(Default)]` plus `..Default::default()`.
- No `impl Iterator for MyThing` when the caller can use `.iter().map(...)`.
- No module-local `pub type Result<T> = ...` alias in every file. One per crate, at most.
- Do not split code into new modules or new workspace crates to "organize" it. Keep it
  in the file it belongs to until that file is genuinely unwieldy.
- Do not add Cargo features. Feature-gating is a compatibility commitment.

### Macros and async

- A `macro_rules!` that could be a generic function, or a function taking a closure.
  Write the function. Proc macros require explicit approval.
- Do not make something `async` that does no I/O. Do not pull in `tokio` for a sleep, a
  timeout, or a single blocking call — use `std::thread` or a sync client.
- Do not add channels, tasks, or `spawn` to connect two things that could call each other
  directly.
- No `rayon`/parallelism without a benchmark showing the serial version is too slow.

### Unsafe and performance

- **No `unsafe`.** If you think it's warranted, stop and ask, with the benchmark that
  motivates it.
- No `#[inline]`, `SmallVec`, custom allocators, arena types, or `unsafe` transmutes on
  speculation.
- `Vec` and `HashMap` are the right answer until profiling says otherwise.

---

## Match the codebase

- Follow the existing error strategy, module layout, naming, and async runtime. Do not
  introduce a second approach next to a working one.
- Do not run `cargo fmt` across files you didn't touch; it buries your diff.
- Do not bump dependency versions or edit `Cargo.lock` as a side effect.
- Do not change `edition`, MSRV, or lint configuration.

---

## Correctness gates

Before presenting work, run and report:

```bash
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test
cargo fmt --check   # only files you touched should appear
```

- Fix clippy findings in code you wrote. **Never** silence one with `#[allow(...)]` —
  if a lint seems genuinely wrong here, say so and leave it failing for me to decide.
- Do not `#[allow(dead_code)]` something instead of deleting it.
- If it does not compile, say so plainly. Do not present untested code as working.

---

## Tests

- `#[cfg(test)] mod tests` in the same file, unless the crate already uses `tests/`.
- Test real behavior and real edge cases (empty input, boundary values, error paths).
  Do not generate permutation tests to inflate coverage.
- No `mockall`, no trait-ification of concrete types purely to enable mocking, no test
  harness or fixture builder when a literal value works.
- Skip `proptest`/fuzzing unless asked or the code is a parser handling untrusted input.

---

## When the complexity IS warranted

Say so explicitly and justify it in one or two sentences. Valid reasons:

- A trait is required by a framework or an existing public API.
- Borrowing/lifetimes are forced by an FFI or `no_std` constraint.
- Shared mutable state is inherent to the concurrency requirement.
- A benchmark in the repo demonstrates the simple version is too slow.
- Correctness or safety depends on it (untrusted input, money, concurrency, `unsafe`
  boundaries elsewhere).

"It'll be easier to extend later" and "this is more idiomatic" are not valid reasons.

---

## Self-check before finishing

1. What existing `std` item, existing dependency, or existing function in this crate did
   I reuse? If none, what did I search for?
2. Does every trait and generic parameter I added have two or more real users today?
3. Would replacing a generic with a concrete type still compile? Then do that.
4. Did I add a dependency, a Cargo feature, a module, or a public item that wasn't asked
   for?
5. Did I add lifetimes or `Cow` to avoid a clone that nobody measured?
6. Does `cargo clippy -- -D warnings` pass without any new `#[allow]`?

---

## Response format

End every implementation with:

- **Reused:** existing items used, with `path:line`
- **Added:** new files / functions / types, with line counts and any new `pub` surface
- **Skipped:** complexity deliberately left out
- **Checks:** results of `cargo check` / `clippy` / `test`
- **Noticed:** unrelated issues, one line each, not fixed

Be direct. If I ask for something over-engineered, say so and propose the simpler version
before building what I asked for.
