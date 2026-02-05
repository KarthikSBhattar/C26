C26
===

What if Dennis wrote C in 2026 instead of 1972? C26 is an experiment to answer that question without losing the sharp, low-level feel we love. Goal: be “C for 2026,” with modern features and a garbage collector by default. Some DNA comes from an older project, JLang—I’ve reused its codegen system plus chunks of the lexer and parser to move fast.

Work in progress
----------------
- Early prototype: parser/IR still in progress.
- Design-first: we’re testing ideas before freezing syntax.
- Expect rough edges: crashes, missing diagnostics, and lots of TODOs.

Goals
-----
- Be C, but garbage collected by default—clear escape hatches stay for manual control.
- Modern features baked in: `match` expressions, string interpolation, `auto` type inference, tuples/destructuring, `typeof`, `null`, and generic containers (see `dict` in `examples/types.c26`).
- Tooling from day one: formatter, lints, package manager, and fast incremental builds.

Roadmap
-------
- Parser/AST cleanup and snapshot syntax reference.
- Minimal stdlib with memory, strings, and filesystem utilities.
- Tooling pass: formatter + linter + single-command build.
- FFI story: smooth interop with C and Rust.
- Performance tuning: benchmark harness and optimizer passes.

Contributing
------------
- Any ideas or annoyances or half-baked thoughts are VERY MUCH welcome.
- Short PRs are appreciated since we’re iterating fast.
