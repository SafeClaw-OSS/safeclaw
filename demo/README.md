# Recording the README demo

The README reserves a slot for `demo/demo.gif` (the HTML comment right under the
nav links). Two ways to produce it:

## vhs (scripted, reproducible)

[vhs](https://github.com/charmbracelet/vhs) replays a `.tape` script in a real
terminal and renders a GIF. The storyboard is already written:

```bash
go install github.com/charmbracelet/vhs@latest   # or: brew install vhs
vhs demo/demo.tape                                # writes demo/demo.gif
```

Prereqs on the recording machine: paired daemon, unlocked vault, a `github`
connection, `gh` installed. Edit the tape's `Sleep`s to match real latency,
re-run until it reads well, then swap the README comment for:

```markdown
<p align="center"><img src="demo/demo.gif" alt="SafeClaw demo" width="800" /></p>
```

## asciinema (freehand)

For a hand-driven take: `asciinema rec demo.cast`, then render with
[agg](https://github.com/asciinema/agg) (`agg demo.cast demo/demo.gif`) or embed
the cast on asciinema.org. Use vhs when you want retakes to be one command.

Keep the GIF under ~2 MB (GitHub renders it inline on the README); vhs's
default palette and 1100x560 frame stay well under that at ~25 s.
