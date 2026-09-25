#!/bin/sh
# CI helper — runs INSIDE a per-kernel VM. Loads the built BPF object with the
# vendored static veristat and fails if the running kernel's verifier rejects
# any program. Driven by .github/workflows/kernel-matrix.yml, which boots each
# kernel with cilium's little-vm-helper and mounts the project at /host; the
# workflow stages the static veristat into bin/ before booting.
#
#   sh build/verify-kernel.sh [bpf-object ...]   (default: every bin/*.bpf.o)
#
# Set OUT_CSV=<path> to also write a machine-readable result (file,prog,verdict,
# insns,states) — the workflow points it at the mounted workspace so the runner
# can render a summary table from it after the VM exits.
#
# Why parse output instead of trusting the exit code: veristat returns 0 even
# when a program fails to load — a rejected program shows up as a VERDICT of
# "failure" in its table, not as a non-zero status. So the gate reads the verdict
# column. (veristat only exits non-zero on infra errors: missing file, OOM, etc.)

set -eu

# Every loadable object by default (probe, probe_ex, goprobe, rustprobe,
# socket) — the tap is split across several, and each must load on the kernel.
if [ "$#" -gt 0 ]; then
	set -- "$@"
else
	set -- bin/*.bpf.o
fi
VERISTAT="${VERISTAT:-./bin/veristat}"
# verdict LAST so the gate below can match it at end-of-line. veristat's CSV
# header uses each stat's canonical name, so the columns come out as
# file_name,prog_name,total_insns,total_states,verdict.
COLS="file,prog,insns,states,verdict"

[ -x "$VERISTAT" ] || { echo "error: veristat not found/executable at $VERISTAT" >&2; exit 1; }
for o in "$@"; do [ -f "$o" ] || { echo "error: BPF object not found at $o" >&2; exit 1; }; done

KREL="$(uname -r)"
echo ">> kernel $KREL: loading $*"

# Human-readable table for the console log (full default columns).
"$VERISTAT" "$@" || true

# Machine-readable pass: the verdict column is the gate; the rest feeds the
# workflow's summary table.
csv="$("$VERISTAT" -o csv -e "$COLS" "$@")"
if [ -n "${OUT_CSV:-}" ]; then
	mkdir -p "$(dirname "$OUT_CSV")"
	printf '%s\n' "$csv" > "$OUT_CSV"
fi

# Drop the header row; fail if any program's verdict is not "success".
rejected="$(printf '%s\n' "$csv" | tail -n +2 | awk -F, '$5 == "failure" { print $2 }')"
if [ -n "$rejected" ]; then
	# A verdict alone doesn't say why. Re-run just the rejected programs with the
	# verifier log on so the rejection is readable in the job output. Filter by
	# program name against the same object list: veristat's CSV names the file by
	# basename, which isn't a path we could hand back to it.
	for p in $rejected; do
		echo ">> verifier log for $p on kernel $KREL"
		"$VERISTAT" -v -f "$p" "$@" 2>&1 || true
	done
	echo "::error::BPF verifier rejected a program on kernel $KREL" >&2
	exit 1
fi

echo ">> all programs loaded on kernel $KREL"
