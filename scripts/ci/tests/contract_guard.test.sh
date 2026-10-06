#!/bin/sh
# Self-test of scripts/ci/contract_guard.sh: every case builds a throw-away git
# repository, runs the guard in it and asserts the exit status AND a piece of the
# message, so a guard that always fails (or always passes) cannot satisfy it.
#
# This is what exercises the guard's logic when no pull request exists: the
# workflow wiring (checkout depth, github.event.* fields) is the part only GitHub
# can run. Run it locally with:  sh scripts/ci/tests/contract_guard.test.sh
#
# Overrides, for proving that a case has teeth against a deliberately broken guard:
#   CONTRACT_GUARD=<script>          the guard under test
#   CONTRACT_SURFACES_FILE=<file>    the surface table handed to it
#   CONTRACT_GUARD_SHELL=<shell>     the interpreter for it (default sh)
set -eu

here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
guard="${CONTRACT_GUARD:-${here}/../contract_guard.sh}"
table="${CONTRACT_SURFACES_FILE:-${here}/../contract_surfaces.txt}"
guard_shell="${CONTRACT_GUARD_SHELL:-sh}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM

# The repositories below must not see the developer's git configuration or an
# enclosing repository (GIT_DIR is set when this runs from a git hook).
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE
export HOME="${work}/home" XDG_CONFIG_HOME="${work}/xdg" GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME" "$XDG_CONFIG_HOME"
git config --global user.name "Contract Guard Test"
git config --global user.email "contract-guard-test@example.invalid"
git config --global init.defaultBranch main
git config --global commit.gpgsign false
git config --global core.autocrlf false

zero="0000000000000000000000000000000000000000"
unknown="1111111111111111111111111111111111111111"
matrix="docs/COMPATIBILITY_MATRIX.md"

total=0
failed=0
rc=0

# put REPO PATH TEXT: write one file.
put() {
  mkdir -p "$(dirname -- "$1/$2")"
  printf '%s\n' "$3" > "$1/$2"
}

# commit REPO MESSAGE: commit everything.
commit() {
  git -C "$1" add -A
  git -C "$1" commit -q -m "$2"
}

# new_repo NAME: a repository with one base commit that holds a file on, and a
# file next to, each guarded area; prints its path.
new_repo() {
  repo="${work}/$1"
  mkdir -p "$repo"
  git -C "$repo" init -q
  put "$repo" "$matrix" "matrix v1"
  put "$repo" README.md "readme v1"
  put "$repo" crates/ssk-config/src/routing.rs "routing v1"
  put "$repo" crates/ssk-daemon/src/ingress/audit/writer.rs "writer v1"
  put "$repo" crates/ssk-daemon/src/ingress/engine.rs "engine v1"
  commit "$repo" "base"
  printf '%s\n' "$repo"
}

sha() {
  git -C "$1" rev-parse "$2"
}

# run_guard REPO BASE HEAD [TABLE]: sets $rc; stdout and stderr land in $work/out
# and $work/err (joined in $work/both for the assertions).
run_guard() {
  rc=0
  (cd "$1" && CONTRACT_SURFACES_FILE="${4:-$table}" "$guard_shell" "$guard" "$2" "$3") \
    > "${work}/out" 2> "${work}/err" || rc=$?
  cat "${work}/out" "${work}/err" > "${work}/both"
}

# check DESCRIPTION WANT_STATUS TEXT...: the last run_guard must have exited with
# WANT_STATUS and printed every TEXT.
check() {
  desc="$1"
  want="$2"
  shift 2
  total=$((total + 1))
  why=""
  if [ "$rc" -ne "$want" ]; then
    why="exit status ${rc}, wanted ${want}"
  else
    for text in "$@"; do
      if ! grep -qF -e "$text" "${work}/both"; then
        why="output does not contain '${text}'"
        break
      fi
    done
  fi
  if [ -z "$why" ]; then
    echo "ok ${total} - ${desc}"
  else
    failed=$((failed + 1))
    echo "not ok ${total} - ${desc}: ${why}"
    sed 's/^/#   /' "${work}/both"
  fi
}

# --- The rule -----------------------------------------------------------------

r="$(new_repo c01)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/ingress.rs "pub struct Ingress;"
commit "$r" "feat(ssk-config): add the ingress section"
run_guard "$r" "$base" HEAD
check "a new ingress.rs without a matrix entry fails (the old regex missed it)" 1 \
  "a contract surface changed but" "config:" "crates/ssk-config/src/ingress.rs"

r="$(new_repo c02)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "feat(ssk-config): change routing"
run_guard "$r" "$base" HEAD
check "an edited routing.rs without a matrix entry fails" 1 \
  "a contract surface changed but" "crates/ssk-config/src/routing.rs"

r="$(new_repo c03)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
put "$r" "$matrix" "matrix v2"
commit "$r" "feat(ssk-config): change routing and record it"
run_guard "$r" "$base" HEAD
check "a surface change plus a matrix update passes" 0 "was updated in the same range"

r="$(new_repo c04)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "fix(ssk-config): reword a comment

Compat-Impact: none (comment only change)"
run_guard "$r" "$base" HEAD
check "a Compat-Impact trailer with a reason passes" 0 "trailer was given"

r="$(new_repo c05)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "fix(ssk-config): reword a comment

Compat-Impact: none ()"
run_guard "$r" "$base" HEAD
check "a Compat-Impact trailer with an empty reason fails" 1 "a contract surface changed but"

r="$(new_repo c06)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "fix(ssk-config): reword a comment

Compat-Impact: none (x)"
run_guard "$r" "$base" HEAD
check "a Compat-Impact trailer with a one-character reason fails" 1 "a contract surface changed but"

r="$(new_repo c07)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "fix(ssk-config): reword a comment

Compat-Impact: none (1234567)"
run_guard "$r" "$base" HEAD
check "a seven-character reason fails (the minimum is eight)" 1 "a contract surface changed but"

r="$(new_repo c08)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "fix(ssk-config): reword a comment

Compat-Impact: none (12345678)"
run_guard "$r" "$base" HEAD
check "an eight-character reason passes" 0 "trailer was given"

r="$(new_repo c09)"
base="$(sha "$r" HEAD)"
put "$r" README.md "readme v2"
commit "$r" "docs: reword the readme"
run_guard "$r" "$base" HEAD
check "an unrelated file passes" 0 "no contract surface changed"

r="$(new_repo c10)"
base="$(sha "$r" HEAD)"
put "$r" "$matrix" "matrix v2"
commit "$r" "docs: add a matrix note"
run_guard "$r" "$base" HEAD
check "a matrix-only change passes (the old regex counted it as a contract change)" 0 \
  "no contract surface changed"

r="$(new_repo c10b)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
put "$r" "${matrix}.orig" "a stray copy"
commit "$r" "feat(ssk-config): change routing, leave a stray copy of the matrix"
run_guard "$r" "$base" HEAD
check "a file that merely contains the matrix path is not the matrix" 1 \
  "a contract surface changed but"

r="$(new_repo c11)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-daemon/src/ingress/audit/writer.rs "writer v2"
commit "$r" "fix(ssk-daemon): change the ledger writer"
run_guard "$r" "$base" HEAD
check "an ingress ledger writer change without a matrix entry fails" 1 \
  "a contract surface changed but" "ingress-ledger:" "crates/ssk-daemon/src/ingress/audit/writer.rs"

r="$(new_repo c12)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-daemon/src/ingress/engine.rs "engine v2"
commit "$r" "fix(ssk-daemon): change the engine"
run_guard "$r" "$base" HEAD
check "an ingress file that is not a format passes" 0 "no contract surface changed"

r="$(new_repo c13)"
base="$(sha "$r" HEAD)"
git -C "$r" rm -q crates/ssk-config/src/routing.rs
commit "$r" "refactor(ssk-config): remove routing"
run_guard "$r" "$base" HEAD
check "deleting a surface file fails" 1 \
  "a contract surface changed but" "crates/ssk-config/src/routing.rs"

r="$(new_repo c14)"
base="$(sha "$r" HEAD)"
mkdir -p "$r/crates/other"
git -C "$r" mv crates/ssk-config/src/routing.rs crates/other/routing.rs
commit "$r" "refactor: move routing out of ssk-config"
run_guard "$r" "$base" HEAD
check "moving a surface file out of its directory fails (renames are not collapsed)" 1 \
  "a contract surface changed but" "crates/ssk-config/src/routing.rs"

# --- Every row of the surface table ---------------------------------------------

samples="config crates/ssk-config/tests/golden/schema.json
ipc-wire crates/ssk-ipc/tests/wire_protocol0.rs
activation-ledger-and-wire-types crates/ssk-netadmin/src/audit.rs
ingress-ledger crates/ssk-daemon/src/ingress/audit/store.rs
ui-contract crates/ssk-ui-contract/src/dto.rs
interop crates/ssk-interop/src/lib.rs
interop-spec docs/INTEROP_SPEC.md"

while read -r label path <&3; do
  r="$(new_repo "row-${label}")"
  base="$(sha "$r" HEAD)"
  put "$r" "$path" "changed"
  commit "$r" "change ${path}"
  run_guard "$r" "$base" HEAD
  check "the ${label} surface fires on ${path}" 1 "${label}:" "${path}"
done 3<<EOF
${samples}
EOF

# A row added to the table without a case above would be unpinned.
table_labels="$(awk -F '\t' '!/^#/ && NF > 0 { print $1 }' "$table" | sort)"
sample_labels="$(printf '%s\n' "$samples" | awk '{ print $1 }' | sort)"
total=$((total + 1))
if [ "$table_labels" = "$sample_labels" ]; then
  echo "ok ${total} - every row of the surface table has a sample path above"
else
  failed=$((failed + 1))
  echo "not ok ${total} - every row of the surface table has a sample path above"
  echo "#   table rows:   $(echo "$table_labels" | tr '\n' ' ')"
  echo "#   sample paths: $(echo "$sample_labels" | tr '\n' ' ')"
fi

# --- The range ------------------------------------------------------------------

r="$(new_repo c20)"
put "$r" README.md "readme v2"
commit "$r" "docs: earlier work

Compat-Impact: none (it belongs to an earlier pull request)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "feat(ssk-config): change routing"
run_guard "$r" "$base" HEAD
check "a trailer on a commit before BASE does not excuse a later change" 1 \
  "a contract surface changed but"

r="$(new_repo c21)"
put "$r" "$matrix" "matrix v2"
commit "$r" "docs: earlier matrix note"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "feat(ssk-config): change routing"
run_guard "$r" "$base" HEAD
check "a matrix update before BASE does not excuse a later change" 1 \
  "a contract surface changed but"

r="$(new_repo c22)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "feat(ssk-config): change routing"
put "$r" README.md "readme v2"
commit "$r" "docs: explain it

Compat-Impact: none (the change above is a comment)"
put "$r" README.md "readme v3"
commit "$r" "docs: reword the explanation"
run_guard "$r" "$base" HEAD
check "a trailer on any commit of the range counts, not only the last" 0 "trailer was given"

# BASE is where the target branch is NOW; a change that landed there after HEAD
# forked is not HEAD's. HEAD is the unrelated side here.
r="$(new_repo c23)"
fork="$(sha "$r" HEAD)"
git -C "$r" checkout -q -b feature
put "$r" README.md "readme v2"
commit "$r" "docs: reword the readme"
feature_tip="$(sha "$r" HEAD)"
git -C "$r" checkout -q main
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "feat(ssk-config): change routing, recorded elsewhere"
main_tip="$(sha "$r" HEAD)"
run_guard "$r" "$main_tip" "$feature_tip"
check "the diff starts at the merge base, so changes that landed on BASE are not HEAD's" 0 \
  "no contract surface changed in ${fork}"

# --- Fails closed ---------------------------------------------------------------

r="$(new_repo c30)"
head_sha="$(sha "$r" HEAD)"
run_guard "$r" "$zero" "$head_sha"
check "an all-zero BASE fails closed" 1 "all-zero"

run_guard "$r" "$unknown" "$head_sha"
check "an unknown BASE fails closed" 1 "is not in this checkout"

run_guard "$r" "$head_sha" "$unknown"
check "an unknown HEAD fails closed" 1 "HEAD ${unknown} is not in this checkout"

run_guard "$r" "$head_sha" "$head_sha" "${work}/no-such-table.txt"
check "a missing surface table fails closed" 1 "surface table" "is missing"

printf '%s\n' "# nothing but a comment" "" > "${work}/empty-table.txt"
run_guard "$r" "$head_sha" "$head_sha" "${work}/empty-table.txt"
check "a surface table without rows fails closed" 1 "has no surface rows"

printf 'broken\t^crates/(unclosed\n' > "${work}/bad-regex-table.txt"
run_guard "$r" "$head_sha" "$head_sha" "${work}/bad-regex-table.txt"
check "a regex that grep rejects fails closed instead of matching nothing" 1 "grep rejected the regex"

r="$(new_repo c31)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "feat(ssk-config): change routing"
printf 'config\t^crates/ssk-config/src/' > "${work}/no-newline-table.txt"
run_guard "$r" "$base" HEAD "${work}/no-newline-table.txt"
check "the last table row is enforced although it has no trailing newline" 1 \
  "a contract surface changed but" "config:"

# A history that shares nothing with BASE has no merge base.
r="$(new_repo c32)"
base="$(sha "$r" HEAD)"
git -C "$r" checkout -q --orphan unrelated
git -C "$r" rm -rfq .
put "$r" README.md "a different history"
commit "$r" "root of an unrelated history"
run_guard "$r" "$base" HEAD
check "no merge base fails closed" 1 "no merge base"

# What actions/checkout does without fetch-depth: BASE is not in the clone.
r="$(new_repo c33)"
base="$(sha "$r" HEAD)"
put "$r" crates/ssk-config/src/routing.rs "routing v2"
commit "$r" "feat(ssk-config): change routing"
git clone -q --depth 1 "file://${r}" "${work}/c33-shallow"
run_guard "${work}/c33-shallow" "$base" HEAD
check "a depth-1 clone fails closed and names fetch-depth" 1 "is not in this checkout" "fetch-depth: 0"

# --- Paths git does not print as plain text -------------------------------------

r="$(new_repo c40)"
base="$(sha "$r" HEAD)"
umlaut_name="$(printf '\303\274bersicht.rs')"
put "$r" "crates/ssk-config/src/${umlaut_name}" "non-ASCII name"
commit "$r" "feat(ssk-config): add a file with a non-ASCII name"
run_guard "$r" "$base" HEAD
check "a surface file with a non-ASCII name is still matched" 1 \
  "a contract surface changed but" "crates/ssk-config/src/${umlaut_name}"

r="$(new_repo c41)"
base="$(sha "$r" HEAD)"
tab_name="$(printf 'a\tb.md')"
put "$r" "docs/${tab_name}" "tab in the name"
commit "$r" "docs: a file name with a tab"
run_guard "$r" "$base" HEAD
check "a path that git must quote fails closed" 1 "cannot be matched"

echo "${total} cases, ${failed} failed"
[ "$failed" -eq 0 ]
