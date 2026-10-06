#!/bin/sh
# Fails when a contract surface changed between BASE and HEAD without either
#   (a) a change to docs/COMPATIBILITY_MATRIX.md in the same range, or
#   (b) a commit message line "Compat-Impact: none (<reason of at least 8 characters>)".
# The surfaces are the rows of scripts/ci/contract_surfaces.txt.
#
# Fails CLOSED: a BASE or HEAD that cannot be resolved, a missing or empty or
# unusable surface table, no merge base, or any failing git command is exit 1,
# never a pass. A guard that can only say "yes" is what this replaces.
#
# POSIX sh on purpose (no pipefail, no arrays): every command whose failure must
# be fatal runs as its own `x="$(...)" || fail`, not as a pipeline stage.
#
# Usage: contract_guard.sh BASE HEAD     (run it from inside the repository)
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
surfaces="${CONTRACT_SURFACES_FILE:-${script_dir}/contract_surfaces.txt}"
matrix="docs/COMPATIBILITY_MATRIX.md"

fail() {
  echo "contract_guard: FAIL: $*" >&2
  exit 1
}

[ "$#" -eq 2 ] || fail "usage: contract_guard.sh BASE HEAD"
base="$1"
head="$2"
[ -n "$base" ] || fail "BASE is empty"
[ -n "$head" ] || fail "HEAD is empty"

case "$base" in
  *[!0]*) ;; # contains a non-zero digit: fine
  *) fail "BASE is the all-zero sha (a new branch); the workflow must pass a merge base" ;;
esac
git cat-file -e "${base}^{commit}" 2>/dev/null \
  || fail "BASE ${base} is not in this checkout (the job needs fetch-depth: 0)"
git cat-file -e "${head}^{commit}" 2>/dev/null \
  || fail "HEAD ${head} is not in this checkout"
[ -r "$surfaces" ] || fail "surface table ${surfaces} is missing"

mb="$(git merge-base "$base" "$head")" || fail "no merge base between ${base} and ${head}"
# quotepath=off: git would otherwise print a non-ASCII name as "crates/...\303\274.rs"
# in quotes, and the leading quote would hide a surface file from every regex.
changed="$(git -c core.quotepath=off diff --name-only --no-renames "$mb" "$head")" \
  || fail "git diff ${mb}..${head} failed"

# Git still quotes a name with a tab, newline, double quote or backslash. Such a
# name cannot be matched reliably, so it is refused instead of risking a miss.
tab="$(printf '\t')"
nl='
'
dq='"'
case "${nl}${changed}" in
  *"${nl}${dq}"*) fail "a changed path contains a tab, newline, quote or backslash and cannot be matched; rename it" ;;
esac

hits=""
rows=0
# `|| [ -n "$label" ]`: a last row without a trailing newline makes `read` fail
# although it filled the variables, and that row must still be enforced.
while IFS="$tab" read -r label re || [ -n "$label" ]; do
  case "$label" in '' | '#'*) continue ;; esac
  [ -n "$re" ] || fail "surface table line for '${label}' has no regex"
  rows=$((rows + 1))
  # grep exits 1 for "no match" (fine) and 2 for an unusable regex or an I/O
  # error; the second must not be read as "nothing matched".
  status=0
  matched="$(printf '%s\n' "$changed" | grep -E -e "$re")" || status=$?
  [ "$status" -le 1 ] || fail "surface '${label}': grep rejected the regex '${re}'"
  if [ -n "$matched" ]; then
    indented="$(printf '%s\n' "$matched" | sed 's/^/    /')"
    hits="${hits}${label}:${nl}${indented}${nl}"
  fi
done < "$surfaces"
# A truncated or all-comment table would otherwise be a table nothing matches.
[ "$rows" -gt 0 ] || fail "surface table ${surfaces} has no surface rows"

if [ -z "$hits" ]; then
  echo "contract_guard: no contract surface changed in ${mb}..${head}"
  exit 0
fi

if printf '%s\n' "$changed" | grep -qxF -e "$matrix"; then
  echo "contract_guard: contract surface changed and ${matrix} was updated in the same range"
  exit 0
fi

# Captured first: `git log | grep -q` would let grep close the pipe early and
# make a long range look like a git failure.
messages="$(git log --format=%B "${mb}..${head}")" || fail "git log ${mb}..${head} failed"
if printf '%s\n' "$messages" | grep -Eq '^Compat-Impact: none \(.{8,}\)$'; then
  echo "contract_guard: contract surface changed; a 'Compat-Impact: none (...)' trailer was given"
  exit 0
fi

{
  echo "contract_guard: FAIL: a contract surface changed but ${matrix} did not, and no"
  echo "'Compat-Impact: none (<reason>)' trailer is present in ${mb}..${head}."
  echo "Changed surface files:"
  printf '%s' "$hits"
  echo "Either record the change in ${matrix}, or add the trailer to a commit message"
  echo "when the edit provably changes neither a file format nor a wire shape."
} >&2
exit 1
