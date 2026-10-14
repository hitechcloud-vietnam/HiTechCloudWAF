#!/bin/sh
# Applies the brand to a console static directory:
#  1. every file under brand/static/ replaces the file at the same path;
#  2. each line "FROM<TAB>TO" of replacements.tsv is replaced literally in
#     index.html and the JavaScript bundles.
# Licence / copyright notices are deliberately not touched: only the exact
# product-name phrases listed in replacements.tsv are changed.
set -eu
ROOT=${1:?static dir}
HERE=$(dirname "$0")

if [ -d "$HERE/static" ]; then
  (cd "$HERE/static" && find . -type f ! -name '.gitkeep') | while read -r f; do
    mkdir -p "$ROOT/$(dirname "$f")"
    cp "$HERE/static/$f" "$ROOT/$f"
    echo "asset: $f"
  done
fi

# Escape a literal for use in a sed s||| expression.
esc() { printf '%s' "$1" | sed -e 's/[\/&|.*^$[]/\\&/g' -e 's/\]/\\]/g'; }

TAB=$(printf '\t')
grep -v '^#' "$HERE/replacements.tsv" | grep "$TAB" | while IFS="$TAB" read -r from to; do
  [ -n "$from" ] || continue
  f=$(esc "$from"); t=$(esc "$to")
  n=0
  for file in "$ROOT/index.html" "$ROOT"/assets/*.js; do
    [ -f "$file" ] || continue
    if grep -qF "$from" "$file"; then
      sed -i "s|$f|$t|g" "$file"
      n=$((n + 1))
    fi
  done
  echo "replace: '$from' -> '$to' in $n file(s)"
done

# The upstream page has no <title>; give it one.
if ! grep -q '<title>' "$ROOT/index.html"; then
  sed -i "s|<head>|<head><title>${HCW_TITLE:-HiTechCloud WAF}</title>|" "$ROOT/index.html"
fi
