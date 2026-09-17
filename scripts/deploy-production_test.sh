#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/scripts/deploy-production.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if "$script" invalid 1.2.3 /missing 2>/dev/null; then
	printf '%s\n' 'deploy script accepted an invalid commit' >&2
	exit 1
fi
if "$script" 0123456789012345678901234567890123456789 1.2 /missing 2>/dev/null; then
	printf '%s\n' 'deploy script accepted an invalid version' >&2
	exit 1
fi

bash -n "$script"

printf '%s\n' '#!/usr/bin/env bash' 'printf '\''fluxgate 1.2.3 (test)\n'\''' >"$tmp/artifact"
printf '%s\n' '#!/usr/bin/env bash' 'printf '\''path\tcommand-line-arguments\nmod\tgithub.com/HeartBtz/fluxgate\t(devel)\n'\''' >"$tmp/go"
printf '%s\n' '#!/usr/bin/env bash' 'printf '\''%s\n'\'' "$@" > "$SSH_ARGS"' 'cat > "$SSH_STDIN"' >"$tmp/ssh"
chmod +x "$tmp/artifact" "$tmp/go" "$tmp/ssh"
touch "$tmp/known_hosts"

checksum="$(sha256sum "$tmp/artifact")"
checksum="${checksum%% *}"
export GO_TOOL="$tmp/go"
export DEPLOY_TARGET="root@ct110.example"
export DEPLOY_KNOWN_HOSTS="$tmp/known_hosts"
export SSH_ARGS="$tmp/ssh.args"
export SSH_STDIN="$tmp/ssh.stdin"
PATH="$tmp:$PATH" "$script" 0123456789012345678901234567890123456789 1.2.3 "$tmp/artifact"

grep -Fxq 'root@ct110.example' "$SSH_ARGS"
grep -Fxq "deploy fluxgate 0123456789012345678901234567890123456789 $checksum" "$SSH_ARGS"
cmp "$tmp/artifact" "$SSH_STDIN"
printf '%s\n' 'deploy-production.sh validation tests passed'
