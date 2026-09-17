#!/usr/bin/env bash
set -euo pipefail

usage() {
	printf 'Usage: %s <commit-sha> <version> <artifact>\n' "$0" >&2
}

if [[ $# -ne 3 ]]; then
	usage
	exit 64
fi

commit="$1"
version="$2"
artifact="$3"

[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || {
	printf '%s\n' 'Invalid commit SHA.' >&2
	exit 64
}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
	printf '%s\n' 'Invalid semantic version.' >&2
	exit 64
}
[[ -f "$artifact" && ! -L "$artifact" ]] || {
	printf '%s\n' 'Artifact must be a regular file.' >&2
	exit 66
}

go_tool="${GO_TOOL:-go}"
if ! "$go_tool" version -m "$artifact" | grep -Fq $'mod\tgithub.com/HeartBtz/fluxgate\t'; then
	printf '%s\n' 'Artifact module does not match github.com/HeartBtz/fluxgate.' >&2
	exit 65
fi
version_pattern="${version//./\.}"
if [[ ! "$($artifact --version)" =~ ^fluxgate\ $version_pattern\ \(.+\)$ ]]; then
	printf '%s\n' 'Artifact version does not match the requested release.' >&2
	exit 65
fi

deploy_target="${DEPLOY_TARGET:?Set DEPLOY_TARGET to the CT110 forced-command SSH target}"
known_hosts="${DEPLOY_KNOWN_HOSTS:?Set DEPLOY_KNOWN_HOSTS to a pinned known_hosts file}"
[[ "$deploy_target" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$ ]] || {
	printf '%s\n' 'Invalid deployment target.' >&2
	exit 64
}
[[ -f "$known_hosts" ]] || {
	printf '%s\n' 'Pinned known_hosts file not found.' >&2
	exit 66
}

checksum="$(sha256sum "$artifact")"
checksum="${checksum%% *}"
ssh_options=(-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$known_hosts")
if [[ -n "${DEPLOY_IDENTITY_FILE:-}" ]]; then
	ssh_options+=(-i "$DEPLOY_IDENTITY_FILE")
fi

ssh "${ssh_options[@]}" "$deploy_target" "deploy fluxgate $commit $checksum" <"$artifact"
