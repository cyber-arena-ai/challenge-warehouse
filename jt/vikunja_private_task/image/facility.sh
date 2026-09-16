#!/usr/bin/env bash
set -eu

. /arena/secrets/facility.env
BASE=http://127.0.0.1:3456
HTTP=/arena/facility-http.js

token() {
    response=$(printf '{"username":"%s","password":"%s"}' \
        "$FACILITY_USER" "$FACILITY_PASS" \
        | node "$HTTP" POST "$BASE/api/v1/login" \
            'Content-Type=application/json') || return 3
    printf %s "$response" | node -e \
        'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let v=JSON.parse(s).token||"";if(v)process.stdout.write(v+"\n")})'
}

repair_account() {
    set -a
    . /arena/secrets/service.env
    set +a
    if /arena/vikunja user reset-password "$FACILITY_USER" \
        --direct --password "$FACILITY_PASS" >/dev/null 2>&1; then
        /arena/vikunja user change-status "$FACILITY_USER" \
            --enable >/dev/null 2>&1 || return 3
    else
        /arena/vikunja user create \
            --username "$FACILITY_USER" \
            --email "$FACILITY_USER@arena.invalid" \
            --password "$FACILITY_PASS" >/dev/null 2>&1 || return 3
    fi
    token >/dev/null || return 3
    touch /arena/state/facility_ready || return 3
}

case "${1:-}" in
    setup)
        printf '{"username":"%s","email":"%s@arena.invalid","password":"%s"}' \
            "$FACILITY_USER" "$FACILITY_USER" "$FACILITY_PASS" \
            | node "$HTTP" POST "$BASE/api/v1/register" \
                'Content-Type=application/json' >/dev/null || true
        token >/dev/null || exit 3
        touch /arena/state/facility_ready
        ;;
    token)
        token
        ;;
    repair)
        repair_account || exit 3
        ;;
    find-uid)
        project="${2:?project id required}"
        needle=$(printf %s "${3:?needle required}" | base64 -d)
        auth=$(printf '%s' "$FACILITY_USER:$FACILITY_PASS" | base64 | tr -d '\n')
        xml=$(node "$HTTP" PROPFIND "$BASE/dav/projects/$project/" \
            "Authorization=Basic $auth" 'Depth=1')
        paths=$(printf %s "$xml" | grep -oE "/dav/projects/$project/[^<]+[.]ics" | sort -u)
        for path in $paths; do
            body=$(node "$HTTP" GET "$BASE$path" \
                "Authorization=Basic $auth" \
                'Accept=text/calendar') || continue
            if printf %s "$body" | grep -Fq -- "$needle"; then
                uid=${path##*/}
                printf '%s\n' "${uid%.ics}"
                exit 0
            fi
        done
        exit 4
        ;;
    *)
        echo "usage: facility.sh setup|token|repair|find-uid" >&2
        exit 2
        ;;
esac
