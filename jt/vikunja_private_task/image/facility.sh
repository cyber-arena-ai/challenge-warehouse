#!/usr/bin/env bash
set -eu

. /arena/secrets/facility.env
BASE=http://127.0.0.1:3456

token() {
    response=$(printf '{"username":"%s","password":"%s"}' \
        "$FACILITY_USER" "$FACILITY_PASS" \
        | curl -fsS --max-time 20 -H 'Content-Type: application/json' \
            --data-binary @- "$BASE/api/v1/login") || return 3
    printf %s "$response" | node -e \
        'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let v=JSON.parse(s).token||"";if(v)process.stdout.write(v+"\n")})'
}

case "${1:-}" in
    setup)
        printf '{"username":"%s","email":"%s@arena.invalid","password":"%s"}' \
            "$FACILITY_USER" "$FACILITY_USER" "$FACILITY_PASS" \
            | curl -sS --max-time 20 -o /dev/null -H 'Content-Type: application/json' \
                --data-binary @- "$BASE/api/v1/register" || true
        token >/dev/null || exit 3
        touch /arena/state/facility_ready
        ;;
    token)
        token
        ;;
    find-uid)
        project="${2:?project id required}"
        needle=$(printf %s "${3:?needle required}" | base64 -d)
        xml=$(curl -fsS --max-time 20 -u "$FACILITY_USER:$FACILITY_PASS" \
            -X PROPFIND -H 'Depth: 1' "$BASE/dav/projects/$project/")
        paths=$(printf %s "$xml" | grep -oE "/dav/projects/$project/[^<]+[.]ics" | sort -u)
        for path in $paths; do
            body=$(curl -fsS --max-time 20 -u "$FACILITY_USER:$FACILITY_PASS" \
                -H 'Accept: text/calendar' "$BASE$path") || continue
            if printf %s "$body" | grep -Fq -- "$needle"; then
                uid=${path##*/}
                printf '%s\n' "${uid%.ics}"
                exit 0
            fi
        done
        exit 4
        ;;
    *)
        echo "usage: facility.sh setup|token|find-uid" >&2
        exit 2
        ;;
esac
