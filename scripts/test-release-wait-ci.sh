#!/usr/bin/env bash
# Cases for release.sh's wait_for_ci, against a fake gh: it must never call CI
# green while the commit's CI workflow is queued or not started (#251).
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sed -n '/^die()/p; /^wait_for_ci()/,/^}/p' scripts/release.sh > "$work/wait.sh"
# The fake gh prints $CHECKS for check runs and $RUNS for workflow runs.
cat > "$work/gh" <<'GH'
#!/usr/bin/env bash
case $1 in api) printf '%b' "$CHECKS" ;; run) printf '%b' "$RUNS" ;; *) exit 2 ;; esac
GH
chmod +x "$work/gh"
fail=0
check() { # want (green|wait|failed), check runs, workflow runs (name\tstatus\tconclusion lines)
    local got
    got=$(PATH=$work:$PATH CHECKS=$2 RUNS=$3 RELEASE_CI_TIMEOUT=0 bash -c ". '$work/wait.sh'; wait_for_ci abc1234" 2>&1 || true)
    case $got in
        *"CI is green"*) got=green ;;
        *"CI failed"*) got=failed ;;
        *"not finished"*) got="wait" ;;
    esac
    [[ $got == "$1" ]] || { echo "FAIL: want $1, got: $got (checks '$2', runs '$3')"; fail=1; }
}
sonar='SonarCloud\tcompleted\tsuccess\n'
check wait  "$sonar" ''                                        # CI not started yet: the v0.2.7 case
check wait  "$sonar" 'CI\tqueued\t\n'                          # CI queued behind the previous commit
check wait  "$sonar" 'CI\tin_progress\t\n'
check green "${sonar}Rust\tcompleted\tsuccess\n" 'CI\tcompleted\tsuccess\n'
check failed "$sonar" 'CI\tcompleted\tfailure\n'
check failed "${sonar}Rust\tcompleted\tfailure\n" 'CI\tcompleted\tfailure\n'
[[ $fail == 0 ]] && echo "release wait_for_ci: all cases pass"
exit "$fail"
