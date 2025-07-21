#!/usr/bin/env bash
set -e

INSPECTOR=${INSPECTOR:-noir-inspector}
cd $(dirname "$0")/../

artifacts_path="./export"
artifacts=$(ls $artifacts_path)

# Start the JSON array
REPORTS=$(jq --null-input '[]')

for artifact in $artifacts; do    
    # Get and format the opcode info
    OP_CODE_INFO=$($INSPECTOR info --json "$artifacts_path/$artifact")

    # Simplified jq expression to output only package_name and opcodes from unconstrained_functions
    REPORTS=$(echo $OP_CODE_INFO | jq -c '.programs[0] | del(.functions)' | jq -c --argjson old_reports $REPORTS '$old_reports + [.]')
done

echo $REPORTS | jq '{ programs: . }' > brillig_report.json

# Convert brillig report to benchmark format
output_file_brillig="benchmark-brillig.json"
jq -r '[.programs[] | .unconstrained_functions[] | {
    "name": (if (.package_name // "") == "" then .name else "\(.package_name | sub("^null/"; ""))/\(.name)" end),
    "unit": "opcodes",
    "value": (.opcodes // 0)
}]' brillig_report.json > $output_file_brillig
