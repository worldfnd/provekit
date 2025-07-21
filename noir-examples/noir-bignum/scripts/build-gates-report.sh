#!/usr/bin/env bash
set -e

BACKEND=${BACKEND:-bb}

cd $(dirname "$0")/../

artifacts_path="./export"
artifacts=$(ls $artifacts_path)

echo "{\"programs\": [" > gates_report.json

# Bound for checking where to place last parentheses 
NUM_ARTIFACTS=$(ls -1q "$artifacts_path" | wc -l)

ITER="1"
for artifact in $artifacts; do    
    ARTIFACT_NAME=$(basename "$artifact")

    GATES_INFO=$($BACKEND gates -b "$artifacts_path/$artifact")
    MAIN_FUNCTION_INFO=$(echo $GATES_INFO | jq -r '.functions[0] | .name = "main"')
    echo "{\"package_name\": \"$ARTIFACT_NAME\", \"functions\": [$MAIN_FUNCTION_INFO]" >> gates_report.json

    if (($ITER == $NUM_ARTIFACTS)); then
        echo "}" >> gates_report.json
    else 
        echo "}, " >> gates_report.json
    fi

    ITER=$(( $ITER + 1 ))
done

echo "]}" >> gates_report.json 

# Convert the gates report into separate benchmark files
output_file_opcodes="benchmark-opcodes.json"
output_file_circuit="benchmark-circuit.json"

# Convert gates report - opcodes
jq -r '[.programs[] | {
    "name": "\(.package_name)/main",
    "unit": "acir_opcodes",
    "value": (.functions[0].acir_opcodes // 0)
}]' gates_report.json > $output_file_opcodes

# Convert gates report - circuit size
jq -r '[.programs[] | {
    "name": "\(.package_name)/main",
    "unit": "circuit_size",
    "value": (.functions[0].circuit_size // 0)
}]' gates_report.json > $output_file_circuit

