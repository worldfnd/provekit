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


