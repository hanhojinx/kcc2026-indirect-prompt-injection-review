#!/bin/bash
# run_all_v2.sh - Batch runner for the dataset-based PR-metadata benchmark
# Usage: OPENAI_API_KEY=your_key bash run_all_v2.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATASET_DIR="$SCRIPT_DIR/../dataset"
RESULTS_DIR="$SCRIPT_DIR/../results_v2"

if [ -z "$OPENAI_API_KEY" ]; then
    echo "Error: set the OPENAI_API_KEY environment variable first."
    exit 1
fi

echo "============================================"
echo "Dataset-Based PR Metadata Benchmark (v2)"
echo "============================================"

LANGUAGES=("python" "javascript")
# Code-channel payloads
PAYLOAD_TYPES=(
    "original"
    "payload_comment"
    "payload_string"
    "payload_varname"
    "payload_encoding"
    "payload_overflow"
    "payload_role_switch"
    "payload_multi_file"
)

# Metadata-only attack conditions
METADATA_CASES=(
    "payload_pr_title|_title.md|--pr-title-dir"
    "payload_pr_desc|_pr.md|--pr-desc-dir"
    "payload_commit_msg|_commit.md|--commit-msg-dir"
)

for LANG in "${LANGUAGES[@]}"; do
    for PTYPE in "${PAYLOAD_TYPES[@]}"; do
        INPUT="$DATASET_DIR/$LANG/$PTYPE"
        OUTPUT="$RESULTS_DIR/${PTYPE}_${LANG}"

        if [ ! -d "$INPUT" ]; then
            echo "Skip: missing directory $INPUT"
            continue
        fi

        # Check whether the condition directory contains code files.
        FILE_COUNT=$(find "$INPUT" -name "*.py" -o -name "*.js" 2>/dev/null | wc -l)
        if [ "$FILE_COUNT" -eq 0 ]; then
            echo "Skip: no code files found in $INPUT"
            continue
        fi

        echo ""
        echo "▶ Running: $LANG / $PTYPE ($FILE_COUNT files)"
        python3 "$SCRIPT_DIR/reviewer_v2.py" \
            --api-key "$OPENAI_API_KEY" \
            --input-dir "$INPUT" \
            --output-dir "$OUTPUT"
    done

    # Metadata-channel experiment: original code + separate metadata payload.
    for META_SPEC in "${METADATA_CASES[@]}"; do
        IFS='|' read -r META_TYPE META_PATTERN META_FLAG <<< "$META_SPEC"
        INPUT="$DATASET_DIR/$LANG/original"
        META_DIR="$DATASET_DIR/$LANG/$META_TYPE"
        OUTPUT="$RESULTS_DIR/${META_TYPE}_${LANG}"

        if [ ! -d "$META_DIR" ]; then
            echo "Skip: missing directory $META_DIR"
            continue
        fi

        META_COUNT=$(find "$META_DIR" -name "*$META_PATTERN" 2>/dev/null | wc -l)
        if [ "$META_COUNT" -eq 0 ]; then
            echo "Skip: no metadata files found in $META_DIR"
            continue
        fi

        echo ""
        echo "▶ Running: $LANG / $META_TYPE ($META_COUNT files)"
        python3 "$SCRIPT_DIR/reviewer_v2.py" \
            --api-key "$OPENAI_API_KEY" \
            --input-dir "$INPUT" \
            "$META_FLAG" "$META_DIR" \
            --output-dir "$OUTPUT"
    done
done

echo ""
echo "============================================"
echo "Benchmark complete."
echo "Analyze results with: python3 $SCRIPT_DIR/analyze_v2.py --results-dir $RESULTS_DIR"
echo "============================================"
