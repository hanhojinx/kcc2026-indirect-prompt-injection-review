#!/bin/bash
# run_all.sh - 전체 실험 배치 실행
# 사용법: OPENAI_API_KEY=your_key bash run_all.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATASET_DIR="$SCRIPT_DIR/../dataset"
RESULTS_DIR="$SCRIPT_DIR/../results"

if [ -z "$OPENAI_API_KEY" ]; then
    echo "에러: OPENAI_API_KEY 환경변수를 설정해주세요."
    echo "  export OPENAI_API_KEY=your_key"
    exit 1
fi

echo "============================================"
echo "KCC 2026 실험 전체 배치 실행"
echo "============================================"

LANGUAGES=("python" "javascript")
# payload_pr_desc는 별도 처리 (PR description + original 코드 조합)
PAYLOAD_TYPES=("original" "payload_comment" "payload_string" "payload_varname")

# 일반 실험: original + 3가지 payload
for LANG in "${LANGUAGES[@]}"; do
    for PTYPE in "${PAYLOAD_TYPES[@]}"; do
        INPUT="$DATASET_DIR/$LANG/$PTYPE"
        OUTPUT="$RESULTS_DIR/${PTYPE}_${LANG}"

        if [ ! -d "$INPUT" ]; then
            echo "스킵: $INPUT 없음"
            continue
        fi

        echo ""
        echo "▶ 실행: $LANG / $PTYPE"
        python3 "$SCRIPT_DIR/reviewer.py" \
            --api-key "$OPENAI_API_KEY" \
            --input-dir "$INPUT" \
            --output-dir "$OUTPUT"
    done
done

# PR Description 실험: original 코드 + PR desc payload
for LANG in "${LANGUAGES[@]}"; do
    INPUT="$DATASET_DIR/$LANG/original"
    PR_DESC="$DATASET_DIR/$LANG/payload_pr_desc"
    OUTPUT="$RESULTS_DIR/payload_pr_desc_${LANG}"

    if [ ! -d "$PR_DESC" ]; then
        echo "스킵: $PR_DESC 없음"
        continue
    fi

    echo ""
    echo "▶ 실행: $LANG / payload_pr_desc (original code + PR desc)"
    python3 "$SCRIPT_DIR/reviewer.py" \
        --api-key "$OPENAI_API_KEY" \
        --input-dir "$INPUT" \
        --pr-desc-dir "$PR_DESC" \
        --output-dir "$OUTPUT"
done

echo ""
echo "============================================"
echo "전체 실험 완료! 결과 분석 실행:"
echo "  python3 $SCRIPT_DIR/analyze.py --results-dir $RESULTS_DIR"
echo "============================================"
