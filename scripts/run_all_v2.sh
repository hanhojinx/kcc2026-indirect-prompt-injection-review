#!/bin/bash
# run_all_v2.sh - 전체 실험 배치 (고도화 payload + 세분화 평가 포함)
# 사용법: OPENAI_API_KEY=your_key bash run_all_v2.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATASET_DIR="$SCRIPT_DIR/../dataset"
RESULTS_DIR="$SCRIPT_DIR/../results_v2"

if [ -z "$OPENAI_API_KEY" ]; then
    echo "에러: OPENAI_API_KEY 환경변수를 설정해주세요."
    exit 1
fi

echo "============================================"
echo "KCC 2026 실험 v2 (고도화 + 세분화)"
echo "============================================"

LANGUAGES=("python")  # JS는 필요시 추가
# 기본 payload + 고도화 payload
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

for LANG in "${LANGUAGES[@]}"; do
    for PTYPE in "${PAYLOAD_TYPES[@]}"; do
        INPUT="$DATASET_DIR/$LANG/$PTYPE"
        OUTPUT="$RESULTS_DIR/${PTYPE}_${LANG}"

        if [ ! -d "$INPUT" ]; then
            echo "스킵: $INPUT 없음"
            continue
        fi

        # 코드 파일이 있는지 확인
        FILE_COUNT=$(find "$INPUT" -name "*.py" -o -name "*.js" 2>/dev/null | wc -l)
        if [ "$FILE_COUNT" -eq 0 ]; then
            echo "스킵: $INPUT 에 코드 파일 없음"
            continue
        fi

        echo ""
        echo "▶ 실행: $LANG / $PTYPE ($FILE_COUNT files)"
        python3 "$SCRIPT_DIR/reviewer_v2.py" \
            --api-key "$OPENAI_API_KEY" \
            --input-dir "$INPUT" \
            --output-dir "$OUTPUT"
    done

    # PR Description 실험 (original code + PR desc)
    INPUT="$DATASET_DIR/$LANG/original"
    PR_DESC="$DATASET_DIR/$LANG/payload_pr_desc"
    OUTPUT="$RESULTS_DIR/payload_pr_desc_${LANG}"

    if [ -d "$PR_DESC" ]; then
        echo ""
        echo "▶ 실행: $LANG / payload_pr_desc"
        python3 "$SCRIPT_DIR/reviewer_v2.py" \
            --api-key "$OPENAI_API_KEY" \
            --input-dir "$INPUT" \
            --pr-desc-dir "$PR_DESC" \
            --output-dir "$OUTPUT"
    fi
done

echo ""
echo "============================================"
echo "전체 실험 완료!"
echo "결과 분석: python3 $SCRIPT_DIR/analyze_v2.py --results-dir $RESULTS_DIR"
echo "============================================"
