# KCC 2026 실험 워크스페이스

이 디렉토리는 KCC 2026 논문용 LLM 코드리뷰 실험 자산을 한곳에 모아 둔 메인라인 워크스페이스다. 현재 논문 작성과 직접 연결되는 `v2 데이터셋 기반 실험`을 중심으로 유지한다.

## 현재 구조

```text
github-code-review/
├── dataset/
│   ├── python/
│   │   ├── original/
│   │   ├── payload_comment/
│   │   ├── payload_string/
│   │   ├── payload_varname/
│   │   ├── payload_pr_title/
│   │   ├── payload_pr_desc/
│   │   ├── payload_commit_msg/
│   │   ├── payload_encoding/
│   │   ├── payload_overflow/
│   │   ├── payload_role_switch/
│   │   └── payload_multi_file/
│   └── javascript/
│       ├── original/
│       ├── payload_comment/
│       ├── payload_string/
│       ├── payload_varname/
│       ├── payload_pr_title/
│       ├── payload_pr_desc/
│       └── payload_commit_msg/
├── scripts/
│   ├── reviewer_v2.py
│   ├── run_all_v2.sh
│   ├── analyze_v2.py
│   ├── advanced_experiment.py
│   └── setup_github_test.sh
├── results_advanced/
│   ├── _full_results.json
│   └── _results.csv
└── results_v2/
    ├── github_results_template.csv
    └── SCORING_GUIDE.md
```

## 실험 축별 역할

### 1. v2 데이터셋 기반 실험 축

- `scripts/reviewer_v2.py`
- `scripts/run_all_v2.sh`
- `scripts/analyze_v2.py`

현재 논문 본문과 가장 직접적으로 연결되는 주 실험 축이다. `dataset/` 아래의 실제 파일 기반 payload 세트를 읽어 2-pass 평가를 수행한다.

Python 데이터셋은 다음 11개 조건을 지원한다.

- `original`
- `payload_comment`
- `payload_string`
- `payload_varname`
- `payload_pr_title`
- `payload_pr_desc`
- `payload_commit_msg`
- `payload_encoding`
- `payload_overflow`
- `payload_role_switch`
- `payload_multi_file`

JavaScript 데이터셋은 현재 다음 7개 조건을 지원한다.

- `original`
- `payload_comment`
- `payload_string`
- `payload_varname`
- `payload_pr_title`
- `payload_pr_desc`
- `payload_commit_msg`

참고:
- `run_all_v2.sh`는 현재 Python과 JavaScript를 모두 순회하도록 설정되어 있다.
- PR 메타데이터 조건은 `payload_pr_title`, `payload_pr_desc`, `payload_commit_msg`를 각각 독립 결과 디렉토리로 저장한다.
- 준비되지 않은 고도화 payload 디렉토리나 비어 있는 메타데이터 디렉토리는 실행 시 자동으로 스킵된다.

### 2. 고급 조합 실험 축

- `scripts/advanced_experiment.py`

이 스크립트는 `dataset/` 트리를 읽는 방식이 아니라, 파일 내부에 정의된 취약 코드와 주입 기법 매트릭스를 조합해 별도 실험을 수행하는 독립 축이다. 즉, `reviewer_v2.py` 계열과는 목적과 입력 방식이 다르며, 같은 디렉토리에 공존하도록 유지한다.

현재 특성:

- PR reviewer 역할을 고정한 synthetic benchmark 형태다.
- 코드 샘플과 주입 기법이 스크립트 내부에 하드코딩되어 있다.
- 코드 블록 포맷과 샘플 파일명이 Python 기준으로 작성되어 있어, 현재 버전은 Python 중심 실험으로 보는 것이 맞다.

## 데이터셋 개요

### Python 취약점 세트

- SQL Injection
- XSS
- Path Traversal
- Command Injection
- SSRF

### JavaScript 취약점 세트

- SQL Injection
- XSS
- Path Traversal
- Command Injection
- SSRF

## 결과 기록 파일

- `results_v2/github_results_template.csv`: GitHub 기반 리뷰 결과 수기 정리 템플릿
- `results_v2/SCORING_GUIDE.md`: 5단계 리뷰 품질 채점 기준

## 실행 예시

### v2 데이터셋 기반 실험

```bash
cd scripts
export OPENAI_API_KEY=your_openai_api_key
bash run_all_v2.sh
python analyze_v2.py --results-dir ../results_v2 --csv ../results_v2/full_results.csv
```

### 고급 조합 실험

```bash
cd scripts
export OPENAI_API_KEY=your_openai_api_key
python advanced_experiment.py --output-dir ../results_advanced
```

### GitHub PR 실험 준비

```bash
cd scripts
bash setup_github_test.sh <GITHUB_USERNAME> <REPO_NAME>
```

## 운영 메모

- 이 워크스페이스는 논문 메인라인인 `v2` 실험을 기준으로 유지한다.
- `advanced_experiment.py`는 보조적인 별도 축이며, `dataset/` 기반 메인라인과 입력 방식이 다르다.
- 문서를 갱신할 때는 어떤 축을 설명하는지 먼저 명시하는 편이 혼선을 줄인다.
