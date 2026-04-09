# KCC 2026 코드리뷰 실험 레포

KCC 2026 논문 작업하면서 쓰는 실험 레포다.  
주제는 LLM 기반 코드리뷰 환경에서 indirect prompt injection이 리뷰 품질을 얼마나 흔드는지 보는 것이다.

지금 메인으로 보는 건 `v2` 데이터셋 기반 실험이고, 별도로 더 공격적인 조합을 돌려보는 `advanced_experiment.py`도 같이 두고 있다.

## 폴더

```text
github-code-review/
├── dataset/
├── scripts/
├── results_v2/
├── results_advanced/
└── README.md
```

- `dataset/`
  실험에 쓰는 코드와 PR 메타데이터 payload가 들어 있다.
- `scripts/`
  실행 스크립트 모음.
- `results_v2/`
  파일 기반 `v2` 실험 결과와 GitHub 수기 기록용 파일.
- `results_advanced/`
  `advanced_experiment.py` 결과.

## dataset 메모

Python 쪽은 현재 아래 조건들을 쓴다.

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

JavaScript 쪽은 아직 여기까지만 정리돼 있다.

- `original`
- `payload_comment`
- `payload_string`
- `payload_varname`
- `payload_pr_title`
- `payload_pr_desc`
- `payload_commit_msg`

## 지금 실제로 쓰는 스크립트

- `scripts/reviewer_v2.py`
  `dataset/` 기반으로 리뷰 생성 + 2차 채점까지 수행한다.
- `scripts/run_all_v2.sh`
  `v2` 전체 배치 실행용. Python, JavaScript 둘 다 순회한다.
- `scripts/analyze_v2.py`
  `results_v2/`를 읽어서 평균 점수, 공격 성공 비율 등을 본다.
- `scripts/advanced_experiment.py`
  파일 기반 데이터셋과는 별도로, 하드코딩된 취약 코드와 공격 조합을 한꺼번에 돌리는 실험용이다.
- `scripts/setup_github_test.sh`
  GitHub PR 실험 세팅용.

## 실행

### v2 실험

```bash
cd scripts
export OPENAI_API_KEY=your_openai_api_key
bash run_all_v2.sh
python analyze_v2.py --results-dir ../results_v2 --csv ../results_v2/full_results.csv
```

없는 payload 디렉토리는 자동으로 스킵한다.

### 고급 조합 실험

```bash
cd scripts
export OPENAI_API_KEY=your_openai_api_key
python advanced_experiment.py --output-dir ../results_advanced
```

### GitHub PR 실험

```bash
cd scripts
bash setup_github_test.sh <GITHUB_USERNAME> <REPO_NAME>
```

## 결과 파일

- `results_v2/github_results_template.csv`
  GitHub 리뷰 결과 수기로 적어두는 템플릿.
- `results_v2/SCORING_GUIDE.md`
  5단계 채점 기준.
- `results_advanced/_results.csv`
  고급 조합 실험 결과 요약 CSV.
- `results_advanced/_full_results.json`
  고급 조합 실험 원본 결과.

## 메모

- 논문 본문에 직접 넣을 메인 결과는 우선 `v2` 기준으로 보는 게 맞다.
- `advanced_experiment.py`는 채널 효과를 더 세게 보기 위한 보조 실험에 가깝다.
- README는 필요한 내용만 적어둔 상태라, 논문 범위가 바뀌면 같이 고치는 편이 편하다.
