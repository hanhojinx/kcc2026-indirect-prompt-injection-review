# KCC 2026 Code Review Experiment Repo

This repository is for the KCC 2026 paper experiments.

The main topic is how indirect prompt injection affects review quality in LLM-based code review environments.

The main workflow here is the dataset-based `v2` experiment. There is also a separate `advanced_experiment.py` script for more aggressive channel-combination testing.

## Layout

```text
github-code-review/
├── dataset/
├── scripts/
├── results_v2/
├── results_advanced/
└── README.md
```

- `dataset/`
  Code samples and PR metadata payloads used in the experiments.
- `scripts/`
  Execution and analysis scripts.
- `results_v2/`
  Results from the dataset-based `v2` pipeline and manual GitHub review logs.
- `results_advanced/`
  Results from `advanced_experiment.py`.

## Dataset Notes

The Python dataset currently uses these conditions:

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

The JavaScript dataset is currently prepared for these conditions:

- `original`
- `payload_comment`
- `payload_string`
- `payload_varname`
- `payload_pr_title`
- `payload_pr_desc`
- `payload_commit_msg`

## Scripts in Active Use

- `scripts/reviewer_v2.py`
  Runs review generation and second-pass grading over the file-based dataset.
- `scripts/run_all_v2.sh`
  Batch runner for the full `v2` experiment. It walks both Python and JavaScript conditions.
- `scripts/analyze_v2.py`
  Reads `results_v2/` and summarizes average scores and attack success rates.
- `scripts/advanced_experiment.py`
  Runs a separate experiment based on hardcoded vulnerable samples and attack combinations rather than the file-based dataset layout.
- `scripts/setup_github_test.sh`
  Prepares GitHub PR experiments.

## Running Experiments

### v2 dataset-based experiment

```bash
cd scripts
export OPENAI_API_KEY=your_openai_api_key
bash run_all_v2.sh
python analyze_v2.py --results-dir ../results_v2 --csv ../results_v2/full_results.csv
```

Missing payload directories are skipped automatically.

### Advanced combination experiment

```bash
cd scripts
export OPENAI_API_KEY=your_openai_api_key
python advanced_experiment.py --output-dir ../results_advanced
```

### GitHub PR experiment

```bash
cd scripts
bash setup_github_test.sh <GITHUB_USERNAME> <REPO_NAME>
```

## Result Files

- `results_v2/github_results_template.csv`
  Manual template for GitHub review results.
- `results_v2/SCORING_GUIDE.md`
  The 5-level scoring guide.
- `results_advanced/_results.csv`
  Summary CSV for the advanced experiment.
- `results_advanced/_full_results.json`
  Full raw output for the advanced experiment.

## Notes

- The main results for the paper should come from the `v2` pipeline first.
- `advanced_experiment.py` is better treated as a supplementary experiment for channel effects.
- This README is intentionally brief. If the scope of the paper changes, update it together with the dataset and scripts.
