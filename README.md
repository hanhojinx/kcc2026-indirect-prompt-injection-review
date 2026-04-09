# Indirect Prompt Injection in LLM-Based Code Review

This repository contains the experiment code and result artifacts for the paper:

*Indirect Prompt Injection in LLM-Based Code Review: A Channel-Separated Empirical Analysis of PR Metadata Attacks*

The project studies how pull request metadata and code-adjacent text can degrade review quality in LLM-based review settings. The repository keeps two experiment tracks:

- A dataset-driven benchmark under `dataset/` and `scripts/reviewer_v2.py`
- A synthetic channel-combination benchmark under `scripts/advanced_experiment.py`

## Repository Layout

```text
github-code-review/
├── cases/
├── dataset/
├── results_advanced/
├── results_v2/
├── scripts/
└── README.md
```

- `dataset/` stores the Python and JavaScript review cases plus PR metadata payload files.
- `scripts/` stores the active runners, analyzers, and GitHub automation helpers.
- `results_v2/` stores dataset-based experiment outputs and manual GitHub review scoring sheets.
- `results_advanced/` stores outputs from the advanced channel-separated benchmark.
- `cases/` stores extra case material kept alongside the main dataset.

## Active Scripts

- `scripts/reviewer_v2.py`
  Runs the dataset-based review pipeline and second-pass grading.
- `scripts/run_all_v2.sh`
  Batch runner for the dataset benchmark across Python and JavaScript conditions.
- `scripts/analyze_v2.py`
  Summarizes `results_v2/` into paper-ready score tables and CSV exports.
- `scripts/advanced_experiment.py`
  Runs the channel-separated PR metadata benchmark on hardcoded vulnerable samples.
- `scripts/setup_github_test.sh`
  Creates GitHub branches and pull requests for external review-tool experiments.

## Running the Dataset Benchmark

```bash
cd scripts
export OPENAI_API_KEY=your_openai_api_key
bash run_all_v2.sh
python analyze_v2.py --results-dir ../results_v2 --csv ../results_v2/full_results.csv
```

The batch runner skips missing directories automatically, so incomplete language-condition pairs do not stop the run.

## Running the Advanced Benchmark

```bash
cd scripts
export OPENAI_API_KEY=your_openai_api_key
python advanced_experiment.py --output-dir ../results_advanced
```

Optional filters:

```bash
python advanced_experiment.py --vulns sqli_basic xss_basic --techniques none role_hijack
```

## Running the GitHub PR Setup

```bash
cd scripts
bash setup_github_test.sh <GITHUB_USERNAME> <REPO_NAME>
```

This creates PR branches from the dataset cases so external review tools such as CodeRabbit can be evaluated with the same scoring guide used in the paper.

## Result Files

- `results_v2/SCORING_GUIDE.md`
  Five-level review-quality scoring guide used across tools.
- `results_v2/github_results_template.csv`
  Manual scoring sheet for GitHub-based review experiments.
- `results_advanced/_full_results.json`
  Full JSON output from the advanced benchmark.
- `results_advanced/_results.csv`
  Flattened CSV export from the advanced benchmark.

## Notes

- The dataset benchmark is the main line for the paper.
- The advanced benchmark is meant to isolate channel effects and attack combinations more aggressively.
- If the experiment design changes, update the dataset, scripts, and result templates together so the repository stays internally consistent.
