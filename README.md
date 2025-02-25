# LogParserX
A well-performance log parser model for rules generation and parsing task focusing on untagged log information. Specifically for 2025th West Lake Digitalsecurity Conference.

----

### Model

- Qwen-2.5-72B-Instruct (about 148GB): https://huggingface.co/Qwen/Qwen2.5-72B-Instruct/tree/main

- Qwen-2.5-7B-Instruct (about 16GB): https://huggingface.co/Qwen/Qwen2.5-7B-Instruct/tree/main

(1) A little try: deployment for Qwen-2.5-7B for testing

For some easy testing, but actually you should interact through API Key.

(2) API Key Link: 

Official：https://help.aliyun.com/zh/model-studio/billing-for-model-studio

WCode：https://wcode.net/qwen-llm-api

### HandBook

#### 1. Preparation
Install docker and conda environment:
```shell
conda create -n logX python=3.12
conda activate logX
# logX environment
pip install -r requirements.txt
```
#### 2. Run Experiments
A. Manual Mode
For manual regex pattern lib, `faster_tool.py` is re.compile version and `tool.py` is the original version.
And it provides Three Evaluation Modes:
`coverage`(`testing_regex.py`), `match`(`official_testing.py`), `combination`(`new_eval.py`)
For coverage mode, the coverage reprents the percentage of the original logField can be covered by the generated logField.
For match mode, the match represents 40% * one_match_rate + 60% * perfect_match_rate (completely match).
For combination mode, the combination represents 40% * one_match_rate + 60% * perfect_match_rate(coverage = 100%).
```shell
python testing_regex.py # log
python official_testing.py # record
python new_eval.py # new_eval
```

B. LogParserX
Use crewai and qwen-llm-api to generate regex pattern lib instead of manual mode.
Main python files include:


LogParserX output structure:
```shell
LogParserX
├── output
│   ├── gen
│   │   ├── codes
│   │   │   ├── output_0.py
│   │   │   ├── output_1.py
|   │   ├── patterns
|   │   │   ├── patterns_0.md
|   │   │   ├── patterns_1.md
|   │   ├── reports
|   │   │   ├── report_0.md
|   │   │   ├── report_1.md
|   ├── opt
│   │   ├── opt_0.py
│   │   ├── opt_1.py
|   ├── test
|   │   ├── opt_0.py
│   │   ├── opt_1.py
```


 



