# OpenMalAttack

**Open Malware Attack–Defense Evaluation Platform** — A research-oriented platform for quantifying the security and robustness of intelligent code representation learning systems (e.g., PE malware detectors) through reproducible attack–defense experiments.

---

## Overview

This project implements an **attack–defense evaluation framework** for PE malware detection and code representation learning. It provides:

- **Automated preprocessing** for PE malware/goodware datasets
- **Multiple detectors**: MalConv, MalGraph, Magic
- **Black-box attacks**: Random, Gamma, MAB
- **White-box attacks**: ATMPA, Copycat (validated on InceptionV3); MakeOver
- **Unified evaluation** with ASR, FPR/TPR/Acc/AUC, and mean time per sample

Black-box experiments are run against all three detectors; white-box experiments have been validated on InceptionV3.

---

## Detectors and Attackers (Brief)

**Detectors** — Three deep-learning PE detectors at different representation levels:

- **MalConv**: Raw-byte CNN. Inputs PE as a byte sequence; embedding layer + gated 1D convolution + global max pooling → malware probability. End-to-end, no hand-crafted features.
- **MAGIC**: ACFG-based GNN. Extracts intra-function control flow graphs with block-level attributes (e.g. instruction stats); deep graph convolution → graph-level embedding → classification.
- **MalGraph**: Hierarchical graph detector. PE → two-level graph: function-level CFGs (block execution logic) + call graph (function interactions). GraphSAGE on both levels, then pooling/aggregation → program embedding → classifier.

**Attackers** — Adversarial modifications that preserve functionality to evade detectors.

- **Black-box (no model internals):**  
  **Random** — Baseline: random PE-valid edits (e.g. padding, new sections, header fields) until evasion.  
  **GAMMA** — Genetic algorithm: gene pool from benign sections; selection, crossover, mutation to minimize detection score and payload size.  
  **MAB** — Multi-armed bandit RL: actions = PE edits; reward = drop in detection score; learns an effective edit sequence.
- **White-box (full model access, for image-based detectors e.g. InceptionV3):**  
  **ATMPA** — PE → texture image; FGSM in image space to add adversarial perturbation.  
  **COPYCAT** — Adversarial image patch injected/appended into PE; original code unchanged, execution preserved.  
  **MakeOver** — Function-preserving code transforms (equivalent instruction swap, register reassign, reorder); optimizes transformation choice for evasion.

---

## Core Features

- **Data preprocessing**: PE dataset loading, optional ACFG extraction (IDA + scripts), paths configurable via scripts and config files
- **Detectors**: MalConv (raw bytes), MalGraph (ACFG + hierarchical graph), Magic (ACFG), InceptionV3 (image-based)
- **Attack–defense pairing**: Combine any supported attacker with any classifier via a single evaluator interface (`Evaler` or `RLEvaler`)
- **Metrics**: ASR (Attack Success Rate), mean time per sample; detector thresholds at 100 FPR / 1000 FPR
- **Configurable paths**: Model weights, IDA path, script path, dataset directories, and JSON configs

---

## System Architecture

**Workflow:**

1. **Data**: Place PE samples in `dataset/malware/` and `dataset/goodware/` (or use `dataset/mal_train/`, `dataset/mal_test/` for split). For MalGraph/Magic, run preprocessing to generate ACFG (IDA Pro + `scripts/graph_handle_acfg.py`).
2. **Models**: Load detector weights from paths defined in each classifier (e.g. `classifiers/malconv/`, `classifiers/malgraph/`). Place pre-trained weights in the expected paths.
3. **Evaluation**: Run a main script (e.g. `main_random_malconv.py`) which builds attacker + classifier and invokes `Evaler(attacker=..., clsf=...)()` or `RLEvaler(...)()`.

**Module layout:**

| Layer        | Contents |
|-------------|----------|
| **Data**    | `dataset/` (malware, goodware, tmp, mal_train, mal_test), `configs/` (YAML, JSON, vocab) |
| **Classifiers** | `classifiers/` — MalConv, MalGraph, Magic, InceptionV3 |
| **Attackers**  | `attackers/BAttacks/` — Random, Gamma, MAB; `attackers/WAttacks/` — ATMPA, Copycat, MakeOver |
| **Evaluation** | `attack_evals/base.py` — `Evaler`, `RLEvaler`; entry scripts `main_<attack>_<detector>.py` |
| **Preprocessing** | `preprocess.py`, `preprocess_singlepro.py`, `scripts/` (graph_handle_acfg, processing_by_ida, etc.) |
| **Third-party** | `ThirdParty/MAB/`, `ThirdParty/MakeOver/`, `ThirdParty/CW/`, `ThirdParty/FGSM/`, etc. |

MalGraph/Magic rely on IDA Pro and `scripts/graph_handle_acfg.py` for ACFG; set `IDA_PATH` and `SCRIPT_PATH` in the scripts you use. MAB uses `utils/file_handler.get_rl_dataset()` and config/JSON for train/test split (e.g. `configs/MAB.ini`, `configs/malware_le_3000blocks.json`).

---

## Quick Start

### 1. Environment

- **Python**: 3.8+
- **GPU**: CUDA recommended for detectors (PyTorch)
- **Optional**: IDA Pro for ACFG-based detectors (MalGraph, Magic); see [Optional: IDA Pro setup](#optional-ida-pro-setup-linux) below for manual setup on Linux.

### 2. Install dependencies

From the project root:

```bash
pip install -r requirements.txt
```

### 3. Optional: IDA Pro setup (Linux)

Only needed if you use **MalGraph** or **Magic** (ACFG extraction). Install [IDA Pro](https://hex-rays.com/IDA-pro/) and its dependencies on Linux as follows.

**VNC server (for IDA GUI on headless machines):**

```bash
sudo apt-get update
sudo apt-get install gnome-core vnc4server
vncserver
export DISPLAY=localhost:1
xhost +
```

**IDA Pro system dependencies (i386 libs):**

```bash
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install -y libc6:i386 libexpat1:i386 libfontconfig1:i386 libfreetype6:i386 libgcc1:i386 libglib2.0-0:i386 libice6:i386 libpcre3:i386 libsm6:i386 libuuid1:i386 libx11-6:i386 libxau6:i386 libxcb1:i386 libxdmcp6:i386 libxext6:i386 libxrender1:i386 zlib1g:i386 libx11-xcb1:i386 libdbus-1-3:i386 libxi6:i386 libstdc++6:i386
sudo apt install -y openssl wget
```

Then install IDA Pro from the vendor (Hex-Rays) and place `idaq64` (or your IDA executable) in a path you will set as `IDA_PATH` in the preprocessing scripts.

**Miniconda and IDA Python 2.7 packages (for scripts run inside IDA):**

```bash
wget https://mirrors.tuna.tsinghua.edu.cn/anaconda/miniconda/Miniconda3-py38_4.8.3-Linux-x86_64.sh --no-check-certificate
bash Miniconda3-py38_4.8.3-Linux-x86_64.sh

conda create -n py2 python=2.7
conda activate py2
pip install setuptools==40.0.0 networkx==1.5 jsonlines --target="path/to/IDA/python/lib/python2.7"
```

Replace `path/to/IDA` with your IDA Pro installation directory (e.g. the folder containing `python/lib/python2.7`). This lets IDA run scripts that use `networkx` and `jsonlines` for ACFG extraction.

### 4. Project layout

Ensure the following exist (create empty dirs if needed):

- `dataset/malware/` — PE malware samples (filenames without extension or SHA256)
- `dataset/goodware/` — Benign PE samples
- `models/` or paths expected by classifiers
- `configs/` — YAML/JSON configs

### 5. Models

Place pre-trained weights where each classifier expects them (paths are set inside each classifier’s `__init__` or config):

- **MalConv**: e.g. `classifiers/malconv/` or path in `configuration.model_file`
- **MalGraph**: model and vocab paths in `classifiers/malgraph/__init__.py`
- **Magic**: model path in `classifiers/magic/__init__.py`
- **InceptionV3**: see `classifiers/inceptionV3/__init__.py`

### 6. Run a demo

From project root, run an attack–defense pair. Example: **Random vs MalConv**

```bash
python main_random_malconv.py
```

Other examples:

- Black-box: `main_random_malgraph.py`, `main_random_magic.py`, `main_gamma_malconv.py`, `main_gamma_malgraph.py`, `main_gamma_magic.py`, `main_mab_malconv.py`, `main_mab_malgraph.py`, `main_mab_magic.py`
- White-box (InceptionV3): `main_atmpa_inceptionV3.py`, `main_copycat_inceptionV3.py`
- MakeOver: `main_makeover_malconv.py` (requires running `deploy.py` and obtaining `bmp.bz2` first; see [Attack-specific prerequisites](#attack-specific-prerequisites))

**Note:** MAB requires running `process_benign_dataset.py` first to generate benign section content; MakeOver requires running `deploy.py` (Docker) and preprocessing test files to get `bmp.bz2` before attacking. See [Attack-specific prerequisites](#attack-specific-prerequisites) for details.

Evasive samples are written to `output/evasive/` by default. ASR and mean time are printed to the console.

---

## Detailed Usage

### Data preprocessing

- **MalConv**: Only raw bytes are needed. Put PE files in `dataset/malware/` and `dataset/goodware/`.
- **MalGraph / Magic**: Use preprocessing that produces ACFG (IDA Pro + `scripts/graph_handle_acfg.py`). Run from project root. Optional: `preprocess.py` or `preprocess_singlepro.py` for batch ACFG; set `IDA_PATH` and `SCRIPT_PATH` in the script or environment.
- **MAB (RL)**: Provide JSONs for train/test split (e.g. `configs/malware_le_3000blocks.json`, `configs/malware_preprocessed_train.json`, `configs/malware_preprocessed_test.json`). Point the MAB code to these files via `configs/MAB.ini` or the paths used in `utils/file_handler.get_rl_dataset()`.

Config files under `configs/` (e.g. `attack_mal.yaml`) may contain absolute paths from the original environment; replace them with your own paths where needed.

### Attack-specific prerequisites

- **MAB:** Before running MAB attacks, you must run `process_benign_dataset.py` to extract benign PE section content into `benign_section_content` (or the path configured for the MAB pipeline). This step is required for the MAB rewriter to use benign sections. Run from the project root or the path where the script expects benign PE files.
- **MakeOver:** Before running MakeOver attacks, (1) run `deploy.py` to start the Docker-based preprocessing service, (2) process your test PE files through that service to obtain `bmp.bz2` (or equivalent) outputs, then (3) run the attack (e.g. `main_makeover_malconv.py`) using those processed files. MakeOver relies on the official [enhanced-binary-diversification](https://github.com/pwwl/enhanced-binary-diversification) workflow; see that repo for Docker and deployment details.

### Adding a new attack method

1. Implement an attacker that satisfies the interface used by `attack_evals.base.Evaler` (or `RLEvaler` for RL):
   - **Evaler**: callable `(clsf, data) -> (sha256, label)`; optional `_ASR()`, `_Mean_Time()`.
   - **RLEvaler**: implement the RL attacker interface (e.g. gym env) and pass it to `RLEvaler`.
2. Register or import the attacker in `attackers/` (e.g. under `BAttacks` or `WAttacks`) and in `attackers/__init__.py`.
3. Add a small entry script (e.g. `main_<newattack>_malconv.py`) that builds the attacker and classifier and calls `Evaler(attacker=..., clsf=...)()` or `RLEvaler(...)()`.

### Adding a new detector

1. Implement a classifier that matches the interface expected by the evaluator (e.g. `__call__(self, bytez)` or `(bytez, data_hash)` returning a label or score). See `classifiers/base.py` and existing classifiers in `classifiers/malconv/`, `classifiers/malgraph/`, etc.
2. Place it under `classifiers/` and load model weights from paths you define (or kwargs).
3. In entry scripts, instantiate your classifier and pass it to `Evaler(attacker=..., clsf=...)` or `RLEvaler(...)`.

### Evaluation framework (attack–defense pairs)

Use the same pattern as the existing `main_*.py` scripts:

```python
from attack_evals.base import Evaler
from attackers import GammaAttacker   # or RandomAttacker, MABAttacker, ATMPA_Attacker, ...
from classifiers import MalConv      # or MalGraph, Magic, InceptionV3

attacker = GammaAttacker()
clsf = MalConv()
evaler = Evaler(attacker=attacker, clsf=clsf)
evaler()  # uses dataset from dataset.malware_data by default
```

For RL (MAB), use `RLEvaler`. You can pass a custom dataset and (for MalFox-style attacks) `change_input=1` where applicable. Evasive samples are written by the attacker to the configured output directory.

### Metrics

**Attack evaluation**

- **ASR (Attack Success Rate)**: Fraction of malware samples that successfully evade the detector after the attack.
- **Mean time**: Average time per sample for the attack (reported by the attacker’s `_Mean_Time()`).

**Detector evaluation** (e.g. on malware + goodware test sets)

- **FPR (False Positive Rate)**: FP / (FP + TN); rate of benign samples wrongly classified as malware.
- **TPR (True Positive Rate)**: TP / (TP + FN); detection rate on malware.
- **TNR (True Negative Rate)**: TN / (TN + FP); correct rejection rate on benign.
- **Acc (Accuracy)**: (TP + TN) / total.
- **BAcc (Balanced Accuracy)**: (TPR + TNR) / 2; suitable for imbalanced data.
- **AUC**: Area under the ROC curve (detector ranking quality).

Detectors use decision thresholds at a fixed FPR (e.g. 100 FPR or 1000 FPR); see `get_threshold.py` and each classifier’s `threshold_type`. For a full example of computing FPR, TPR, Acc, BAcc, and AUC from a confusion matrix, see `test_malgraph.py`.

---

## Configuration

Paths and options are spread across:

- **Classifiers**: Each classifier’s `__init__.py` or a small config class (e.g. `configuration` in `classifiers/malconv/__init__.py`) for model path, device, threshold type.
- **Preprocessing**: `IDA_PATH`, `SCRIPT_PATH`, `tmp_sample_root` in `preprocess.py` / `preprocess_singlepro.py` and related scripts.
- **Attack/config**: `configs/attack_mal.yaml`, `configs/MAB.ini`, and JSON files under `configs/` for vocab, split, and attack parameters.

Adjust these to your environment (especially IDA path and dataset paths) when using ACFG-based pipelines or MAB.

---

## Third-Party Code and Licenses

This project includes or adapts code from the following:

| Component        | Source / Repo                          | License     | Location        |
|------------------|----------------------------------------|-------------|-----------------|
| Malware Makeover | [pwwl/enhanced-binary-diversification](https://github.com/pwwl/enhanced-binary-diversification) | MIT         | `ThirdParty/MakeOver/` |
| MAB-malware      | [weisong-ucr/MAB-malware](https://github.com/weisong-ucr/MAB-malware) | MIT         | `ThirdParty/MAB/`  |
| nn_robust_attacks| [carlini/nn_robust_attacks](https://github.com/carlini/nn_robust_attacks) | BSD-2-Clause| `ThirdParty/CW/`   |
| MalGraph (reference) | [ryderling/MalGraph](https://github.com/ryderling/MalGraph) | MIT         | reference / `classifiers/malgraph/` |

When using or redistributing this project, you must comply with this repository’s **MIT** license and **retain all third-party copyright and license notices** (e.g. in `ThirdParty/` and in any redistributed code). Third-party LICENSE files are placed under `ThirdParty/MakeOver/LICENSE`, `ThirdParty/MAB/LICENSE`, and `ThirdParty/CW/LICENSE`. See [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for details and a compliance checklist.

---

## Citation

If you find this repository helpful for your research, please cite as follows:

```bibtex
@misc{openmalattack,
	title        = {OpenMalAttack: Open Malware Attack-Defense Evaluation Platform},
	author       = {Ling, Xiang},
	howpublished = {\url{https://github.com/tobbykun/OpenMalAttack}}
}
```

## References

This platform builds upon or reproduces the following detectors and attacks. Please cite the relevant work when you use them.

**Detectors**

- **Magic:** Yan J, Yan G, Jin D. Classifying malware represented as control flow graphs using deep graph convolutional neural network. *DSN*, 2019: 52-63. [IEEE](https://ieeexplore.ieee.org/document/8809504)
- **MalConv:** Raff E, Barker J, Sylvester J, et al. Malware detection by eating a whole exe. *arXiv preprint arXiv:1710.09435*, 2017.
- **MalGraph:** Ling X, Wu L, Deng W, et al. Malgraph: Hierarchical graph neural networks for robust windows malware detection. *IEEE INFOCOM*, 2022: 1998-2007. [IEEE](https://ieeexplore.ieee.org/abstract/document/9796786) | [GitHub](https://github.com/ryderling/MalGraph)

**Black-box attacks**

- **Gamma:** Demetrio L, Biggio B, Lagorio G, et al. Functionality-preserving black-box optimization of adversarial windows malware. *IEEE TIFS*, 2021, 16: 3469-3478. [IEEE](https://ieeexplore.ieee.org/abstract/document/9437194)
- **MAB:** Song W, Li X, Afroz S, et al. Mab-malware: A reinforcement learning framework for attacking static malware classifiers. *arXiv preprint arXiv:2003.03100*, 2020. [GitHub](https://github.com/weisong-ucr/MAB-malware)

**White-box attacks**

- **ATMPA:** Liu X, Zhang J, Lin Y, et al. ATMPA: attacking machine learning-based malware visualization detection methods via adversarial examples. *IWQoS*, 2019: 1-10. [ACM](https://dl.acm.org/doi/abs/10.1145/3326285.3329073)
- **Copycat:** Khormali A, Abusnaina A, Chen S, et al. Copycat: practical adversarial attacks on visualization-based malware detection. *arXiv preprint arXiv:1909.09735*, 2019. [arXiv](https://arxiv.org/pdf/1909.09735)
- **MakeOver:** Lucas K, Sharif M, Bauer L, et al. Malware makeover: Breaking ml-based static analysis by modifying executable bytes. *ACM Asia CCS*, 2021: 744-758. [ACM](https://dl.acm.org/doi/pdf/10.1145/3433210.3453086) | [GitHub](https://github.com/pwwl/enhanced-binary-diversification)

**BibTeX (for References)**

```bibtex
@inproceedings{yan2019classifying,
	title        = {Classifying malware represented as control flow graphs using deep graph convolutional neural network},
	author       = {Yan, Jian and Yan, Guixin and Jin, Dong},
	booktitle    = {2019 49th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN)},
	year         = {2019},
	pages        = {52--63},
	organization = {IEEE}
}

@misc{raff2017malware,
	title        = {Malware Detection by Eating a Whole EXE},
	author       = {Edward Raff and Jon Barker and Jared Sylvester and Robert Brandon and Bryan Catanzaro and Charles Nicholas},
	year         = {2017},
	eprint       = {1710.09435},
	archiveprefix= {arXiv},
	primaryclass = {stat.ML}
}

@inproceedings{ling2022malgraph,
	title        = {MalGraph: Hierarchical graph neural networks for robust Windows malware detection},
	author       = {Ling, Xiang and Wu, Lei and Deng, Weibin and others},
	booktitle    = {IEEE INFOCOM 2022},
	year         = {2022},
	pages        = {1998--2007},
	organization = {IEEE}
}

@article{demetrio2021functionality,
	title        = {Functionality-preserving black-box optimization of adversarial Windows malware},
	author       = {Demetrio, Luca and Biggio, Battista and Lagorio, Giovanni and Roli, Fabio and Armando, Alessandro},
	journal      = {IEEE Transactions on Information Forensics and Security},
	year         = {2021},
	volume       = {16},
	pages        = {3469--3478},
	publisher    = {IEEE}
}

@misc{song2020mab,
	title        = {MAB-Malware: A reinforcement learning framework for attacking static malware classifiers},
	author       = {Song, Wei and Li, Xiu and Afroz, Sadia and others},
	year         = {2020},
	eprint       = {2003.03100},
	archiveprefix= {arXiv}
}

@inproceedings{liu2019atmpa,
	title        = {ATMPA: attacking machine learning-based malware visualization detection methods via adversarial examples},
	author       = {Liu, Xiaolei and Zhang, Jianwen and Lin, Yinzhi and others},
	booktitle    = {Proceedings of the International Symposium on Quality of Service},
	year         = {2019},
	pages        = {1--10}
}

@misc{khormali2019copycat,
	title        = {Copycat: Practical adversarial attacks on visualization-based malware detection},
	author       = {Khormali, Ammar and Abusnaina, Ahmed and Chen, Songqing and others},
	year         = {2019},
	eprint       = {1909.09735},
	archiveprefix= {arXiv}
}

@inproceedings{lucas2021makeover,
	title        = {Malware makeover: Breaking ML-based static analysis by modifying executable bytes},
	author       = {Lucas, Keane and Sharif, Mahmood and Bauer, Lujo and others},
	booktitle    = {Proceedings of the 2021 ACM Asia Conference on Computer and Communications Security},
	year         = {2021},
	pages        = {744--758}
}
```

---

## Disclaimer

**This project is for security research and education only.**

- The provided code and models are intended **only** for: (1) researching the robustness of malware detection and code representation learning, and (2) educational use in controlled environments.
- **Do not use** this software to develop, deploy, or distribute malware or to evade security products in unauthorized or illegal ways.
- You are solely responsible for ensuring that your use complies with all applicable laws and with the policies of any networks or systems you test.
- The authors and contributors disclaim any liability for misuse or damage arising from the use of this software.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file in the repository root.

Third-party notices and license files are listed in [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
