from __future__ import division

import random
import time
from pathlib import Path
import os
import sys
import copy

from attackers.base import Problem_Space
from classifiers.base import Classifier
from utils.file_handler import calc_sha256
from utils.utils4makeover import judge_grad


ROOT_DIR = Path(__file__).resolve().parents[3]
MAKEOVER_ROOT = ROOT_DIR / "ThirdParty" / "MakeOver" / "enhanced-binary-randomization"
ORP_ROOT = MAKEOVER_ROOT / "orp"

sys.setrecursionlimit(10_000_000)
if str(MAKEOVER_ROOT) not in sys.path:
    sys.path.append(str(MAKEOVER_ROOT))
if str(ORP_ROOT) not in sys.path:
    sys.path.append(str(ORP_ROOT))

import peLib
import func
import inp
import swap
import reorder
import equiv
import preserv
import disp
import semnops
from randtoolkit import reanalyze_functions, patch


def _ensure_output_dirs() -> Path:
    """
    Ensure MakeOver working directories exist and return the root path.
    """
    root = ROOT_DIR / "output" / "makeover"
    (root / "saved_samples").mkdir(parents=True, exist_ok=True)
    (root / "tmp").mkdir(parents=True, exist_ok=True)
    return root


def _get_score(clsf: Classifier, bytez: bytes, data_hash: str) -> float:
    """
    Unified helper to obtain a detection score from different classifier types.

    Requirements:
    - MalConv-like classifiers: implement `predict_prob` and `extract`
    - Graph-based classifiers (Magic/MalGraph): implement `get_score(bytez, data_hash)`
    """
    # Prefer dedicated get_score(bytez, data_hash) if available and scalar
    if hasattr(clsf, "get_score"):
        try:
            score = clsf.get_score(bytez, data_hash)  # type: ignore[attr-defined]
        except TypeError:
            # Some implementations may not accept data_hash
            score = clsf.get_score(bytez)  # type: ignore[attr-defined]
        # Some historical implementations returned (embed, grad, score)
        if isinstance(score, tuple) and len(score) == 3:
            _, _, score = score
        return float(score)

    # MalConvClsf-style: use predict_prob(extract(bytez))
    if hasattr(clsf, "predict_prob") and hasattr(clsf, "extract"):
        prob = clsf.predict_prob(clsf.extract(bytez))  # type: ignore[attr-defined]
        # Torch tensor or numpy / list
        if hasattr(prob, "item"):
            return float(prob.item())
        if isinstance(prob, (list, tuple)) and prob:
            return float(prob[0])
        return float(prob)

    # Fallback: boolean classifier output -> map to {0.0, 1.0}
    label = clsf(bytez)  # type: ignore[call-arg]
    try:
        label = label.item()
    except AttributeError:
        pass
    return 1.0 if bool(label) else 0.0


def _get_score_with_grad(clsf: Classifier, bytez: bytes, data_hash: str):
    """
    Try to obtain (embed_x, embed_x_grad, score) from classifier.
    If unsupported, raise to let caller fall back to score-only mode.
    """
    # Prefer explicit gradient API if available
    if hasattr(clsf, "get_score_with_grad"):
        return clsf.get_score_with_grad(bytez, data_hash)  # type: ignore[attr-defined]

    # Otherwise, assume no gradient support
    raise RuntimeError("Classifier does not support gradient output")


def attack_for_one_data(data: bytes, clsf: Classifier, n_randomize: int, size_increasement: float):
    """
    Apply MakeOver-style randomization to a single PE sample.

    Returns:
        (sha256, success):
            sha256: sha256 of adversarial sample if attack succeeded,
                    otherwise sha256 of original sample.
            success: True if attack succeeded, False otherwise.
    """
    try:
        return _attack_for_one_data(data, clsf, n_randomize, size_increasement)
    except Exception as e:
        # Fail-safe: treat as attack failure, keep original hash
        print(f"[MakeOver.attack_for_one_data] ERROR: {e}")
        return calc_sha256(data), False


def _attack_for_one_data(data: bytes, clsf: Classifier, n_randomize: int, size_increasement: float):
    start_time = time.time()
    work_root = _ensure_output_dirs()
    saved_root = work_root / "saved_samples"
    tmp_root = work_root / "tmp"

    # Persist original bytes to a temp file so that ThirdParty MakeOver code
    # (which expects file paths) can operate normally.
    data_hash = calc_sha256(data)
    input_path = tmp_root / data_hash
    if not input_path.exists():
        with open(input_path, "wb") as f:
            f.write(data)

    origin_size = os.path.getsize(str(input_path))
    size_increasement_budget = int(origin_size * size_increasement)
    ALLOWED_TRANSFORMS = ["equiv", "swap", "preserv", "reorder", "disp", "semnops"]

    orig_bytez = data

    # Try gradient mode first (for MalConv); fall back to score-only.
    use_grad = False
    try:
        orig_embed_x, orig_embed_x_grad, orig_score = _get_score_with_grad(clsf, orig_bytez, data_hash)
        use_grad = True
    except Exception:
        orig_score = _get_score(clsf, orig_bytez, data_hash)

    # Already benign w.r.t. this classifier
    clsf_threshold = getattr(clsf, "clsf_threshold", 0.5)
    if orig_score < clsf_threshold:
        return data_hash, True

    pe_file, epilog = peLib.read_pe(pe_path=str(input_path), remove_rubbish=False)

    min_score = orig_score
    min_score_bytez = copy.deepcopy(pe_file.__data__[:])
    if use_grad:
        min_embed_x = orig_embed_x
        min_embed_x_grad = orig_embed_x_grad

    # init DispState
    disp_state = disp.DispState(pe_file)
    imagebase = disp_state.peinfo.getImageBase()

    # get_functions is in inp_dump.py, this function reads the bmp.bz2 file to generate addr->function dict
    functions = inp.get_functions(str(input_path))

    levels = func.classify_functions(functions)
    func.analyze_functions(functions, levels)

    # see what happens when randomizing again and again and again...
    disp_iter = 0
    for i_r in range(n_randomize):
        curr_time = time.time()
        if curr_time - start_time > 20 * 60:
            break

        # transform counts (kept for potential debugging / extension)
        transform_counts = [0] * len(ALLOWED_TRANSFORMS)

        for f in filter(lambda x: x.level != -1, functions.itervalues()):
            section = pe_file.get_section_by_rva(f.addr - imagebase)
            if "reloc" not in section.Name:
                orig_f = copy.deepcopy(f)
            else:
                continue

            # skip the SEH prolog and epilog functions .. they cause trouble
            if "_SEH_" in f.name:
                continue

            selected_transform = random.choice(ALLOWED_TRANSFORMS)
            transform_counts[ALLOWED_TRANSFORMS.index(selected_transform)] += 1

            diffs = None

            if selected_transform == "equiv":  # equivs
                diffs, c_b, c_i = equiv.do_equiv_instrs(f, p=0.5)
            elif selected_transform == "swap":  # swaps
                swap.liveness_analysis(f.code)
                live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
                swaps = swap.get_reg_swaps(live_regs)
                diffs, c_b, c_i = swap.do_multiple_swaps(f, swaps, p=0.5)
            elif selected_transform == "preserv":  # preservs
                preservs, avail_regs = preserv.get_reg_preservations(f)
                diffs, c_b, c_i = preserv.do_reg_preservs(f, preservs, avail_regs, p=0.5)
            elif selected_transform == "reorder":  # reorders
                diffs, c_b = reorder.do_random_reordering(f, pe_file)
            elif selected_transform == "disp":  # displacements
                diffs, c_b, c_i = disp.displace_block(f, disp_state)
            elif selected_transform == "semnops":  # semantic nops
                diffs, c_b = semnops.do_semnops(f)
            else:
                raise ValueError(f"Unknown transform type: {selected_transform}")

            if not diffs:
                continue

            # Apply patches
            patch(pe_file, disp_state, diffs)

            filename = os.path.basename(str(input_path))
            output_file = saved_root / (filename.replace(".exe", "") + "_patched")

            if selected_transform == "disp":
                disp_iter += 1
                adj_pe = peLib.AdjustPE(pe_file)
                adj_pe.update_displacement(disp_state, data_hash, size_increasement_budget, disp_iter=disp_iter)
                peLib.write_pe(str(output_file), pe_file, epilog)

                if disp_state.peinfo.getRelocationSize() > 0 and hasattr(disp_state.pe, "DIRECTORY_ENTRY_BASERELOC"):
                    disp._merge_file(str(output_file), data_hash)
            else:
                peLib.write_pe(str(output_file), pe_file, epilog)

            curr_bytez = output_file.read_bytes()
            if use_grad:
                curr_embed_x, curr_embed_x_grad, curr_score = _get_score_with_grad(clsf, curr_bytez, data_hash)
            else:
                curr_score = _get_score(clsf, curr_bytez, data_hash)

            # Successful evasion
            if curr_score < clsf_threshold:
                return calc_sha256(curr_bytez), True

            # Keep best-so-far candidate
            if use_grad:
                # Use gradient-based acceptance criterion
                if judge_grad(min_embed_x, curr_embed_x, min_embed_x_grad):
                    min_score = curr_score
                    min_score_bytez = curr_bytez
                    min_embed_x = curr_embed_x
                    min_embed_x_grad = curr_embed_x_grad
                else:
                    # Reject this modification at function level
                    functions[f.addr] = orig_f
            else:
                # Score-only greedy update
                if curr_score < min_score:
                    min_score = curr_score
                    min_score_bytez = curr_bytez
                else:
                    # Roll back function-level change
                    functions[f.addr] = orig_f

            pe_file, epilog = peLib.read_pe(pe_data=min_score_bytez, remove_rubbish=False)

        # reanalyze functions (if not the last iteration)
        if i_r < n_randomize - 1:
            reanalyze_functions(functions, levels)

    # Attack failed
    return data_hash, False


class MakeOverAttacker(Problem_Space):
    """
    MakeOver white-box style attacker adapted to the unified Problem_Space API.
    """

    def __init__(self, n_randomize: int = 200, size_increasement: float = 0.05, **kwargs):
        super(MakeOverAttacker, self).__init__(**kwargs)
        self.reset()

        self.__name__ = "MakeOver"
        random.seed(23)
        self.n_randomize = n_randomize
        self.size_increasement = size_increasement

    def __call__(self, clsf: Classifier, input_: bytes):
        """
        Args:
            clsf:   Classifier instance (MalConv / Magic / MalGraph wrapper).
            input_: Raw PE bytes.

        Returns:
            (sha256, label):
                sha256: sha256 of adversarial sample if attack succeeded,
                        otherwise sha256 of original sample.
                label:  True if attack succeeded, False otherwise.
        """
        self._attack_begin()
        sha256, label = attack_for_one_data(input_, clsf, self.n_randomize, self.size_increasement)
        self._attack_finish()
        if label:
            self._succeed()
        return sha256, label

