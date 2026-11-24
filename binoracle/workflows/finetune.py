"""Fine-tuning pipeline for exploit hypothesis generation.

Builds a training dataset from binoracle session store (CVE investigations)
and generates JSONL files + a LoRA training script for a small local model
(Qwen-2.5-Coder-7B, Mistral-7B, or any HuggingFace causal-LM).

Pipeline:
  1. Export CVE investigations from the session store as instruction pairs:
       system: "You are an exploit hypothesis generator..."
       user:   "CVE-XXXX-YYYY: <NVD description>"
       assistant: "<verified hypothesis / attack path>"
  2. Write train.jsonl and val.jsonl (90/10 split, shuffled)
  3. Generate a LoRA fine-tuning script (run_lora.py) using PEFT + transformers
  4. Optionally kick off training if the user passes --run

No model weights are shipped with binoracle; the training script pulls the
base model from HuggingFace Hub on first run (requires HUGGINGFACE_TOKEN env
var or public model).

SOLO USO AUTORIZADO — el modelo resultante solo debe usarse contra targets
propios o con autorización escrita.
"""
from __future__ import annotations

import json
import os
import random
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TrainingExample:
    cve_id: str
    description: str
    hypothesis: str
    verified: bool = False
    vuln_class: str = ""
    cvss_score: Optional[float] = None


@dataclass
class FinetuneDataset:
    model_id: str
    train: List[TrainingExample] = field(default_factory=list)
    val: List[TrainingExample] = field(default_factory=list)
    train_path: str = ""
    val_path: str = ""
    script_path: str = ""
    note: str = ""
    ok: bool = False


# ---------------------------------------------------------------------------
# Dataset extraction from session store
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are an expert offensive security researcher. "
    "Given a CVE identifier and its NVD description, generate a detailed exploit "
    "hypothesis: the vulnerability class, the attack vector, a proof-of-concept "
    "outline, and the likely impact. "
    "Be specific, technical and accurate. "
    "AUTHORIZED USE ONLY — for authorized pentesting, CTF, and security research."
)


def _example_to_jsonl(ex: TrainingExample) -> dict:
    """Convert a TrainingExample to a ChatML-style JSONL record."""
    user_text = f"{ex.cve_id}: {ex.description}"
    if ex.vuln_class:
        user_text += f"\nVulnerability class: {ex.vuln_class}"
    if ex.cvss_score is not None:
        user_text += f"\nCVSS score: {ex.cvss_score}"
    return {
        "messages": [
            {"role": "system",  "content": _SYSTEM_PROMPT},
            {"role": "user",    "content": user_text},
            {"role": "assistant", "content": ex.hypothesis},
        ],
        "metadata": {
            "cve_id": ex.cve_id,
            "verified": ex.verified,
            "vuln_class": ex.vuln_class,
        },
    }


def extract_from_store(store) -> List[TrainingExample]:
    """Extract CVE investigation records from a binoracle session store."""
    examples: List[TrainingExample] = []
    if store is None:
        return examples
    try:
        # binoracle session store: list_cve_investigations() returns CVEInvestigation objects
        investigations = store.list_cve_investigations() if hasattr(store, "list_cve_investigations") else []
        for inv in investigations:
            if not (getattr(inv, "description", "") and getattr(inv, "hypothesis", "")):
                continue
            ex = TrainingExample(
                cve_id=inv.cve_id,
                description=inv.description or "",
                hypothesis=inv.hypothesis or "",
                verified=getattr(inv, "verified", False),
                vuln_class=getattr(inv, "vuln_class", "") or "",
                cvss_score=getattr(inv, "cvss_score", None),
            )
            examples.append(ex)
    except Exception:
        pass
    return examples


def extract_from_jsonl_dir(reports_dir: str) -> List[TrainingExample]:
    """Extract from binoracle JSON report files in a directory."""
    examples: List[TrainingExample] = []
    base = Path(reports_dir)
    for p in base.rglob("*.json"):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            cve_id = d.get("cve_id") or d.get("id") or ""
            if not cve_id or not cve_id.upper().startswith("CVE-"):
                continue
            # Binoracle investigation report format: description comes from NVD (not stored
            # in the JSON — but we can reconstruct a minimal one from known fields)
            description = (d.get("description") or d.get("summary") or
                           d.get("nvd_description") or "")
            if not description:
                # reconstruct from fields
                parts = []
                if d.get("vuln_class"):
                    parts.append(f"Vulnerability class: {d['vuln_class']}")
                if d.get("plugin"):
                    parts.append(f"Plugin: {d['plugin']}")
                if d.get("endpoint"):
                    parts.append(f"Endpoint: {d['endpoint']}")
                if d.get("sqli_context"):
                    parts.append(f"SQLi context: {d['sqli_context']}")
                description = ". ".join(parts)
            # hypothesis / attack path
            hypothesis = (d.get("hypothesis") or d.get("attack_path")
                          or d.get("verified_detail") or d.get("findings") or "")
            if isinstance(hypothesis, list):
                hypothesis = "\n".join(str(h) for h in hypothesis)
            if not (description and hypothesis):
                continue
            ex = TrainingExample(
                cve_id=cve_id,
                description=str(description)[:2048],
                hypothesis=str(hypothesis)[:4096],
                verified=bool(d.get("verified", False)),
                vuln_class=str(d.get("vuln_class") or ""),
                cvss_score=d.get("cvss_score"),
            )
            examples.append(ex)
        except Exception:
            pass
    return examples


# ---------------------------------------------------------------------------
# LoRA training script generator
# ---------------------------------------------------------------------------

def _make_lora_script(model_id: str, train_path: str, val_path: str,
                      out_dir: str) -> str:
    """Generate a self-contained LoRA fine-tuning script."""
    return textwrap.dedent(f"""\
    #!/usr/bin/env python3
    # LoRA fine-tuning script — generated by binoracle
    # Base model: {model_id}
    # SOLO USO AUTORIZADO
    #
    # Requirements:
    #   pip install transformers peft datasets accelerate bitsandbytes trl
    #
    # Run:
    #   python run_lora.py
    #   # or with 4-bit quantization (requires bitsandbytes):
    #   python run_lora.py --load_in_4bit

    import argparse, json, os
    from pathlib import Path
    from datasets import Dataset
    from transformers import (AutoTokenizer, AutoModelForCausalLM,
                               TrainingArguments, BitsAndBytesConfig)
    from peft import LoraConfig, get_peft_model, TaskType
    from trl import SFTTrainer

    MODEL_ID   = "{model_id}"
    TRAIN_FILE = "{train_path}"
    VAL_FILE   = "{val_path}"
    OUTPUT_DIR = "{out_dir}/lora_output"

    def load_jsonl(path):
        rows = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return rows

    def messages_to_text(row, tokenizer):
        # Apply chat template if available, else manual ChatML
        if hasattr(tokenizer, "apply_chat_template"):
            return tokenizer.apply_chat_template(
                row["messages"], tokenize=False, add_generation_prompt=False)
        parts = []
        for m in row["messages"]:
            parts.append(f"<|im_start|>{{m['role']}}\\n{{m['content']}}<|im_end|>")
        return "\\n".join(parts)

    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--load_in_4bit", action="store_true")
        parser.add_argument("--epochs",   type=int,   default=3)
        parser.add_argument("--lr",       type=float, default=2e-4)
        parser.add_argument("--max_seq",  type=int,   default=2048)
        parser.add_argument("--batch",    type=int,   default=2)
        args = parser.parse_args()

        bnb_config = None
        if args.load_in_4bit:
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True, bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype="bfloat16", bnb_4bit_use_double_quant=True)

        print(f"Loading tokenizer: {{MODEL_ID}}")
        tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        print(f"Loading model: {{MODEL_ID}}")
        model = AutoModelForCausalLM.from_pretrained(
            MODEL_ID,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )

        lora_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=16, lora_alpha=32, lora_dropout=0.05,
            target_modules=["q_proj", "v_proj", "k_proj", "o_proj",
                            "gate_proj", "up_proj", "down_proj"],
            bias="none",
        )
        model = get_peft_model(model, lora_config)
        model.print_trainable_parameters()

        train_rows = load_jsonl(TRAIN_FILE)
        val_rows   = load_jsonl(VAL_FILE)

        def to_text(row):
            return {{"text": messages_to_text(row, tokenizer)}}

        train_ds = Dataset.from_list([to_text(r) for r in train_rows])
        val_ds   = Dataset.from_list([to_text(r) for r in val_rows])

        training_args = TrainingArguments(
            output_dir=OUTPUT_DIR,
            num_train_epochs=args.epochs,
            per_device_train_batch_size=args.batch,
            per_device_eval_batch_size=args.batch,
            gradient_accumulation_steps=4,
            learning_rate=args.lr,
            fp16=True,
            logging_steps=10,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            report_to="none",
        )

        trainer = SFTTrainer(
            model=model,
            tokenizer=tokenizer,
            args=training_args,
            train_dataset=train_ds,
            eval_dataset=val_ds,
            dataset_text_field="text",
            max_seq_length=args.max_seq,
        )
        trainer.train()
        model.save_pretrained(OUTPUT_DIR)
        tokenizer.save_pretrained(OUTPUT_DIR)
        print(f"[+] LoRA adapter saved to {{OUTPUT_DIR}}")
        print("    Load with: AutoModelForCausalLM.from_pretrained(base) + PeftModel.from_pretrained(adapter)")

    if __name__ == "__main__":
        main()
    """)


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_finetune_dataset(
    store=None,
    reports_dir: str = "",
    extra_examples: Optional[List[TrainingExample]] = None,
    model_id: str = "Qwen/Qwen2.5-Coder-7B-Instruct",
    out_dir: str = ".",
    val_ratio: float = 0.1,
    seed: int = 42,
) -> FinetuneDataset:
    """Build a fine-tuning dataset from binoracle investigations.

    Args:
        store:           binoracle session store (optional)
        reports_dir:     directory of binoracle JSON report files (optional)
        extra_examples:  additional manually-crafted examples (optional)
        model_id:        HuggingFace model ID for the LoRA script
        out_dir:         output directory for train.jsonl, val.jsonl, run_lora.py
        val_ratio:       fraction of data to use for validation (default 0.1)
        seed:            random seed for reproducible shuffling

    Returns:
        FinetuneDataset with paths to generated files.
    """
    dataset = FinetuneDataset(model_id=model_id)
    examples: List[TrainingExample] = []

    if store:
        examples += extract_from_store(store)
    if reports_dir and Path(reports_dir).exists():
        examples += extract_from_jsonl_dir(reports_dir)
    if extra_examples:
        examples += extra_examples

    # Deduplicate by CVE ID
    seen: set = set()
    unique: List[TrainingExample] = []
    for ex in examples:
        if ex.cve_id not in seen and ex.description and ex.hypothesis:
            seen.add(ex.cve_id)
            unique.append(ex)

    if not unique:
        dataset.note = (
            "No training examples found. Run some CVE investigations first "
            "(binoracle investigate / cve commands), then re-run finetune."
        )
        return dataset

    rng = random.Random(seed)
    rng.shuffle(unique)
    split = max(1, int(len(unique) * (1 - val_ratio)))
    dataset.train = unique[:split]
    dataset.val = unique[split:] or unique[:1]  # at least 1 val example

    # Write JSONL files
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    train_path = str(out / "train.jsonl")
    val_path   = str(out / "val.jsonl")
    with open(train_path, "w", encoding="utf-8") as f:
        for ex in dataset.train:
            f.write(json.dumps(_example_to_jsonl(ex), ensure_ascii=False) + "\n")
    with open(val_path, "w", encoding="utf-8") as f:
        for ex in dataset.val:
            f.write(json.dumps(_example_to_jsonl(ex), ensure_ascii=False) + "\n")

    script = _make_lora_script(model_id, train_path, val_path, out_dir)
    script_path = str(out / "run_lora.py")
    Path(script_path).write_text(script, encoding="utf-8")
    os.chmod(script_path, 0o755)

    dataset.train_path  = train_path
    dataset.val_path    = val_path
    dataset.script_path = script_path
    dataset.ok = True
    dataset.note = (
        f"{len(unique)} unique CVE examples "
        f"({len(dataset.train)} train / {len(dataset.val)} val)."
    )
    return dataset


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

def render_finetune(ds: FinetuneDataset) -> str:
    out = ["## Fine-tuning dataset — exploit hypothesis generation\n"]
    out.append(f"**Base model:** `{ds.model_id}`")
    out.append(f"**Status:** {'✅ dataset ready' if ds.ok else '❌ ' + ds.note}\n")

    if not ds.ok:
        out.append(f"_{ds.note}_")
        return "\n".join(out)

    out.append(f"**Examples:** {len(ds.train) + len(ds.val)} total "
               f"({len(ds.train)} train / {len(ds.val)} val)")
    out.append(f"**Train:** `{ds.train_path}`")
    out.append(f"**Val:**   `{ds.val_path}`")
    out.append(f"**Script:** `{ds.script_path}`\n")

    if ds.train:
        out.append("### Sample training examples\n")
        out.append("| CVE | Verified | Class | Description (truncated) |")
        out.append("|-----|:--------:|-------|------------------------|")
        for ex in ds.train[:8]:
            vf = "✅" if ex.verified else "—"
            desc = (ex.description[:60] + "…") if len(ex.description) > 60 else ex.description
            out.append(f"| `{ex.cve_id}` | {vf} | {ex.vuln_class or '—'} | {desc} |")
        out.append("")

    out.append("### How to train\n")
    out.append("```bash")
    out.append("# Install dependencies")
    out.append("pip install transformers peft datasets accelerate bitsandbytes trl")
    out.append("")
    out.append("# Run LoRA fine-tuning (requires GPU; use --load_in_4bit for 8GB VRAM)")
    out.append(f"python {ds.script_path} --epochs 3 --load_in_4bit")
    out.append("```\n")

    out.append("### How to use the fine-tuned model\n")
    out.append("```python")
    out.append("from transformers import AutoTokenizer, AutoModelForCausalLM")
    out.append("from peft import PeftModel")
    out.append(f'base = AutoModelForCausalLM.from_pretrained("{ds.model_id}")')
    out.append(f'model = PeftModel.from_pretrained(base, "{Path(ds.script_path).parent}/lora_output")')
    out.append(f'tok = AutoTokenizer.from_pretrained("{ds.model_id}")')
    out.append('inputs = tok("CVE-XXXX-YYYY: <description>", return_tensors="pt")')
    out.append('print(tok.decode(model.generate(**inputs, max_new_tokens=512)[0]))')
    out.append("```")

    out.append("\n_SOLO USO AUTORIZADO — el modelo resultante solo debe usarse contra "
               "targets propios o con autorización escrita._")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Checkpoint distribution
# ---------------------------------------------------------------------------

@dataclass
class DistributeResult:
    ok:            bool = False
    checkpoint_dir: str = ""
    gguf_path:     str = ""
    ollama_model:  str = ""
    hf_repo:       str = ""
    steps_done:    list = field(default_factory=list)
    steps_failed:  list = field(default_factory=list)
    note:          str = ""


def _merge_lora_to_base(lora_dir: str, base_model_id: str, out_dir: str) -> str:
    """Merge LoRA adapter weights into the base model and save a full HF checkpoint.

    Returns the path to the merged checkpoint directory.
    Requires: transformers, peft, torch.
    """
    merged_dir = str(Path(out_dir) / "merged")
    script = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        # merge_lora.py — generated by binoracle finetune
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer
        import torch, os

        base_id  = {base_model_id!r}
        lora_dir = {lora_dir!r}
        out_dir  = {merged_dir!r}

        print(f"Loading base {{base_id}}...")
        model = AutoModelForCausalLM.from_pretrained(base_id, torch_dtype=torch.float16,
                                                     device_map="cpu")
        tok   = AutoTokenizer.from_pretrained(base_id)

        print(f"Loading LoRA from {{lora_dir}}...")
        model = PeftModel.from_pretrained(model, lora_dir)

        print("Merging and unloading adapter...")
        model = model.merge_and_unload()

        print(f"Saving merged checkpoint to {{out_dir}}...")
        os.makedirs(out_dir, exist_ok=True)
        model.save_pretrained(out_dir)
        tok.save_pretrained(out_dir)
        print("Done.")
    """)
    script_path = str(Path(out_dir) / "merge_lora.py")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    Path(script_path).write_text(script, encoding="utf-8")
    os.chmod(script_path, 0o755)
    return merged_dir, script_path


def convert_to_gguf(merged_dir: str, out_dir: str,
                    quantization: str = "Q4_K_M",
                    llama_cpp_path: str = "") -> str:
    """Convert a merged HF checkpoint to GGUF using llama.cpp.

    Tries to find convert_hf_to_gguf.py in:
      1. LLAMA_CPP_PATH env var
      2. `llama_cpp_path` argument
      3. Common install paths

    Returns path to the output .gguf file, or raises RuntimeError.
    """
    import subprocess

    search_paths = [
        llama_cpp_path,
        os.environ.get("LLAMA_CPP_PATH", ""),
        os.path.expanduser("~/llama.cpp/convert_hf_to_gguf.py"),
        os.path.expanduser("~/llama.cpp/convert-hf-to-gguf.py"),
        "/opt/llama.cpp/convert_hf_to_gguf.py",
        "/usr/local/lib/llama.cpp/convert_hf_to_gguf.py",
    ]
    convert_script = next((p for p in search_paths if p and Path(p).exists()), None)
    if not convert_script:
        raise RuntimeError(
            "convert_hf_to_gguf.py not found. Clone llama.cpp and set LLAMA_CPP_PATH "
            "to the full path of convert_hf_to_gguf.py.")

    out_dir_p = Path(out_dir)
    out_dir_p.mkdir(parents=True, exist_ok=True)
    model_name = Path(merged_dir).name or "model"
    gguf_path = str(out_dir_p / f"{model_name}.gguf")

    # Step 1: convert to FP16 GGUF
    fp16_path = str(out_dir_p / f"{model_name}-f16.gguf")
    subprocess.run(
        ["python3", convert_script, merged_dir, "--outfile", fp16_path, "--outtype", "f16"],
        check=True, capture_output=True, text=True,
    )

    # Step 2: quantize (requires llama-quantize in PATH or same dir as convert script)
    quantize_bin = str(Path(convert_script).parent / "llama-quantize")
    if not Path(quantize_bin).exists():
        quantize_bin = "llama-quantize"
    try:
        subprocess.run(
            [quantize_bin, fp16_path, gguf_path, quantization],
            check=True, capture_output=True, text=True,
        )
        Path(fp16_path).unlink(missing_ok=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        # quantize not available — keep FP16
        gguf_path = fp16_path

    return gguf_path


def push_to_ollama(gguf_path: str, model_name: str,
                   system_prompt: str = "",
                   ollama_bin: str = "ollama") -> dict:
    """Create an Ollama model from a GGUF file.

    Writes a Modelfile alongside the GGUF, then runs `ollama create`.
    Returns {ok, model_name, note}.
    """
    import subprocess

    if not system_prompt:
        system_prompt = (
            "You are a security exploit analysis assistant specialized in CVE research. "
            "Given a CVE description, generate a precise exploit hypothesis including "
            "the vulnerable parameter, expected payload, and attack vector."
        )

    gguf_parent = Path(gguf_path).parent
    if not gguf_parent.exists():
        return {"ok": False, "model_name": model_name,
                "note": f"GGUF directory does not exist: {gguf_parent}"}
    modelfile_path = str(gguf_parent / "Modelfile")
    modelfile = textwrap.dedent(f"""\
        FROM {gguf_path}
        PARAMETER temperature 0.2
        PARAMETER top_p 0.9
        PARAMETER num_ctx 4096
        SYSTEM \"\"\"{system_prompt}\"\"\"
    """)
    Path(modelfile_path).write_text(modelfile, encoding="utf-8")

    try:
        r = subprocess.run(
            [ollama_bin, "create", model_name, "-f", modelfile_path],
            capture_output=True, text=True, timeout=600,
        )
        if r.returncode != 0:
            return {"ok": False, "model_name": model_name,
                    "note": f"ollama create failed: {r.stderr[:500]}"}
        return {"ok": True, "model_name": model_name,
                "note": f"Ollama model '{model_name}' created. Run: ollama run {model_name}"}
    except FileNotFoundError:
        return {"ok": False, "model_name": model_name,
                "note": "ollama binary not found — install Ollama first (https://ollama.ai)"}
    except Exception as e:
        return {"ok": False, "model_name": model_name, "note": str(e)}


def push_to_huggingface(checkpoint_dir: str, hf_repo: str,
                         private: bool = True,
                         token: str = "") -> dict:
    """Push a merged HF checkpoint to HuggingFace Hub.

    Args:
        checkpoint_dir: path to merged model (save_pretrained output)
        hf_repo:        HF repo id, e.g. 'beafn28/binoracle-cve-7b'
        private:        whether to create a private repo (default True)
        token:          HF token; falls back to HUGGINGFACE_TOKEN / HF_TOKEN env vars

    Returns {ok, repo_url, note}.
    """
    tok = token or os.environ.get("HUGGINGFACE_TOKEN") or os.environ.get("HF_TOKEN") or ""
    if not tok:
        return {"ok": False, "hf_repo": hf_repo,
                "note": "No HuggingFace token found. Set HUGGINGFACE_TOKEN env var."}
    try:
        from huggingface_hub import HfApi
        api = HfApi(token=tok)
        api.create_repo(repo_id=hf_repo, private=private, exist_ok=True)
        api.upload_folder(
            folder_path=checkpoint_dir,
            repo_id=hf_repo,
            commit_message="binoracle: upload fine-tuned CVE exploit hypothesis model",
        )
        url = f"https://huggingface.co/{hf_repo}"
        return {"ok": True, "hf_repo": hf_repo, "repo_url": url,
                "note": f"Uploaded to {url}"}
    except ImportError:
        return {"ok": False, "hf_repo": hf_repo,
                "note": "huggingface_hub not installed. Run: pip install huggingface_hub"}
    except Exception as e:
        return {"ok": False, "hf_repo": hf_repo, "note": str(e)}


def list_checkpoints(out_dir: str) -> list:
    """List all checkpoint directories produced by run_lora.py in `out_dir`.

    Returns list of {path, step, size_mb, is_best} sorted by step descending.
    """
    out = Path(out_dir)
    checkpoints = []
    for p in sorted(out.glob("**/checkpoint-*"), reverse=True):
        if not p.is_dir():
            continue
        step_m = Path(p.name).name.split("-")[-1]
        step = int(step_m) if step_m.isdigit() else 0
        size_mb = sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) / 1_048_576
        is_best = (p.parent / "best_model").exists() and str(p) == str(p.parent / "best_model")
        checkpoints.append({"path": str(p), "step": step, "size_mb": round(size_mb, 1),
                             "is_best": is_best})
    return sorted(checkpoints, key=lambda x: x["step"], reverse=True)


def clean_old_checkpoints(out_dir: str, keep: int = 2) -> list:
    """Remove all but the `keep` most recent checkpoints. Returns list of removed paths."""
    import shutil
    all_ckpts = list_checkpoints(out_dir)
    to_remove = all_ckpts[keep:]
    removed = []
    for ckpt in to_remove:
        try:
            shutil.rmtree(ckpt["path"])
            removed.append(ckpt["path"])
        except Exception:
            pass
    return removed


def distribute_checkpoint(
    lora_dir: str,
    base_model_id: str = "Qwen/Qwen2.5-Coder-7B-Instruct",
    out_dir: str = ".",
    quantization: str = "Q4_K_M",
    ollama_model_name: str = "binoracle-cve",
    hf_repo: str = "",
    hf_token: str = "",
    hf_private: bool = True,
    push_ollama: bool = True,
    push_hf: bool = False,
    llama_cpp_path: str = "",
    system_prompt: str = "",
) -> DistributeResult:
    """Full checkpoint distribution pipeline.

    Given a LoRA adapter directory (produced by run_lora.py), this function:
      1. Generates a merge script (merge_lora.py) — merge adapter into base weights
      2. Converts merged checkpoint to GGUF (Q4_K_M by default via llama.cpp)
      3. Creates an Ollama model and registers it locally (`ollama create`)
      4. Optionally pushes the merged checkpoint to HuggingFace Hub

    Args:
        lora_dir:          path to LoRA adapter (output of run_lora.py)
        base_model_id:     HuggingFace base model ID
        out_dir:           output directory for merged weights + GGUF
        quantization:      GGUF quantization type (Q4_K_M, Q5_K_M, Q8_0, f16)
        ollama_model_name: local Ollama model name
        hf_repo:           HuggingFace repo ID (required if push_hf=True)
        hf_token:          HuggingFace token (falls back to env var)
        hf_private:        create private HF repo (default True)
        push_ollama:       create Ollama model (default True)
        push_hf:           push to HuggingFace Hub (default False)
        llama_cpp_path:    path to convert_hf_to_gguf.py (falls back to env var)
        system_prompt:     system prompt for the Ollama Modelfile

    Returns DistributeResult with paths and status of each step.
    """
    res = DistributeResult(checkpoint_dir=lora_dir)

    # Step 1: generate merge script
    try:
        merged_dir, merge_script = _merge_lora_to_base(lora_dir, base_model_id, out_dir)
        res.steps_done.append(f"merge script written → {merge_script}")
        res.note += (
            f"\nRun merge first:\n  python3 {merge_script}\n"
            f"Then re-run distribute_checkpoint(lora_dir='{lora_dir}', "
            f"out_dir='{out_dir}') once merged_dir exists."
        )
    except Exception as e:
        res.steps_failed.append(f"merge script: {e}")

    # Step 2: GGUF conversion (requires merged dir to exist)
    merged_dir_p = Path(out_dir) / "merged"
    if merged_dir_p.exists() and any(merged_dir_p.glob("*.safetensors")):
        try:
            gguf = convert_to_gguf(str(merged_dir_p), str(Path(out_dir) / "gguf"),
                                   quantization=quantization,
                                   llama_cpp_path=llama_cpp_path)
            res.gguf_path = gguf
            res.steps_done.append(f"GGUF → {gguf}")
        except RuntimeError as e:
            res.steps_failed.append(f"GGUF conversion skipped: {e}")
        except Exception as e:
            res.steps_failed.append(f"GGUF conversion failed: {e}")

    # Step 3: Ollama push
    if push_ollama and res.gguf_path:
        r = push_to_ollama(res.gguf_path, ollama_model_name, system_prompt=system_prompt)
        if r["ok"]:
            res.ollama_model = ollama_model_name
            res.steps_done.append(f"Ollama: {r['note']}")
        else:
            res.steps_failed.append(f"Ollama: {r['note']}")

    # Step 4: HuggingFace Hub push
    if push_hf and hf_repo and merged_dir_p.exists():
        r = push_to_huggingface(str(merged_dir_p), hf_repo,
                                private=hf_private, token=hf_token)
        if r["ok"]:
            res.hf_repo = hf_repo
            res.steps_done.append(f"HuggingFace: {r['note']}")
        else:
            res.steps_failed.append(f"HuggingFace: {r['note']}")

    res.ok = bool(res.steps_done)
    return res


def render_distribute(res: DistributeResult) -> str:
    out = ["## Checkpoint distribution\n"]
    out.append(f"**LoRA checkpoint:** `{res.checkpoint_dir}`")
    if res.gguf_path:
        out.append(f"**GGUF:** `{res.gguf_path}`")
    if res.ollama_model:
        out.append(f"**Ollama model:** `{res.ollama_model}` — run with `ollama run {res.ollama_model}`")
    if res.hf_repo:
        out.append(f"**HuggingFace:** https://huggingface.co/{res.hf_repo}")
    if res.steps_done:
        out.append("\n**Steps completed:**")
        for s in res.steps_done:
            out.append(f"  - {s}")
    if res.steps_failed:
        out.append("\n**Steps failed / skipped:**")
        for s in res.steps_failed:
            out.append(f"  - {s}")
    if res.note:
        out.append(f"\n{res.note}")
    out.append("\n_SOLO USO AUTORIZADO — distribuye el checkpoint solo contra targets propios "
               "o con autorización escrita._")
    return "\n".join(out)
