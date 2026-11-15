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
    out.append(f"# Run LoRA fine-tuning (requires GPU; use --load_in_4bit for 8GB VRAM)")
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
