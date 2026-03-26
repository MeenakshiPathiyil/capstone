"""Compatibility launcher for the QLoRA fine-tuning script.

This file lets Colab and local commands run:
    python fine_tune.py --data training_data.jsonl --out ./output
"""

from finetuning import main


if __name__ == "__main__":
    main()
