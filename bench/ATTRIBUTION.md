# Dataset attribution

The optional benchmark adapter can download the validation split of **PII Masking Nano** from Ai4Privacy:

- Dataset: <https://huggingface.co/datasets/ai4privacy/pii-masking-nano-1k>
- Author/maintainer: Ai Suisse SA / Ai4Privacy
- License: [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/)
- Dataset card describes the sample as synthetic PII only, with no real personal data.

The repository does not redistribute the dataset. When using the adapter, retain this attribution and comply with the dataset's CC BY 4.0 terms. The adapter evaluates only the `EMAIL`, `TELEPHONENUM`, and `CREDITCARDNUMBER` label mappings described in [METHODOLOGY.md](METHODOLOGY.md).
