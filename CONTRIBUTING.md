# Contributing

1. Open an issue describing the problem or proposed design change.
2. Keep cryptographic operations inside established libraries; do not introduce custom cryptographic algorithms.
3. Add tests for normal, malformed and adversarial inputs.
4. Run `pytest` and `ruff check .` before submitting.
5. Document security assumptions, limitations and evidence class.
6. Never commit private keys, credentials or confidential device data.

Security-sensitive changes should include a threat-model update and reviewer notes.
