# Scenario: Legal policy corpus

Three policy docs. Test query: `recall scan demos/03-legal-policy-corpus/ --query 'what does the DPA cover'`.

## Expected findings

- RAG_HIT to dpa.md

## Why this matters

Common use case: legal-team policy search without exposing privileged docs to cloud LLMs.
