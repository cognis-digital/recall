# Demo 01 — Basic encrypted recall

This demo shows RECALL ingesting a few personal notes into an encrypted,
audit-logged vault and retrieving the most relevant one for a natural-language
query. Nothing leaves the machine; the vault is encrypted at rest and every
query is recorded in a hash-chained audit log.

## Setup

All commands run with a passphrase. Use the env var so it stays off the
command line:

```sh
export RECALL_PASSPHRASE='correct horse battery staple'
export RECALL_VAULT=demo.vault
```

## 1. Ingest the sample notes

`notes.txt` (in this folder) contains a few personal notes separated by
`---`. Add them one at a time:

```sh
python -m recall add "WiFi password"      --text "Home WiFi network eero-mesh password is hunter2-greenway, 192.168.68.0/22" --tag home
python -m recall add "Alpaca paper key"   --text "Alpaca paper trading API key lives on the Samsung T7 SSD under alpha-trade-deck/.env" --tag trading
python -m recall add "Doctor appointment" --text "Annual physical with Dr. Okafor scheduled for June 30, bring insurance card" --tag health
```

## 2. Ask in natural language

```sh
python -m recall --format json relevant "where is my trading api key stored"
```

Expected: the "Alpaca paper key" note ranks first by TF-IDF cosine score.

## 3. Inspect the audit trail

```sh
python -m recall audit
```

You should see `add` and `query` actions and `chain intact: True`. If anyone
edits the log out from under you, `verify` flips to `False`.
