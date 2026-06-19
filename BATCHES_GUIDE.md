# Azure Permission Batch Review Guide

The 5,065 Azure operations have been organized into **54 reviewable batches** by risk category.

## Quick Start

Start with **Batches 1-8** (in `batches/` directory):

```
batches/batch-1/   — Escalation: Privilege (77 ops)
batches/batch-2/   — Escalation: Privilege (77 ops)
batches/batch-3/   — Takeover: Account (70 ops)
batches/batch-4/   — Exfiltration: Crypto (87 ops)
batches/batch-5/   — Exfiltration: Crypto (86 ops)
batches/batch-6/   — Exfiltration: Data (88 ops)
batches/batch-7/   — Exfiltration: Data (88 ops)
batches/batch-8/   — Persistence: Account (44 ops)
```

**Total: 617 ops** — the highest-impact, most security-critical operations.

## Review Process

For each batch:

1. **Open the batch directory** in your editor
2. **Read `BATCH_README.md`** for category overview
3. **Review the YAML files** — each file is one Azure resource type with its operations
4. **Check with Copilot:**
   - Does the risk assignment match the operation's capability?
   - Are related operations consistently classified?
   - Missing any obvious operations?

## File Organization

Each batch is organized as:

```
batch-N/
  BATCH_README.md
  Microsoft.Authorization/
    roleAssignments.yml
    ...
  Microsoft.Network/
    ...
```

Each `.yml` file contains one resource type (e.g. `roleAssignments`) with its operations (`read`, `write`, `delete`, `action`).

## Batch Contents

See `BATCH_MANIFEST.json` for the complete list of which operations are in each batch.

## If Issues Found

If you find misclassifications:

1. Note the operation ID (e.g. `Microsoft.Authorization/roleAssignments/write`)
2. Note what's wrong (e.g. "missing `escalation:privilege` risk")
3. Create an issue or note for that batch's review

## Next Steps After Batches 1-8

Once the high-impact batches pass review:

- **Batches 9-25** (destruction ops, 1,614 total) — lower priority, clear patterns
- **Batches 26-54** (discovery/metadata, 2,834 total) — optional spot-check

---

**Total progress tracking:**

- High-risk: 617 ops (Batches 1-8)
- Destruction: 1,614 ops (Batches 9-25)
- Discovery/other: 2,834 ops (Batches 26-54)
