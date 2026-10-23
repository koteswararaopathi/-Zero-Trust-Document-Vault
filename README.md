# Zero-Trust-Document-Vault (TrustVault)

TrustVault is an enterprise document vault engineered to eliminate **Insecure Direct Object References (IDOR)** through strict server-side Role-Based Access Control (RBAC) and immutable telemetry backed by a **cryptographic SHA-256 hash chain**.

---

## 🏛️ System Architecture

```
                       ┌───────────────────────────────────────────────┐
                       │               Incoming Request                │
                       └───────────────────────┬───────────────────────┘
                                               │
                                 ┌─────────────▼─────────────┐
                                 │   @require_role(*roles)   │
                                 └─────────────┬─────────────┘
                                               │ [Pass]
                                               ▼
                         ┌───────────────────────────────────────────┐
                         │  @require_document_access(perm_type)      │
                         └─────────────────────┬─────────────────────┘
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       │                                               │
               [Authorized]                                    [Unauthorized]
                       │                                               │
        ┌──────────────▼─────────────┐                   ┌─────────────▼─────────────┐
        │  Fetch / Execute Action    │                   │  Record ACCESS_DENIED     │
        │  (Upload, Download, Share, │                   │  in SHA-256 Audit Chain   │
        │   Revoke, Delete)          │                   │  HTTP 403 Forbidden       │
        └──────────────┬─────────────┘                   └───────────────────────────┘
                       │
        ┌──────────────▼─────────────┐
        │ Cryptographic Audit Block  │
        │ SHA256(uid|act|time|prev)  │
        └────────────────────────────┘
```

---

## 🔐 1. Strict Server-Side RBAC Enforcement (Eliminate IDOR)

### Roles
- **`Admin`**: Read-only oversight of system telemetry and cryptographic audit verification. Zero document-manipulation privileges.
- **`Owner`**: Full ownership authority over their own documents: upload, download, share access with Viewers, revoke access, and delete documents. Cannot delete or manipulate documents owned by other Owners.
- **`Viewer`**: Strictly read-only access to documents explicitly shared by their Owner. Cannot upload, share, revoke, or delete documents.

### Route Decorators
- **`@require_role(*roles)`**:
  * Authenticates user session and validates role membership.
  * Rejects unauthorized personas with **HTTP 403 Forbidden**.
  * Never relies on frontend UI button hiding.
- **`@require_document_access(permission_type)`**:
  * Intercepts document-targeting endpoints (`/download/<doc_id>`, `/share/<doc_id>`, `/revoke/<doc_id>`, `/delete/<doc_id>`).
  * Resolves document from database.
  * Verifies ownership (`doc.owner_id == current_user.id`) for write/delete/share/revoke.
  * Verifies active grant in `DocumentShare` for read requests.
  * Unauthorized attempts record an `ACCESS_DENIED` entry in the cryptographic audit ledger and terminate with **HTTP 403 Forbidden**.

### Instantaneous Revocation
Access grants are persisted in `document_shares` (`is_active = True/False`).
When an Owner revokes access:
```python
share.is_active = False
share.revoked_at = datetime.now(timezone.utc)
db.session.commit()
```
Because `@require_document_access('read')` queries active grants in real time, any subsequent request from the revoked Viewer immediately terminates with **HTTP 403 Forbidden**.

---

## ⛓️ 2. Tamper-Resistant Audit Trail & Telemetry

### Cryptographic Chaining Specification
Each audit record in `audit_logs` contains:
- `timestamp`: UTC datetime
- `timestamp_str`: Canonical ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SS.ffffffZ`)
- `user_id`: Actor identity (or `None` for anonymous)
- `target_document_id`: Target document ID
- `action_type`: `READ`, `WRITE`, `SHARE`, `REVOKE`, `DELETE`, `ACCESS_DENIED`
- `ip_address`: Remote client IP address
- `status_code`: HTTP response status (200, 201, 403, 404, etc.)
- `prev_hash`: SHA-256 hash of previous block (or `"GENESIS"` for block 1)
- `entry_hash`: SHA-256 hash of current block

#### Canonical Chaining Formula:
$$\text{Entry Hash} = \text{SHA-256}(\text{user\_id} \parallel \text{"|"} \parallel \text{action\_type} \parallel \text{"|"} \parallel \text{timestamp\_str} \parallel \text{"|"} \parallel \text{prev\_hash})$$

### Tamper Detection Utility (`verify_audit_integrity()`)
Iterates through all audit records in ascending sequence:
1. Validates previous hash link: `entry.prev_hash == previous_entry.entry_hash`
2. Re-computes expected entry hash: `calculate_entry_hash(entry.user_id, entry.action_type, entry.timestamp_str, entry.prev_hash)`
3. Verifies `entry.entry_hash == expected_entry_hash`
4. If any record was altered out-of-band via direct database SQL or corrupted, flags `DATA_TAMPERING_DETECTED` or `BROKEN_CHAIN_LINK`, emits a **CRITICAL** log alert, and returns details of the tampered record.

---

## 🧪 3. Security & Regression Test Suite

Automated tests under `/tests` verify 100% test pass rate across all attack vectors:

| Test Case | Scenario / Attack Vector | Expected Result |
| :--- | :--- | :--- |
| `test_positive_upload_share_download_flow` | Owner uploads, shares with Viewer, Viewer downloads | HTTP 200 OK |
| `test_idor_viewer_cannot_delete_document` | Viewer attempts direct POST/GET `/delete/<doc_id>` | **HTTP 403 Forbidden** |
| `test_idor_other_owner_cannot_delete_foreign_document` | Owner Charlie attempts to delete Owner Alice's doc | **HTTP 403 Forbidden** |
| `test_idor_unshared_document_download_forbidden` | Viewer Bob attempts `/download/<doc_id>` without grant | **HTTP 403 Forbidden** |
| `test_idor_viewer_cannot_share_document` | Viewer attempts `/share/<doc_id>` | **HTTP 403 Forbidden** |
| `test_instantaneous_revocation` | Owner revokes Viewer -> Viewer downloads immediately | **HTTP 403 Forbidden** |
| `test_admin_audit_stream_restricted_to_admin` | Non-admin users hit `/admin/audit-logs` | **HTTP 403 Forbidden** |
| `test_access_denied_creates_audit_log_entry` | Any unauthorized access attempt occurs | `ACCESS_DENIED` log recorded |
| `test_audit_cryptographic_chaining_positive` | Sequential legitimate events recorded | Chain `valid: True` |
| `test_tamper_detection_action_type_altered` | Out-of-band SQL modification to `action_type` | `DATA_TAMPERING_DETECTED` |
| `test_tamper_detection_user_id_altered` | Out-of-band SQL modification to `user_id` | `DATA_TAMPERING_DETECTED` |
| `test_tamper_detection_broken_chain_prev_hash` | Out-of-band tampering with `prev_hash` | `BROKEN_CHAIN_LINK` |
| `test_tamper_detection_deleted_row` | Malicious deletion of intermediate audit row | `BROKEN_CHAIN_LINK` |
| `test_api_verify_audit_endpoint` | Admin `/admin/verify-audit` API | 200 (Clean) / 409 (Tampered) |

### Running Test Suite:
```bash
pytest
```

---

## 🚀 Quick Start & Development

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Seed Database
```bash
python -c "from run import seed_database; seed_database()"
```

### 3. Run Application
```bash
python run.py
```
App will be running at `http://127.0.0.1:5000`.

### Seed Accounts:
- **Admin**: `admin` / `AdminPass123!` (Role: `Admin`)
- **Owner 1**: `alice` / `AlicePass123!` (Role: `Owner`)
- **Viewer**: `bob` / `BobPass123!` (Role: `Viewer`)
- **Owner 2**: `charlie` / `CharliePass123!` (Role: `Owner` - IDOR Target)
