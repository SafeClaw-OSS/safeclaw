# GCP Secret Manager — End-to-End Smoke Test

Phase 1 + 2 + 3 ship together: stores+items v3 schema, adapter
dispatch, and the GCP Secret Manager adapter. This walks you through
proving the full path: vault.aux carries a `gcp-secret-manager` store
record → daemon's adapter signs a JWT, exchanges it for an OAuth
token, calls `accessSecretVersion`, and forwards the resolved bytes
to the upstream service.

If anything fails, the daemon log (under `[daemon] ...` in dev.sh
output) carries enough to triage.

## 0. GCP setup (one-time, ~5 minutes)

You need a project + a Secret Manager secret + a service-account JSON
with read access to that secret.

```bash
gcloud config set project <YOUR_PROJECT_ID>

# Enable Secret Manager API if not already on
gcloud services enable secretmanager.googleapis.com

# Create a secret (use any item-name you want your service to see;
# we'll use `openai_api_key` so it lines up with the OpenAI service)
echo -n "sk-DEMO-FAKE-VALUE" \
  | gcloud secrets create openai_api_key --replication-policy=automatic --data-file=-

# Create a service account
gcloud iam service-accounts create safeclaw-demo \
  --display-name="SafeClaw demo SA"

# Per-secret IAM binding (the security pitch: SA can only read THIS secret)
gcloud secrets add-iam-policy-binding openai_api_key \
  --member="serviceAccount:safeclaw-demo@<YOUR_PROJECT_ID>.iam.gserviceaccount.com" \
  --role=roles/secretmanager.secretAccessor

# Mint the SA JSON. Save the file path — you'll paste its contents
# into the SafeClaw "Connect GCP" dialog.
gcloud iam service-accounts keys create ./safeclaw-demo-sa.json \
  --iam-account=safeclaw-demo@<YOUR_PROJECT_ID>.iam.gserviceaccount.com
```

## 1. Start the stack

```bash
cd ~/projects/safeclaw
./dev.sh
```

Wait until you see `[daemon] daemon serving on :23294` (admin) and
`[frontend] Local: http://localhost:3000`. The Cargo.toml changed,
so the daemon will rebuild — expect ~30-60s for the first build.

## 2. Enroll a fresh vault

Browser → `http://localhost:3000/vault`

- If you have an old vault.dat from before Phase 1, the unlock will
  hard-fail with "vault plaintext version X (expected 3) — vault is
  from an older binary; re-enroll required". Wipe and retry:
  ```bash
  rm -rf ~/projects/safeclaw/.state/safeclaw-daemon/tenants
  ```
- Click "Seal vault with passkey", do the passkey ceremony.
- Add at least one entry — leave `openai_api_key` empty for now (so
  we can prove the GCP resolution path; if you fill it in, native-
  secrets wins on first-match and GCP never gets hit).

After sealing the daemon log should show:
```
vault enroll complete
vault auto-unlocked after enroll
```

## 3. Connect the GCP store

On the unlocked vault detail view you should see a new "Stores"
section listing `native-secrets` and `native-files` with a
"+ Connect GCP Secret Manager" button.

- Click → dialog opens.
- Fill:
  - **Store ID**: `prod-gcp` (or any unique name)
  - **GCP project_id**: your project ID
  - **Service account JSON**: paste the full contents of
    `safeclaw-demo-sa.json`
- Click "Connect (passkey)". You'll get a passkey prompt; this is
  the write op that adds the GCP store to your vault.

After success:
- The stores list now shows 3 entries:
  `1. native-secrets   2. prod-gcp   3. native-files`
- (Internally, the SA JSON went into native-secrets as
  `_prod-gcp_sa_json`.)

## 4. Trigger a resolve through GCP

The OpenAI service in the in-tree registry has
`auth.env = "openai_api_key"`. Because native-secrets doesn't have
that key (you skipped it in step 2), store_order falls through to
`prod-gcp`, which calls the GCP API.

Easiest trigger: a curl that goes through `/use`.

```bash
# Find your vault_id (= Supabase user.id, or your local user id if
# anon-signed-in). It's also visible in the URL after /vault.
VAULT_ID=<your-vault-id>

# Get the api_key from /vault → Install on agent → "Generate".
# Or use envApi.generateApiKey via the UI — the dialog shows the token once.
SC_TOKEN=sc_xxxxxxxxxxxxxxxx

# Hit OpenAI through SafeClaw. This should:
#   1. Trigger an approval card on /vault (allow-policy services may
#      cache-hit and skip the card — depends on policy)
#   2. Daemon resolves openai_api_key → walks store_order →
#      native-secrets misses → GCP adapter signs JWT, gets token,
#      calls accessSecretVersion → returns "sk-DEMO-FAKE-VALUE"
#   3. Daemon forwards to api.openai.com with that as Bearer
#   4. OpenAI 401s (because we used a fake value) — that's FINE,
#      the 401 means we successfully resolved + forwarded
curl -X POST http://localhost:23295/v/$VAULT_ID/use/openai/v1/models \
  -H "Authorization: Bearer $SC_TOKEN"
```

Look at the daemon log. Success looks like:
```
broker forward target=openai_api_key method=POST url=https://api.openai.com/v1/models
```
plus an HTTP response (likely 401 from OpenAI since the secret value
is fake). What matters is the **`broker forward`** line — it proves
the GCP adapter successfully resolved.

## 5. What "broken" looks like (debug cheat sheet)

| Symptom | Likely cause |
|---------|--------------|
| `vault plaintext version X (expected 3)` | Old vault — wipe + re-enroll |
| `vault aux parse: missing field …` | Client/daemon out of sync — check Cargo.toml version + frontend build |
| `store 'prod-gcp': credentials_item '_prod-gcp_sa_json' not found in native-secrets` | Connect-store write didn't persist the SA JSON — passkey prompt was canceled |
| `accessSecretVersion returned 403` | SA missing `secretAccessor` role on that secret (recheck IAM binding) |
| `accessSecretVersion returned 404` | Secret name typo, or secret doesn't exist in the project |
| `SA private_key not valid RSA PEM` | Pasted the wrong field, or JSON escaping mangled the `\n` — re-paste raw file contents |
| `token endpoint returned 400` | Clock skew, or SA private key doesn't match the SA email — re-mint the SA JSON |

## 6. Cleanup

```bash
gcloud iam service-accounts keys delete <KEY_ID> \
  --iam-account=safeclaw-demo@<YOUR_PROJECT_ID>.iam.gserviceaccount.com
gcloud iam service-accounts delete safeclaw-demo@<YOUR_PROJECT_ID>.iam.gserviceaccount.com
gcloud secrets delete openai_api_key
rm ./safeclaw-demo-sa.json
```
