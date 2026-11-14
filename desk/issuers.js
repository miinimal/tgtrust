// Issuer keys this desk trusts for credential checks. Each entry was read from the issuer's GET /v1/issuer
// on the date in read_at, and its key id recomputed from the key (tests/test_desk_issuers.py checks it again).
export const ISSUERS = Object.freeze([
  {
    "key_id": "9fc6ef5575f072ab",
    "epoch": "v2",
    "scheme": "RSABSSA-SHA384-PSSZERO-Deterministic",
    "credential_prefix": "tgtrust/v1/credential:",
    "url": "https://minimal.tailee59dc.ts.net/v1",
    "label": "tgtrust demo issuer (test policy, single machine, may be offline)",
    "read_at": "2026-11-14",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA1fUfnZzPBVLEXA2LZFj8\nKGKzvvmXhs7IWn2+7k+7qtw0jgE+zWtSBgbAQpdL3LKzPYQUhvjCqoyVu/rTE6FF\nRNX90OHSM6dQmeY5hPKm8SbA2cjlXySlehUgtEqlXp8TAt40GzOOwqDltNrH4sCL\nlkiKu3m1E8wES6Qo4RWQTqoTdFQK0MYpBpxOPOJ0jLGER8J4a+kmiuWFP1enBenO\nMtdjDw26kR9NmB/GC66/A5zK6yHMzhVD3xrp8J5FORBxibe47oRt1gehNcGzskvH\nVGzaH4ibV9pwUqoee4sTmjKhvlIIWClZ9CyyN+UnwT8F+0QVT3tWXp6TDXCp5/n5\nox4QUxg/0PFZFDPKNEVSVtw8EdfL5w9AzMn4VtDyTGoOE7IknY1Ha9u/MMDIBH3E\ndpn7iIOjXQ+R2FZ/Tvw4rSSwUxCumtDjNbj1jFkRTddDFFusRhRbkmF5KTR4tpxQ\n6N/BGg8kaftJj5QJ8LmCRt5+KSgtU0j2QmhiHcAPIxEhAgMBAAE=\n-----END PUBLIC KEY-----\n"
  }
]);
