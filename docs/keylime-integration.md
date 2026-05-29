# Keylime Integration Notes

Keylemon treats Keylime as the source of truth for TPM and vTPM evidence.

The current adapter maps the latest Keylime attestation response into normalized
claims:

- `evaluation == pass` becomes `pcr_policy_ok=true` and authorization `allow`.
- TPM quote evidence metadata can populate `pcr_selection`.
- UEFI and IMA evidence presence populate measured boot and runtime integrity
  booleans when the response includes those evidence items.
- AK material is fingerprinted when exposed in the response.

Minimal upstream-facing additions that would improve integration:

- A stable latest normalized attestation result endpoint for both pull and push.
- Explicit verifier output for PCR, IMA, and measured boot sub-results.
- Broker-friendly revocation webhooks including agent ID, failure reason,
  policy IDs, and timestamp.
- Stable metadata for physical TPM versus vTPM classification.

