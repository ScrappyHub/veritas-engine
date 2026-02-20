# Test Keys

`test_signer_ed25519.pub` is used to verify signatures in test vectors.

Private keys should not be committed unless you explicitly choose to include them for reproducible signing in CI.
Preferred approach: ship only public keys; ship pre-signed vectors.
