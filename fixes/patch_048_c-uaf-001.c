# Use-after-free pattern
# CWE-416 | Severity: HIGH
# File: target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_acl.c line 1288

**Risk:** Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
