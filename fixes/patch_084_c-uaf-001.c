# Use-after-free pattern
# CWE-416 | Severity: HIGH
# File: target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_flow_offload.c line 3131

**Risk:** Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
