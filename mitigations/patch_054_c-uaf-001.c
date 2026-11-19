# Use-after-free pattern
# CWE-416 | Severity: HIGH
# File: package/network/services/hostapd/src/hostapd/radius.c line 128

**Risk:** Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
