# Security audit: openwrt/openwrt

Date: 2026-11-19 | Auditor: [mutsuumii](https://github.com/mutsuumii)

## Summary

Found 120 issue(s): 24 critical, 94 high, 2 medium.

## Findings

### 1. [CRITICAL] Format string vulnerability

**CWE-134** | `target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_flow.c` line 332

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
snprintf(name, sizeof(name), "uplink_port%u_vid%u", up->port,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 2. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `package/network/services/ead/src/tinysrp/t_conv.c` line 99

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(chp, "%.2x", * (unsigned char *) src);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 3. [HIGH] Integer overflow in size calculation

**CWE-190** | `package/network/services/ead/src/tinysrp/t_conv.c` line 126

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
a = malloc((size + 1) * sizeof(unsigned char));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 4. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/tinysrp/t_conv.c` line 168

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(a);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 5. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/network/services/ead/src/tinysrp/t_conv.c` line 126

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
a = malloc((size + 1) * sizeof(unsigned char));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 6. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/network/ipv6/map/src/mapcalc.c` line 232

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
for (char *rule = strdup(argv[i]); *rule; ) {
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 7. [CRITICAL] Format string vulnerability

**CWE-134** | `package/network/services/ead/src/tinysrp/srvtest.c` line 66

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("Enter username: ");
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 8. [HIGH] Use-after-free pattern

**CWE-416** | `package/utils/jboot-tools/src/jboot_config_read.c` line 276

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buffer);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 9. [HIGH] Use-after-free pattern

**CWE-416** | `package/utils/jboot-tools/src/jboot_config_read.c` line 423

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buffer);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 10. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/utils/jboot-tools/src/jboot_config_read.c` line 262

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
buffer = malloc(file_size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 11. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `package/network/services/hostapd/src/src/ap/ucode.c` line 245

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
strcpy(vlan->ifname, wildcard->ifname);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 12. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1253

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(key_hex + 2 * i, "%02x", key[i]);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 13. [CRITICAL] Format string vulnerability

**CWE-134** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1496

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
os_snprintf(addr_str, sizeof(addr_str), MACSTR, MAC2STR(addr));
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 14. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 101

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 15. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 200

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(partners);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 16. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 302

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hostapd_bss_deinit_no_free(hapd);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 17. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 409

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hostapd_config_free(conf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 18. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 486

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(hapd);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 19. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 597

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(hapd);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 20. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 600

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hostapd_config_free(conf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 21. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 651

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(new_bss);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 22. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 652

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(new_conf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 23. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1056

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(prev_path);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 24. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1057

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(path);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 25. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1160

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(p);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 26. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1319

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(frame_data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 27. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1326

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(frame_data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 28. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1330

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(frame_data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 29. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1336

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
wpabuf_free(msg);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 30. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1375

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 31. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1422

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(frame_b64);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 32. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1457

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(query_b64);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 33. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1475

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(resp_data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 34. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1506

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(data_b64);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 35. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1526

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
os_free(extra);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 36. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/src/ap/ucode.c` line 1599

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
void hostapd_ucode_free(void)
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 37. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/network/services/hostapd/src/src/ap/ucode.c` line 99

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
data = strdup(ucv_string_get(iface));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 38. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/network/services/hostapd/src/src/ap/ucode.c` line 163

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
*partners = os_calloc(last - first, sizeof(**partners));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 39. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/network/services/hostapd/src/src/ap/ucode.c` line 619

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
new_bss = calloc(iface->num_bss, sizeof(*new_bss));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 40. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/network/services/hostapd/src/src/ap/ucode.c` line 620

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
new_conf = calloc(iface->num_bss, sizeof(*new_conf));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 41. [CRITICAL] Format string vulnerability

**CWE-134** | `target/linux/ramips/image/lzma-loader/src/loader.c` line 228

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("Incorrect LZMA stream properties!\n");
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 42. [CRITICAL] Format string vulnerability

**CWE-134** | `target/linux/ramips/image/lzma-loader/src/loader.c` line 239

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("data error!\n");
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 43. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/libbridge_init.c` line 82

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(namelist);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 44. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/libbridge_init.c` line 122

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(namelist);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 45. [HIGH] Path traversal via unsanitized input

**CWE-22** | `scripts/sercomm-partition-tag.py` line 24

File path built from user input. Attacker reads/writes arbitrary files using ../ sequences.

```
in_f = open(args.input_file, 'r+b')
```

**Fix:** Use os.path.realpath() and verify result starts with the expected base directory.
---

### 46. [HIGH] Path traversal via unsanitized input

**CWE-22** | `scripts/sercomm-partition-tag.py` line 28

File path built from user input. Attacker reads/writes arbitrary files using ../ sequences.

```
out_f = open(args.output_file, 'w+b')
```

**Fix:** Use os.path.realpath() and verify result starts with the expected base directory.
---

### 47. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_acl.c` line 874

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(r);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 48. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_acl.c` line 1288

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(r);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 49. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/generic/files/drivers/net/phy/rtl8366rb.c` line 1473

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(smi);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 50. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/generic/files/drivers/net/phy/rtl8366rb.c` line 1485

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(smi);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 51. [CRITICAL] Format string vulnerability

**CWE-134** | `target/linux/realtek/image/rt-loader/src/board.c` line 101

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
snprintf(buffer, len, "RTL%04X%c rev %c (%04x)", model_id,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 52. [CRITICAL] Format string vulnerability

**CWE-134** | `target/linux/realtek/files-6.18/drivers/net/mdio/mdio-realtek-otto-serdes.c` line 172

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
snprintf(dirname, sizeof(dirname), "serdes.%d", sds);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 53. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `package/network/services/hostapd/src/hostapd/radius.c` line 511

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
state->node.key = strcpy(name_buf, id);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 54. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/hostapd/radius.c` line 128

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(s);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 55. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/hostapd/src/hostapd/radius.c` line 517

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(state);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 56. [MEDIUM] Large stack allocation (potential stack overflow)

**CWE-770** | `package/network/services/hostapd/src/hostapd/radius.c` line 536

alloca() or large fixed VLA on stack. If size is attacker-controlled or too large, stack overflow corrupts adjacent frames.

```
id = alloca(identity_len + 1);
```

**Fix:** Use heap allocation (malloc) for large or variable-sized buffers. Enforce a size cap before alloca().
---

### 57. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/generic/files/drivers/mtd/mtdsplit/mtdsplit_seil.c` line 95

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
vfree(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 58. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/generic/files/drivers/mtd/mtdsplit/mtdsplit_seil.c` line 173

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(parts);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 59. [HIGH] Missing NULL check after allocation

**CWE-476** | `target/linux/generic/files/drivers/mtd/mtdsplit/mtdsplit_seil.c` line 67

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
buf = vmalloc(env_mtd->size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 60. [HIGH] Missing NULL check after allocation

**CWE-476** | `target/linux/generic/files/drivers/mtd/mtdsplit/mtdsplit_seil.c` line 124

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
parts = kcalloc(NR_PARTS, sizeof(*parts), GFP_KERNEL);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 61. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `package/utils/px5g-mbedtls/px5g-mbedtls.c` line 400

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(sstr + len*2, "%02x", (unsigned char) buf[len]);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 62. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/utils/px5g-mbedtls/px5g-mbedtls.c` line 265

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
subject = calloc(strlen(arg[1]) + 1, 1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 63. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/utils/px5g-mbedtls/px5g-mbedtls.c` line 290

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ext_key_usage = calloc(1, sizeof(mbedtls_asn1_sequence));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 64. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/utils/px5g-mbedtls/px5g-mbedtls.c` line 318

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
san_cur = calloc(1, sizeof(mbedtls_x509_san_list));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 65. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/utils/px5g-mbedtls/px5g-mbedtls.c` line 329

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ipaddr = calloc(1, 16);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 66. [MEDIUM] Large stack allocation (potential stack overflow)

**CWE-770** | `package/utils/px5g-mbedtls/px5g-mbedtls.c` line 51

alloca() or large fixed VLA on stack. If size is attacker-controlled or too large, stack overflow corrupts adjacent frames.

```
static char buf[16384];
```

**Fix:** Use heap allocation (malloc) for large or variable-sized buffers. Enforce a size cap before alloca().
---

### 67. [HIGH] Missing NULL check after allocation

**CWE-476** | `target/linux/generic/files/drivers/mtd/mtdsplit/mtdsplit_cfe_bootfs.c` line 57

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
parts = kcalloc(NR_PARTS, sizeof(*parts), GFP_KERNEL);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 68. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `scripts/mkhash.c` line 695

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(&str[i * 2], "%02x", buf[i]);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 69. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/generic/files/drivers/net/phy/psb6970.c` line 326

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(priv);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 70. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/generic/files/drivers/net/phy/psb6970.c` line 349

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(priv);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 71. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/generic/files/drivers/net/phy/psb6970.c` line 355

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(priv);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 72. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/generic/files/drivers/net/phy/psb6970.c` line 395

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(priv);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 73. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `package/kernel/lantiq/ltq-ptm/src/ifxmips_ptm_ppe_common.h` line 310

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
return sprintf(buf, "Lantiq %s driver, version %d.%d.%d, (c) 2001-2013 Lantiq Deutschland GmbH\n",
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 74. [CRITICAL] Format string vulnerability

**CWE-134** | `package/kernel/lantiq/ltq-ptm/src/ifxmips_ptm_ppe_common.h` line 310

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
return sprintf(buf, "Lantiq %s driver, version %d.%d.%d, (c) 2001-2013 Lantiq Deutschland GmbH\n",
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 75. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `package/kernel/gpio-button-hotplug/src/gpio-button-hotplug.c` line 130

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
strcpy(s, buf);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 76. [CRITICAL] Format string vulnerability

**CWE-134** | `package/kernel/gpio-button-hotplug/src/gpio-button-hotplug.c` line 121

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
len = vsnprintf(buf, sizeof(buf), format, args);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 77. [HIGH] Use-after-free pattern

**CWE-416** | `package/kernel/gpio-button-hotplug/src/gpio-button-hotplug.c` line 203

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(event);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 78. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_flow_offload.c` line 830

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(entry);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 79. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_flow_offload.c` line 2818

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(fb);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 80. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_flow_offload.c` line 2853

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(fb);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 81. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_flow_offload.c` line 3048

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
ppe_shaper_md_free(priv);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 82. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_flow_offload.c` line 3088

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
ppe_shaper_md_free(priv);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 83. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_flow_offload.c` line 3096

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
ppe_shaper_md_free(priv);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 84. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/qualcommax/files/drivers/net/ethernet/qualcomm/qca_ppe_flow_offload.c` line 3131

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
ppe_shaper_md_free(priv);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 85. [HIGH] Use-after-free pattern

**CWE-416** | `target/linux/siflower/files-6.18/drivers/spi/spi-sf21-qspi.c` line 459

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
kfree(chip);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 86. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `scripts/config/symbol.c` line 662

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
strcpy(val, newval);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 87. [HIGH] Integer overflow in size calculation

**CWE-190** | `scripts/config/symbol.c` line 910

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
tmp = realloc(sym_match_arr, size * sizeof(struct sym_match));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 88. [HIGH] Integer overflow in size calculation

**CWE-190** | `scripts/config/symbol.c` line 925

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
sym_arr = malloc((cnt+1) * sizeof(struct symbol *));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 89. [HIGH] Use-after-free pattern

**CWE-416** | `scripts/config/symbol.c` line 933

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
/* sym_match_arr can be NULL if no match, but free(NULL) is OK */
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 90. [HIGH] Use-after-free pattern

**CWE-416** | `scripts/config/symbol.c` line 934

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(sym_match_arr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 91. [HIGH] Missing NULL check after allocation

**CWE-476** | `scripts/config/symbol.c` line 654

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
sym->def[S_DEF_USER].val = val = xmalloc(size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 92. [HIGH] Missing NULL check after allocation

**CWE-476** | `scripts/config/symbol.c` line 658

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
sym->def[S_DEF_USER].val = val = xmalloc(size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 93. [HIGH] Missing NULL check after allocation

**CWE-476** | `scripts/config/symbol.c` line 807

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
new_name = xstrdup(name);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 94. [HIGH] Missing NULL check after allocation

**CWE-476** | `scripts/config/symbol.c` line 813

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
symbol = xmalloc(sizeof(*symbol));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 95. [HIGH] Missing NULL check after allocation

**CWE-476** | `scripts/config/symbol.c` line 910

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
tmp = realloc(sym_match_arr, size * sizeof(struct sym_match));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 96. [HIGH] Missing NULL check after allocation

**CWE-476** | `scripts/config/symbol.c` line 925

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
sym_arr = malloc((cnt+1) * sizeof(struct symbol *));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 97. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/config/swconfig/src/uci.c` line 240

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(settings);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 98. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/network/config/swconfig/src/uci.c` line 96

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
setting = malloc(sizeof(struct swlib_setting));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 99. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `package/network/services/ead/src/tinysrp/tphrase.c` line 148

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(bakfile, "%s.bak", pwname);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 100. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `package/network/services/ead/src/tinysrp/tphrase.c` line 149

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(bakfile2, "%s.sav", pwname);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 101. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/tinysrp/tphrase.c` line 144

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bakfile);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 102. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/tinysrp/tphrase.c` line 154

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bakfile);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 103. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/tinysrp/tphrase.c` line 155

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bakfile2);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 104. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/tinysrp/tphrase.c` line 173

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bakfile);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 105. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/tinysrp/tphrase.c` line 174

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bakfile2);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 106. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/tinysrp/tphrase.c` line 178

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bakfile);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 107. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/tinysrp/tphrase.c` line 179

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bakfile2);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 108. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/tinysrp/tphrase.c` line 189

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bakfile);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 109. [HIGH] Use-after-free pattern

**CWE-416** | `package/network/services/ead/src/tinysrp/tphrase.c` line 190

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bakfile2);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 110. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `package/system/mtd/src/imagetag.c` line 219

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(&tag->root_length[0], "%u", 0);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 111. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `package/system/mtd/src/imagetag.c` line 367

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(&tag->root_length[0], "%u", 0);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 112. [HIGH] Integer overflow in size calculation

**CWE-190** | `package/system/mtd/src/imagetag.c` line 140

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
newstr = calloc(len + 1, sizeof(char));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 113. [HIGH] Use-after-free pattern

**CWE-416** | `package/system/mtd/src/imagetag.c` line 144

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(newstr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 114. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/system/mtd/src/imagetag.c` line 140

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
newstr = calloc(len + 1, sizeof(char));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 115. [HIGH] Missing NULL check after allocation

**CWE-476** | `package/system/mtd/src/imagetag.c` line 321

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
buf = malloc(erasesize);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 116. [HIGH] Use-after-free pattern

**CWE-416** | `tools/padjffs2/src/padjffs2.c` line 133

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 117. [HIGH] Missing NULL check after allocation

**CWE-476** | `tools/padjffs2/src/padjffs2.c` line 56

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
buf = malloc(BUF_SIZE);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 118. [CRITICAL] Format string vulnerability

**CWE-134** | `scripts/config/nconf.c` line 555

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
vsnprintf(k_menu_items[items_num].str,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 119. [CRITICAL] Format string vulnerability

**CWE-134** | `scripts/config/nconf.c` line 589

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
vsnprintf(new_str, sizeof(new_str), fmt, ap);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 120. [HIGH] Use-after-free pattern

**CWE-416** | `scripts/config/nconf.c` line 806

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(sym_arr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---
