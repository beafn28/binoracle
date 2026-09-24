# Cortex-M Virtual Disk Upgrade Firmware's Built-In Mask Rotation/XOR Encapsulation

## Scenario Classification

Binary / Firmware Reverse Engineering

## Target Overview

Analyze a Cortex-M debugging tool upgrade package, identify its custom encapsulation algorithm, and distinguish the application image within the upgrade package from the USB Mass Storage bootloader resident in the device.

## Scope Summary (De-Identified)

- auth_basis: own_system
- network_profile: authorized_target_only (Actual offline sample)
- asset_types: [firmware_container, cortex_m_application, usb_msc_updater]

## Roles

- lead_role: lead
- specialists: [cre, cce, doc]

## Complete Execution Chain

1. Perform length, entropy, tail cycle, and block statistics on the original package to discover that the file size is a multiple of 1 KiB with a 7-byte tail cycle.
2. Enumerate byte-by-byte rotation/XOR relationships starting from the Cortex-M vector table constraints to restore the first block.
3. Discover that each 1 KiB block resets the rotation phase, and the first byte in each block serves as its XOR mask.
4. Decode each block using `P[i] = ROR8(C[i], (3*i) mod 7) XOR C[0]` and reconstruct the original package with an inverse transformation byte-by-byte.
5. Cross-validate with a second, same-series official firmware to recover valid vector tables, version strings, and readable code; all block first bytes are zero.
6. Derive the application/bootloader boundary using vector target addresses and file offsets to confirm that no prior bootloader is included in the upgrade package.
7. Reconstruct the external process of copying MSC files to Flash write from official "enter bootloader / simulate USB" instructions, marking internal bootloader details as inferred.
8. Test common CRCs, STM32 hardware CRCs, Adler, and adder for the 32-bit tail field; none match, so retain it as an unresolved integrity field.

## Evidence Summary (De-Identified)

| E-id | source_type | reusable_command_mode | associated Finding |
|---|---|---|---|
| E-001 | local_binary | block entropy, cycle tail, vector constraint | F-001 |
| E-002 | derived_algorithm | first block mask + ROR/XOR + round-trip | F-001 |
| E-003 | static_analysis | vector, string, Thumb disassembly | F-002 |

## Finding / Path Summary

- top_finding: Partially high entropy firmware packages are only 1 KiB reset mask/ROR/XOR obfuscation; should not be prematurely classified as standard encryption.
- path_type: solve/callflow
- path_one_liner: cycle and block structure → vector crib → first block recovery → block boundary resets → cross-validation with second firmware → application/bootloader boundaries → external MSC upgrade process.

## Pitfalls

| Issue | Reason | Solution | Time |
|---|---|---|---|
| Used "unrotated bytes after decoding" as mask for some blocks, resulting in garbled text | Common plaintext byte within dense-text blocks is not necessarily zero | Compare block first-byte models; garbling disappears and reappears with the second firmware | Medium |
| Only XOR/rotation at the beginning of a full file is valid | Rotation phase and mask reset every 1 KiB | Explicitly chunk by `0x400` | Low |
| IDA and radare2 failed to start | No IDA path on local machine, r2 bootstrap installer anomaly | Use Python + Capstone to verify Cortex-M entry point | Medium |
| Assumed the end is a standard CRC32 based on seeing "firmware_crc32" | String is metadata key; cannot prove package tail parameters and coverage range | Exclude common families after system exclusion and retain unknown without forcing naming | Low |

## Toolchain Discoveries

- Python is suitable for bitwise transformation enumeration, round-trip validation, and invariant cross-sample verification.
- Capstone can validate Cortex-M vector entry and local control flow when IDA/Ghidra/radare2 are missing.
- String recovery quality is a strong signal to compare candidate mask models; however, they must be combined with absolute pointers and disassembly to avoid relying solely on "appears readable."

## Key Algorithms

```text
block_size = 0x400
mask = packed_block[0]
rotation(i) = (3 * i) mod 7
plain[i] = ROR8(packed[i], rotation(i)) XOR mask
```

Inverse transformation uses `ROL8`; validation standard is byte-by-byte equality of encoded results with the original package.

## Recommendations for This Package

- Add a check in the firmware-pentest container identification phase to verify if block boundaries are reset.
- Prioritize testing first and last bytes as self-describing masks when an heuristic zero-byte crib fails on some blocks.
- Report bootloader internal behavior separately from protocol-layer behaviors when the upgrade package only contains applications.

## Reusable Patterns

1. Check for cycle resets at common Flash/transfer block sizes (256, 512, 1024, 2048, 4096).
2. Use Cortex-M SRAM stack pointer and Thumb Reset Vector as strong crib.
3. Execute three validations on each candidate model: full file round-trip, cross-validation with second sample, and absolute address references match.
4. Do not treat variable names or strings as algorithm evidence when common checks fail for the tail field.

## Evolution Actions

- [x] Added field-journal records
- [x] Updated field-journal index
- [ ] Updated routing matrix
- [ ] Updated tool-index
- [ ] Updated bootstrap-manifest
- [ ] Updated sub skill documentation

## Environment Information

- OS: Windows
- Tool Version: Python 3.12, Capstone 5.0.6
- Target Platform/Version: Cortex-M3 / F1 compatible MCU, application firmware

## De-Sensitization Check

- [x] No real domain names, IPs, credentials, tokens, PII (Personally Identifiable Information)
- [x] No absolute local paths
- [x] No sample file body and sample hash values
- [x] Vendor, product, and version information have been generalized