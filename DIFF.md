# DIFF format

**This document is an archived old one. Please refer to https://www.3dbrew.org/wiki/DISA_and_DIFF for the newest one.**

## Scope of This Documentation
This documentation describes the DIFF container format that is used for various purposes in 3DS SD/NAND filesystem

However, this documentation only describe plaintext DIFF format. Any encryption layer on top of it, such as SD file encryption or NAND partition encryption, is not covered. this documentation doesn't cover the file format inside the container either, because its format varies for different purposes. For the detail of different inner formats, please refer to their own documentation.

Generally speaking, consider DIFF format as a container of an arbitrary file. The only purpose of this container format is to provide verification and atomic I/O.

Note that it was a convention to call DIFF container "extdata file". This is not encouraged here, however, and the term "extdata" is used exclusively for those _DIFF groups_ stored in `nand/.../extdata/` or `sdmc/.../extdata/`, which form their own filesystem and can be accessed using archive ID `0x00000006` or `0x00000007`. Please refer to [Extdata](EXTDATA.md) for more details.

The DIFF container is known used for storing following contents:
 - Extdata contents
   - VSXE filesystem metadata (`00000001` file)
   - Extdata subfiles (other numbered files in extdata)
   - QUOT file (`Quota.dat` file)
 - Title database files
   - `ticket.db`
   - `certs.db`
   - `title.db`
   - `import.db`
   - `tmp_t.db`
   - `tmp_i.db`

## General Rule
- All fields are little-endian
- " :thinking: " is put next to unfinished/unconfirmed thing

## Overview of a Save file
A DIFF file consists of the following components
 - AES CMAC Header
 - DIFF Header
 - Two Partition Descriptors
 - Partition

Note:
 - Among the two partition descriptors, only one is active at one time. For a new-created file, it is possible that the inactive one contains invalid data.

## AES CMAC Header
 _TODO_ :thinking:

## DIFF Header
The DIFF header is located at 0x100 in the DIFF file image.

 |Offset|Length|Description|
 |-|-|-|
 |0x00|4|Magic "DIFF"|
 |0x04|4|Magic 0x30000|
 |0x08|8|Secondary partition descriptor offset|
 |0x10|8|Primary partition descriptor offset|
 |0x18|8|Partition descriptor size|
 |0x20|8|Partition offset|
 |0x28|8|Partition size|
 |0x30|4|Active descriptor, 0 = primary, 1 = secondary|
 |0x34|0x20|SHA-256 over the active descriptor|
 |0x54|8|Unique DIFF identifier|
 |0x5C|0xA4|Unused, might contain leftover data|

This header defines the rest components of the file. All offsets in this header is relative to the beginning of the file.

See [Extdata](EXTDATA.md) for its usage of the unique identifier field. For title database files, this field is zero.

## Partition Descriptor
A partition descriptor contains contains the following components:
 - DIFI header
 - IVFC descriptor
 - DPFS descriptor
 - Partition Hash

These components function in exactly the same way as those in
[DISA file](DISA.md#Partition_Table_&_Partition_Entry).

## Partition
Still the same way as [DISA file](DISA.md#Partition), except that DIFF only has one partition. Note that this partition can be a DATA partition (meaning that IVFC level 4 is outside the DPFS tree). Use the flag in DIFI header to identify this case.

## Recap of How to Extract Files From a DIFF file
 - Find the active partition table and the partition(s).
 - Unwrap DPFS tree of partition(s) by reconstructing active data.
 - Unwrap IVFC tree. Either take out level 4 directly, or, better, verify all the hashes and poison the data that is not properly hashed.
 - For DATA partition, since its IVFC level 4 is out side DPFS tree, the DPFS unwrapping step can be skipped. However, if one wants to poison the unhashed data, DPFS tree still need to be unwrapped to get the first three levels of IVFC tree.
 - Now you get IVFC level 4 as the inner image. Proceed to decode it according to its own format spec.

## Recap of Chain of Trust
 - CMAC header verifies DIFF header
 - DIFF header verifies partition descriptor
 - Partition descriptor verifies level 1 of its IVFC tree
 - Each IVFC level verifies the next level, until the level 4, which is the inner image.
