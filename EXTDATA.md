# 3DS Extdata Format

## Scope of This Documentation

This documentation describes the special save format, called "extdata" for 3DS contained in SD and NAND. It does not cover normal save data or any other type of saves. All extdata uses DIFF container format, which is described [here](DIFF.md), and this documentation will skip the DIFF container part, and go directly into the inner data format specific to extdata.

## General Rule
 - All fields are little-endian
 - All "padding" fields can contain random data from uninitialized memory unless marked as "?" or otherwise stated.
 - " :thinking: " is put next to unfinished/unconfirmed thing

## Overview of an Extdata

An extdata is a group of files that forms an internal filesystem, which games can access transparently. Each extdata stores under `nand/data/<ID>/extdata/00048000/<ExtdataID>/` or `sdmc/Nintendo 3DS/<ID0>/<ID1>/extdata/00000000/<ExtdataID>/ `, and forms the following structure
```
 <ExtdataID>
 ├── Quota.dat (optional, unknown usage)
 └── 00000000
     ├── 00000001 (VSXE filesystem metadata)
     ├── 00000002 (Extdata subfile)
     ├── 00000003 (Same as above)
     ...     
```
All files in this strucutre are [DIFF containers](DIFF.md). Extdata subfiles (`00000002` and above) contains raw extdata file data. VSXE filesystem metadata (`00000001`) contains information of the actual file names of the subfiles, and the directory hierarchy of them.

## VSXE Filesystem Metadata
The inner data of `00000001` DIFF container consists of the following components
- VSXE header
- Directory Hash Table
- File Hash Table
- File Allocation Table
- Data region
  - Directory Entry Table
  - File Entry Table

### VSXE Header
|Offset|Length|Description|
|-|-|-|
|0x00|4|Magic "VSXE"|
|0x04|4|Magic 0x30000|
|0x08|8|Filesystem Information offset (0x138)|
|0x10|8|Image size in blocks|
|0x18|4/8?|Image block size|
|0x1C|4|Unknown:thinking:|
|0x20|8|Unknown:thinking:|
|0x28|8|Recent action:thinking:|
|0x30|8|Recent file ID:thinking:|
|0x38|0x100|Recent file path|
|||Below is Filesystem Information, most of which is assumed following the same layout as [SAVE header](DISA.md#SAVE_Header), but it is hard to confirm due to the fact that most of these fields have small values and are hard to change.|
|0x138|4|Unknown:thinking:|
|0x13C|4|Data region block size|
|0x140|8|Directory hash table offset|
|0x148|4|Directory hash table bucket count|
|0x14C|4|Padding|
|0x150|8|File hash table offset|
|0x158|4|File hash table bucket count|
|0x15C|4|Padding|
|0x160|8|File allocation table offset|
|0x168|4|File allocation table entry count|
|0x16C|4|Padding|
|0x170|8|Data region offset (if no DATA image)|
|0x178|4|Data region block count (= File allocation table entry count)|
|0x17C|4|Padding|
|0x180|4|Directory entry table starting block|
|0x184|4|Directory entry table block count|
|0x188|4|Maximum directory count|
|0x18C|4|Padding|
|0x190|4|File entry table starting block|
|0x194|4|File entry table block count|
|0x198|4|Maximum file count|
|0x19C|4|Padding|

 - All "offsets" are relative to the beginning of VSXE image. All "starting block index" are relative to the beginning of data region.

 :thinking: Question: what are those "recent xxx" used for?

### File Allocation Table & Data Region
These function in the same way as those in [SAVE image](DISA.md#File_Allocation_Table). However, the only two "files" allocated in the data region is the directory entry table and file entry table, so the data region is usually pretty small, and the file allocation table is unchanged once created and has no free blocks.

### Directory Hash Table & File Hash Table
Same way as those in [SAVE image](DISA.md#Directory_Hash_Table_&_File_Hash_Table).

### Directory Entry Table
Same way as the one in [SAVE image](DISA.md#Directory_Entry_Table).

### File Entry Table
This is very similar to the one in [SAVE image](DISA.md#File_Entry_Table). However, the (non-dummy) file entry is a little bit modified:

|Offset|Length|Description|
|-|-|-|
|0x00|4|Parent directory index in directory entry table|
|0x04|16|File name|
|0x14|4|Next sibling file index. 0 if this is the last one|
|0x18|4|Padding|
|0x1C|4|~~First block index in data region~~ **Always 0x80000000 because unused**|
|0x20|8|~~File size~~ **Unique DIFF identifier**|
|0x28|4|Unknown :thinking:|
|0x2C|4|Index of the next file in the same hash table bucket. 0 if this is the last one|

Each non-dummy file entry corresponds to a numbered file (`00000002` etc) in extdata structure. The number in file name is the hex of `entry_index + 1` (counting the first dummy entry as the `entry_index = 0`). When mounting extdata, the unique DIFF identifier is used to match the ID stored in subfile [DIFF header](DIFF.md#DIFF_Header). If the ID doesn't match, mounting will fail.
