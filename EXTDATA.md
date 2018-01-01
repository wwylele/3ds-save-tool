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
 ├── 00000000
 │   ├── 00000001 (VSXE filesystem metadata)
 │   ├── 00000002 (Extdata subfile)
 │   ├── 00000003 (Same as above)
 │   ...
 ├── 00000001     (Only exists if there are excessive files)
 │   ├── 00000000 (00000001 directories and above can have the 00000000 subfile)
 │   ├── 00000001 (More subfiles)
 ...
```
All files in this strucuture are [DIFF containers](DIFF.md). File `Quota.dat` is observed only exists in NAND extdata. VSXE filesystem metadata (`00000000/00000001`) contains information of the actual file names of the subfiles, and the directory hierarchy of them. Other files are extdata subfiles, which contain raw extdata file data in its inner data.

## Quota File

The inner data of `Quota.dat` is 0x48 bytes with the following format. The exact function of this file is unclear.

|Offset|Length|Description|
|-|-|-|
|0x00|4|Magic "QUOT"|
|0x04|4|Magic 0x30000|
|0x08|4|Always 126. Probably physical directory capacity. See the next section for mor information.|
|...||The meaning of other fields is unknown|


## Physical Directory Capacity

A physical directory in an extdata (those `00000000` and `00000001` directories, not the virtual directories in the extdata filesystem) seems to have a maximum number of files it can contain. For SD extdata, this maximum number seems to be hard-coded as 126. For NAND extdata, the number is probably indicated by a field in Quota.dat, which is, again, always 126 as observed. 3DS FS tries to put all files in directory `00000000` as possible, and only when more than 126 files needed to add, a second directory `00000001` and so on are created. However, few extdata have such amount files to store (wwylele: _Super Mario Maker_ is a known one to have more than 126 files in its extdata), so the behavior lacks of use cases to confirm.

The number 126 is probably from some kind of other capacity of 128 with `"."` and `".."` entries reserved.

## VSXE Filesystem Metadata
The inner data of `00000000/00000001` DIFF container consists of the following components
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
|0x18|4|Image block size|
|0x1C|4|Padding|
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

Each non-dummy file entry corresponds to a numbered physical file (`00000001/00000002` etc) in extdata structure. The path to a physical file is generated by the following computation:
```
// See previous section about this capacity
const uint32_t physical_dir_capacity = 126;

// entry index is the index in the file entry table, with the first dummy entry as
// index = 0, which is never used for a real file.
// file_index = 1 is reserved for the VSXE Filesystem Metadata itself, so real files
// started from file_index = 1.
const uint32_t file_index = entry_index + 1;

const uint32_t high = file_index / physical_dir_capacity;
const uint32_t low = physical_dir_capacity % physical_dir_capacity;

char extdata_path[...]; // ".../extdata/00000000/<ExtdataID>"
char physical_path[...]; // output path
sprintf(physical_path, "%s/%08x/%08x", extdata_path, high, low);
```
When mounting extdata, the unique DIFF identifier is used to match the ID stored in subfile [DIFF header](DIFF.md#DIFF_Header). If the ID doesn't match, mounting will fail.
