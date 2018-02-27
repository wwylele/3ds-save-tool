3DS Save File Extraction Tools
----

These are tools parsing save (DISA file) and extdata (DIFF file) and extracting files from them. The tools work with decrypted files. They also support encrypted SD files if necessary keys are provided. Create file `secrets.py` from the template `secrets.py.template` to provide your keys.

This repo also contains some old documentations of the save data format. They were migrated to 3dbrew and the version here is outdated and unmaintained. Please refer to the pages on 3dbrew instead.


Required: python 3

## Usage

Some typical usage of the tools is listed here. These commands assume that you already have python 3 in the system PATH. All the file/folder paths in the examples are just a hint of where you can find them. "nand" is where you have the decrypted & mounted NAND. "sdmc" is where the SD card is mounted. "output" is where you store the extracted files. "0123456789abcdef0123456789abcdef" is a random ID (id0) that you will have a different one from your 3DS, and "fedcba9876543210fedcba9876543210" as well (id1).

The general command form is `python disa/diff-extract.py INPUT OUTPUT OPTIONS`. In all examples below, the output path can be omitted, in which case the tool will only print the information of the input file(s) without extracting the data.

For more advanced usage, see the output by running the scripts without arguments.

### Extracting save data

 ```
 python disa-extract.py "nand/data/0123456789abcdef0123456789abcdef/sysdata/00010026/00000000" "output/sysdata-00010026"
 ```
 This extracts system save data 00010026 (CECD data) from NAND to folder `output/sysdata-00010026`.

----
 ```
 python disa-extract.py "sdmc/gm9out/00000001.sav" "output/savedata"
 ```
 This extracts game save data that has been decrypted using GodMode9 (or any other tools) to folder `output/savedata`.

----
 ```
 python disa-extract.py "sdmc/Nintendo 3DS/0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210/title/00040000/00164800/data/00000001.sav" "output/pokemon-sun-save" -sd -decrypt -id 0004000000164800
 ```
 This extracts encrypted save data of Pokemon Sun from SD card to folder `output/pokemon-sun-save`. Some requirement and notes of this command:
  - You need to create `secrets.py` from `secrets.py.template` and fill in the keys.
  - The parameter `-id XXXXXXXXXXXXXXXX` is the game title ID in 16-digit hex and must match the game.
  - An additional library `Cryptodome` is needed.
  - If the script outputs "Error: CMAC mismatch.", it means that some of the keys or the title ID is incorrect.

 ----

### Extracting extdata

 ```
 python diff-extract.py "nand/data/0123456789abcdef0123456789abcdef/extdata/00048000/f000000b" "output/sysextdata-f000000b"
 ```
 This extracts system extdata 00048000f000000b (contains coins info etc.) from NAND to folder `output/sysextdata-f000000b`.

 Note：do **NOT** enter the `00000000` folder inside `f000000b`.

----

 ```
 python diff-extract.py "sdmc/gm9out/12345678" "output/extdata"
 ```
 This extracts extdata that has been decrypted using GodMode9 (or any other tools) to folder `output/extdata`. When using GodMode9, please copy the **entire** folder `sdmc/Nintendo 3DS/<id0>/<id1>/extdata/00000000/<id>/` (and do **NOT** enter the inner folder `00000000`!) to somewhere else in SD card (`gm9out/` for example).

----

 ```
 python diff-extract.py "sdmc/Nintendo 3DS/0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210/00000000/00001554" "output/mhx-save" -decrypt -id 00001554
 ```
 This extracts encrypted game extdata of Monster Hunter X from SD card to folder `output/mhx-save`. Some requirement and notes of this command:
  - You need to create `secrets.py` from `secrets.py.template` and fill in the keys.
  - The parameter `-id XXXXXXXX` is the extdata ID in 8-digit hex and must match the game. It is usually similar to the game title ID.
  - An additional library `Cryptodome` is needed.
  - If the script outputs "Error: CMAC mismatch.", it means that some of the keys or the extdata ID is incorrect.

----

### Extracting single DIFF file (titledb file, extdata subfile etc.)


 ```
 python diff-extract.py "nand/dbs/ticket.db" "output/tickets"
 ```
 This extracts the ticket database file from NAND to folder `output/tickets`.

----

 ```
 python diff-extract.py "sdmc/gm9out/title.db" "output/titles"
 ```
 This extracts the title database file that has been decrypted using GodMode9 (or any other tools) from SD to folder `output/titles`.

----
 ```
 python diff-extract.py "sdmc/Nintendo 3DS/0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210/dbs/title.db" "output/tickets" -titledb -decrypt -id 2
 ```
 This extracts the encrypted title database file from SD to folder `output/tickets`. Some requirement and notes of this command:
  - You need to create `secrets.py` from `secrets.py.template` and fill in the keys.
  - The parameter `-id X` is title database ID: 2 for title.db and 3 for import.db.
  - An additional library `Cryptodome` is needed.
  - If the script outputs "Error: CMAC mismatch.", it means that some of the keys or the ID is incorrect.
