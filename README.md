3DS Save File Extraction Tools
----

These are tools parsing save (DISA file) and extdata (DIFF file) and extracting files from them. The tools work with decrypted files. They also support encrypted SD files if necessary keys are provided. Create file `secrets.py` from the template `secrets.py.template` to provide your keys.

This repo also contains some old documentations of the save data format. They were migrated to 3dbrew and the version here is outdated and unmaintained. Please refer to the pages on 3dbrew instead.


Required: python 3

Usage:
 - `python disa-extract.py <DISA File> [Output dir]`

    Prints information of the `<DISA File>` and extract its sub files to `[Output dir]` if given.
 - `python diff-extract.py <DIFF File> [Output file]`

    Prints information of the single `<DIFF File>` and extract its content to `[Output file]` if given.

 - `python diff-extract.py <Extdata dir> [Output dir]`

    Prints information of extdata stored in `<Extdata dir>` (the directory `extdata/<ExtdataID-High>/<ExtdataID-low>`) and extract its sub files to `[Output dir]` if given.

For more advanced usage, see the output by running the scripts without arguments.
