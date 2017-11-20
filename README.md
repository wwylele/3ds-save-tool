3DS Save File Extraction Tools & Documentation
----

These are tools parsing save (DISA file) and extdata (DIFF file) and extracting files from them. There is also documentation for these two
formats (_TODO: actually write something about DIFF_). Note that these tools can only parse decrypted files.

Required: python 3

Usage:
 - `python disa-extract.py <DISA File> [Output dir]`

    Prints information of the `<DISA File>` and extract its sub files to `[Output dir]` if given.
 - `python diff-extract.py <DIFF File> [Output file]`

    Prints information of the single `<DIFF File>` and extract its content to `[Output file]` if given.

 - `python diff-extract.py <Extdata dir> [Output dir]`

    Prints information of extdata stored in `<Extdata dir>` (the directory `extdata/<ExtdataID-High>/<ExtdataID-low>/00000000`) and extract its sub files to `[Output dir]` if given.
