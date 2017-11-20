# Python 3

import os
import os.path
import struct
import sys
import hashlib

import difi
import savefilesystem


def unwrapDIFF(filePath, expectedUniqueId=None):
    diff = open(filePath, 'rb')

    # Reads DIFF header
    diff.seek(0x100, os.SEEK_SET)
    DIFF, ver, \
        secPartTableOff, priPartTableOff, partTableSize, \
        partOff, partSize, \
        activeTable, tableHash, uniqueId, \
        = struct.unpack('<IIQQQQQI32sQ', diff.read(0x5C))

    if expectedUniqueId is not None:
        if expectedUniqueId != uniqueId:
            print("Warning: unique ID mismatch")

    if DIFF != 0x46464944:
        print("Error: Not a DIFF format")
        exit(1)

    if ver != 0x00030000:
        print("Error: Wrong DIFF version")
        exit(1)

    if activeTable == 0:
        partTableOff = priPartTableOff
    elif activeTable == 1:
        partTableOff = secPartTableOff
    else:
        print("Error: Wrong active table ID %d" % activeTable)
        exit(1)

    # Verify partition table hash
    diff.seek(partTableOff, os.SEEK_SET)
    partTable = diff.read(partTableSize)
    if hashlib.sha256(partTable).digest() != tableHash:
        print("Error: Partition table hash mismatch!")
        exit(1)

    # Reads and unwraps partition
    diff.seek(partOff, os.SEEK_SET)
    part = diff.read(partSize)
    image, isData = difi.unwrap(partTable, part)
    if isData:
        print("Info: this is a DATA partition")

    diff.close()
    return image


def trimBytes(bs):
    """ Trims trailing zeros in a byte string """
    n = bs.find(b'\0')
    if n != -1:
        return bs[:n]
    return bs


def extractExtdata(extdataDir, outputDir):
    def extdataFileById(id):
        return os.path.join(extdataDir, "%08x" % id)
    vsxe = unwrapDIFF(extdataFileById(1))
    # Reads VSXE header
    VSXE, ver, filesystemHeaderOff, imageSize, imageBlockSize, x00, \
        unk1, recentAction, unk2, recentId, unk3, recentPath \
        = struct.unpack('<IIQQIIQIIII256s', vsxe[0:0x138])

    if VSXE != 0x45585356:
        print("Error: Wrong VSXE magic")
        exit(1)

    if ver != 0x00030000:
        print("Error: Wrong VSXE version")
        exit(1)

    if x00 != 0:
        print("Warning: unknown 0 = 0x%X in VSXE header" % x00)

    print("Info: unk1 = %d" % unk1)
    print("Info: recent action = %d" % recentAction)
    print("Info: unk2 = %d" % unk2)
    print("Info: recent ID = %d" % recentId)
    print("Info: unk3 = %d" % unk3)
    print("Info: recentPath = %s" % trimBytes(recentPath).decode())

    fsHeader = savefilesystem.Header(
        vsxe[filesystemHeaderOff:filesystemHeaderOff + 0x68], False)

    # parse hash tables
    dirHashTable = savefilesystem.getHashTable(fsHeader.dirHashTableOff,
                                               fsHeader.dirHashTableSize,
                                               vsxe)

    fileHashTable = savefilesystem.getHashTable(fsHeader.fileHashTableOff,
                                                fsHeader.fileHashTableSize,
                                                vsxe)

    # Parses directory & file entry table
    dirList = savefilesystem.getDirList(
        fsHeader.dirTableOff, vsxe)

    print("Directory list:")
    for i in range(len(dirList)):
        dirList[i].printEntry(i, len(dirList))

    fileList = savefilesystem.getFileList(
        fsHeader.fileTableOff, vsxe)

    print("File list:")
    for i in range(len(fileList)):
        fileList[i].printEntryAsExtdata(i, len(fileList))

    # Verifies directory & file hash table
    print("Verifying directory hash table")
    savefilesystem.verifyHashTable(dirHashTable, dirList)
    print("Verifying file hash table")
    savefilesystem.verifyHashTable(fileHashTable, fileList)

    def extFileDumper(fileEntry, file, index):
        print("Extracting %s" % fileEntry.getName())
        content = unwrapDIFF(extdataFileById(index + 1), fileEntry.uniqueId)
        if file is not None:
            file.write(content)

    savefilesystem.extractAll(dirList, fileList, outputDir, extFileDumper)

    print("Finished!")


def main():
    if len(sys.argv) < 2:
        print("Usage: %s [DIFF file] <output file>" % sys.argv[0])
        print("   or: %s [extdata dir] <output dir>" % sys.argv[0])
        exit(1)

    if len(sys.argv) > 2:
        output = sys.argv[2]
    else:
        output = None
        print("No output file/directory given. Will only do data checking.")

    if os.path.isdir(sys.argv[1]):
        extractExtdata(sys.argv[1], output)
        exit(0)

    image = unwrapDIFF(sys.argv[1])

    if output is not None:
        output_file = open(output, "wb")
        output_file.write(image)
        output_file.close()


if __name__ == "__main__":
    main()
