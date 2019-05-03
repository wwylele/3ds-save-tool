#!/usr/bin/env python3

import os
import struct
import sys

import savefilesystem


def main():
    if len(sys.argv) < 2:
        print("Usage: %s input [output]" % sys.argv[0])
        exit(1)

    inputPath = None
    outputPath = None

    i = 1
    while i < len(sys.argv):
        if inputPath is None:
            inputPath = sys.argv[i]
        else:
            outputPath = sys.argv[i]
        i += 1

    if outputPath is None:
        print("No output directory given. Will only do data checking.")

    tick = open(inputPath, 'rb')
    TICK, a, b, c = struct.unpack('<IIII', tick.read(0x10))
    if TICK != 0x4B434954:
        print("Error: Not a TICK format")
        exit(1)

    print("Info: Pre Header 0x%08X 0x%08X 0x%08X" % (a, b, c))

    dbri = tick.read()
    tick.close()

    BDRI, ver, filesystemHeaderOff, imageSize, imageBlockSize, x00 \
        = struct.unpack('<IIQQII', dbri[0:0x20])

    if BDRI != 0x49524442:
        print("Error: Wrong BDRI magic")
        exit(1)

    if ver != 0x00030000:
        print("Error: Wrong BDRI version")
        exit(1)

    if x00 != 0:
        print("Warning: unknown 0 = 0x%X in BDRI header" % x00)

    fsHeader = savefilesystem.Header(
        dbri[filesystemHeaderOff: filesystemHeaderOff+0x68], False)

    dataRegion = dbri[
        fsHeader.dataRegionOff: fsHeader.dataRegionOff +
        fsHeader.dataRegionSize * fsHeader.blockSize]

    # Parses hash tables
    dirHashTable = savefilesystem.getHashTable(fsHeader.dirHashTableOff,
                                               fsHeader.dirHashTableSize,
                                               dbri)

    fileHashTable = savefilesystem.getHashTable(fsHeader.fileHashTableOff,
                                                fsHeader.fileHashTableSize,
                                                dbri)

    # Parses FAT
    fat = savefilesystem.FAT(fsHeader, dbri)

    # Parses directory & file entry table
    dirList = savefilesystem.getTdbDirList(
        fsHeader, dataRegion, fat)

    print("Directory list:")
    for i in range(len(dirList)):
        dirList[i].printEntry(i)

    fileList = savefilesystem.getTdbFileList(
        fsHeader, dataRegion, fat)

    print("File list:")
    for i in range(len(fileList)):
        fileList[i].printEntry(i)

    # Verifies directory & file hash table
    print("Verifying directory hash table")
    savefilesystem.verifyHashTable(dirHashTable, dirList)
    print("Verifying file hash table")
    savefilesystem.verifyHashTable(fileHashTable, fileList)

    # Walks through free blocks
    print("Walking through free blocks")
    fat.visitFreeBlock()

    def saveFileDumper(fileEntry, file, _):
        fileSize = fileEntry.size

        def blockDumper(index):
            nonlocal fileSize
            if fileSize == 0:
                print("Warning: excessive block")
                return
            tranSize = min(fileSize, fsHeader.blockSize)
            pos = index * fsHeader.blockSize
            if file is not None:
                file.write(dataRegion[pos: pos + tranSize])
            fileSize -= tranSize

        if fileSize != 0:
            fat.walk(fileEntry.blockIndex, blockDumper)
        if fileSize != 0:
            print("Warning: not enough block")

    print("Walking through files and dumping")
    savefilesystem.extractAll(dirList, fileList, outputPath, saveFileDumper)

    fat.allVisited()

    print("Finished!")


if __name__ == "__main__":
    main()
