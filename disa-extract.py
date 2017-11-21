# Python 3

import os
import os.path
import struct
import sys
import hashlib

import difi
import savefilesystem


def main():
    if len(sys.argv) < 2:
        print("Usage: %s [DISA file] <output dir>" % sys.argv[0])
        exit(1)

    disa = open(sys.argv[1], 'rb')

    if len(sys.argv) > 2:
        output_dir = sys.argv[2]
    else:
        output_dir = None
        print("No output directory given. Will only do data checking.")

    # Reads DISA header
    disa.seek(0x100, os.SEEK_SET)
    DISA, ver, \
        partCount, secPartTableOff, priPartTableOff, partTableSize, \
        savePartEntryOff, savePartEntrySize, \
        dataPartEntryOff, dataPartEntrySize, \
        savePartOff, savePartSize, \
        dataPartOff, dataPartSize, \
        activeTable, unk1, unk2 = struct.unpack(
            '<IIQQQQQQQQQQQQBBH', disa.read(0x6C))

    if DISA != 0x41534944:
        print("Error: Not a DISA format")
        exit(1)

    if ver != 0x00040000:
        print("Error: Wrong DISA version")
        exit(1)

    if partCount == 1:
        hasData = False
        print("Info: No DATA partition")
    elif partCount == 2:
        hasData = True
        print("Info: Has DATA partition")
    else:
        print("Error: Wrong partition count %d" % parCount)
        exit(1)

    if activeTable == 0:
        partTableOff = priPartTableOff
    elif activeTable == 1:
        partTableOff = secPartTableOff
    else:
        print("Error: Wrong active table ID %d" % activeTable)
        exit(1)

    Unknown = unk1 + unk2 * 256
    if Unknown != 0:
        print("Warning: Unknown = 0x%X" % Unknown)

    # Verify partition table hash
    tableHash = disa.read(0x20)
    disa.seek(partTableOff, os.SEEK_SET)
    partTable = disa.read(partTableSize)

    if hashlib.sha256(partTable).digest() != tableHash:
        print("Error: Partition table hash mismatch!")
        exit(1)

    # Reads and unwraps SAVE image
    saveEntry = partTable[savePartEntryOff:
                          savePartEntryOff + savePartEntrySize]
    disa.seek(savePartOff, os.SEEK_SET)
    savePart = disa.read(savePartSize)
    saveImage, saveImageIsData = difi.unwrap(saveEntry, savePart)
    if saveImageIsData:
        print("Warning: SAVE partition is marked as DATA")

    # Reads and unwraps DATA image
    if hasData:
        dataEntry = partTable[dataPartEntryOff:
                              dataPartEntryOff + dataPartEntrySize]
        disa.seek(dataPartOff, os.SEEK_SET)
        dataPart = disa.read(dataPartSize)
        dataRegion, dataRegionIsData = difi.unwrap(dataEntry, dataPart)
        if not dataRegionIsData:
            print("Warning: DATA partition is not marked as DATA")

    disa.close()

    # Reads SAVE header
    SAVE, ver, filesystemHeaderOff, imageSize, imageBlockSize, x00 \
        = struct.unpack('<IIQQII', saveImage[0:0x20])

    if SAVE != 0x45564153:
        print("Error: Wrong SAVE magic")
        exit(1)

    if ver != 0x00040000:
        print("Error: Wrong SAVE version")
        exit(1)

    if x00 != 0:
        print("Warning: unknown 0 = 0x%X in SAVE header" % x00)

    fsHeader = savefilesystem.Header(
        saveImage[filesystemHeaderOff:filesystemHeaderOff + 0x68], hasData)

    if not hasData:
        dataRegion = saveImage[
            fsHeader.dataRegionOff: fsHeader.dataRegionOff +
            fsHeader.dataRegionSize * fsHeader.blockSize]

    # parse hash tables
    dirHashTable = savefilesystem.getHashTable(fsHeader.dirHashTableOff,
                                               fsHeader.dirHashTableSize,
                                               saveImage)

    fileHashTable = savefilesystem.getHashTable(fsHeader.fileHashTableOff,
                                                fsHeader.fileHashTableSize,
                                                saveImage)

    # Parses directory & file entry table
    dirList = savefilesystem.getDirList(
        fsHeader.dirTableOff, saveImage)

    print("Directory list:")
    for i in range(len(dirList)):
        dirList[i].printEntry(i)

    fileList = savefilesystem.getFileList(
        fsHeader.fileTableOff, saveImage)

    print("File list:")
    for i in range(len(fileList)):
        fileList[i].printEntryAsSave(i)

    # Verifies directory & file hash table
    print("Verifying directory hash table")
    savefilesystem.verifyHashTable(dirHashTable, dirList)
    print("Verifying file hash table")
    savefilesystem.verifyHashTable(fileHashTable, fileList)

    # Parses FAT
    fatList = []
    for i in range(1, fsHeader.fatSize + 1):  # skip the first entry
        fatList.append(savefilesystem.FatEntry(
            saveImage[fsHeader.fatOff + i * 8: fsHeader.fatOff + (i + 1) * 8]))

    def saveFileDumper(fileEntry, file, _):
        fileSize = fileEntry.size
        if fileSize != 0:
            currentBlock = fileEntry.blockIndex
            previousBlock = -1
            if not fatList[currentBlock].start:
                print("Warning: file start at non-starting block")
            while True:
                if fatList[currentBlock].u != previousBlock:
                    print("Warning: previous index mismatch")

                if fatList[currentBlock].expand:
                    tranSize = fatList[currentBlock + 1].v - \
                        fatList[currentBlock + 1].u + 1
                else:
                    tranSize = 1

                tranSize *= fsHeader.blockSize
                tranSize = min(fileSize, tranSize)
                pos = currentBlock * fsHeader.blockSize
                if file is not None:
                    file.write(dataRegion[pos: pos + tranSize])
                fileSize -= tranSize
                if fileSize <= 0:
                    if fatList[currentBlock].v != -1:
                        print("Warning: file end before block end")
                    break
                previousBlock = currentBlock
                currentBlock = fatList[currentBlock].v

    savefilesystem.extractAll(dirList, fileList, output_dir, saveFileDumper)

    print("Finished!")


if __name__ == "__main__":
    main()
