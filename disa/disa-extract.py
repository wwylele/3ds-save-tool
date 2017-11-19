# Python 3

import os
import os.path
import struct
import sys
import hashlib

import difi


def trimBytes(bs):
    """ Trims trailing zeros in a byte string """
    n = bs.find(b'\0')
    if n != -1:
        return bs[:n]
    return bs


class HashableEntry(object):
    """ A common hash function for directory and file entries """

    def getHash(self):
        hash = self.parentIndex ^ 0x091A2B3C
        for i in range(4):
            hash = ((hash >> 1) | (hash << 31)) & 0xFFFFFFFF
            hash ^= self.name[i * 4]
            hash ^= self.name[i * 4 + 1] << 8
            hash ^= self.name[i * 4 + 2] << 16
            hash ^= self.name[i * 4 + 3] << 24
        return hash


class DirEntry(HashableEntry):
    """ Directory table entry """

    def __init__(self, raw):
        # Reads normal entry data
        self.parentIndex, self.name, \
            self.nextIndex, self.firstDirIndex, self.firstFileIndex, \
            self.unknown, self.nextCollision \
            = struct.unpack('<I16sIIIII', raw)

        if self.unknown != 0:
            print("Warning: unknown = %d" % unknown)

        # Reads dummy entry data
        self.count, self.maxCount, self.nextDummyIndex \
            = struct.unpack('<II28xI', raw)

    def getName(self):
        return trimBytes(self.name).decode()


class FileEntry(HashableEntry):
    """ File table entry """

    def __init__(self, raw):
        # Reads normal entry data
        self.parentIndex, self.name, \
            self.nextIndex, self.u1, self.blockIndex, self.size, \
            self.u2, self.nextCollision \
            = struct.unpack('<I16sIIIQII', raw)

        # Reads dummy entry data
        self.count, self.maxCount, self.nextDummyIndex \
            = struct.unpack('<II36xI', raw)

    def getName(self):
        return trimBytes(self.name).decode()


class FatEntry(object):
    """ FAT entry """

    def __init__(self, raw):
        self.u, self.v = struct.unpack('II', raw)
        if self.u >= 0x80000000:
            self.u -= 0x80000000
            self.start = True
        else:
            self.start = False
        if self.v >= 0x80000000:
            self.v -= 0x80000000
            self.expand = True
        else:
            self.expand = False

        # shift index to match block index
        self.u -= 1
        self.v -= 1


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
    SAVE, ver, x20, imageSize, imageBlockSize, x00, blockSize, \
        dirHashTableOff, dirHashTableSize, dirHashTableUnk, \
        fileHashTableOff, fileHashTableSize, fileHashTableUnk, \
        fatOff, fatSize, fatUnk, \
        dataRegionOff, dataRegionSize, dataRegionUnk, \
        = struct.unpack('<IIQQIQIQIIQIIQIIQII', saveImage[0:0x68])

    if SAVE != 0x45564153:
        print("Error: Wrong SAVE magic")
        exit(1)

    if ver != 0x00040000:
        print("Error: Wrong SAVE version")
        exit(1)

    if x20 != 0x20:
        print("Warning: unknown x20 = 0x%X" % x20)

    if x00 != 0:
        print("Warning: unknown 0 = 0x%X" % x00)

    print("Info: dirHashTableSize = %d" % dirHashTableSize)
    print("Info: dirHashTableUnk = %d" % dirHashTableUnk)
    print("Info: fileHashTableSize = %d" % fileHashTableSize)
    print("Info: fileHashTableUnk = %d" % fileHashTableUnk)
    print("Info: fatSize = %d" % fatSize)
    print("Info: fatUnk = %d" % fatUnk)
    print("Info: dataRegionSize = %d" % dataRegionSize)
    print("Info: dataRegionUnk = %d" % dataRegionUnk)
    if fatSize != dataRegionSize:
        printf("Warning: fatSize != dataRegionSize")

    dirHashTable = []
    for i in range(dirHashTableSize):
        dirHashTable.append(struct.unpack('<I', saveImage[
            dirHashTableOff + i * 4:dirHashTableOff + (i + 1) * 4])[0])

    fileHashTable = []
    for i in range(fileHashTableSize):
        fileHashTable.append(struct.unpack('<I', saveImage[
            fileHashTableOff + i * 4:fileHashTableOff + (i + 1) * 4])[0])

    if not hasData:
        dataRegion = saveImage[dataRegionOff: dataRegionOff +
                               dataRegionSize * blockSize]
        dirTableBlockIndex, dirTableBlockCount, dirMaxCount, dirUnk, \
            fileTableBlockIndex, fileTableBlockCount, fileMaxCount, fileUnk \
            = struct.unpack('<IIIIIIII', saveImage[0x68:0x88])
        dirTableBlockIndex *= blockSize
        dirTableBlockCount *= blockSize
        fileTableBlockIndex *= blockSize
        fileTableBlockCount *= blockSize
        dirTable = dataRegion[dirTableBlockIndex: dirTableBlockIndex +
                              dirTableBlockCount]
        fileTable = dataRegion[fileTableBlockIndex:
                               fileTableBlockIndex + fileTableBlockCount]
    else:
        dirTableOff, dirMaxCount, dirUnk, \
            fileTableOff, fileMaxCount, fileUnk, \
            = struct.unpack('<QIIQII', saveImage[0x68:0x88])
        dirTable = saveImage[dirTableOff: dirTableOff +
                             (dirMaxCount + 2) * 0x28]
        fileTable = saveImage[fileTableOff: fileTableOff +
                              (fileMaxCount + 1) * 0x30]

    print("Info: dirMaxCount = %d" % dirMaxCount)
    print("Info: dirUnk = %d" % dirUnk)
    print("Info: fileMaxCount = %d" % fileMaxCount)
    print("Info: fileUnk = %d" % fileUnk)

    # Parses directory entry table
    dirList = [DirEntry(dirTable[0:0x28])]  # first (dummy) entry
    dirCount = dirList[0].count
    for i in range(1, dirCount):
        dirList.append(DirEntry(dirTable[i * 0x28: (i + 1) * 0x28]))

    print("Directory list:")
    for i in range(len(dirList)):
        if dirList[i].count == dirCount:
            print("[%3d]~~Dummy~~ count=%3d max=%3d next=%3d" % (
                i, dirList[i].count, dirList[i].maxCount,
                dirList[i].nextDummyIndex))
        else:
            print("[%3d]parent=%3d '%16s' next=%3d child=%3d"
                  " file=%3d collision=%3d unknown=%d" % (
                      i, dirList[i].parentIndex, dirList[i].getName(),
                      dirList[i].nextIndex, dirList[i].firstDirIndex,
                      dirList[i].firstFileIndex,
                      dirList[i].nextCollision, dirList[i].unknown))

    # Parses file entry table
    fileList = [FileEntry(fileTable[0:0x30])]  # first (dummy) entry
    fileCount = fileList[0].count
    for i in range(1, fileCount):
        fileList.append(FileEntry(fileTable[i * 0x30: (i + 1) * 0x30]))

    print("File list:")
    for i in range(len(fileList)):
        if fileList[i].count == fileCount:
            print("[%3d]~~Dummy~~ count=%3d max=%3d next=%3d" % (
                i, fileList[i].count, fileList[i].maxCount,
                fileList[i].nextDummyIndex))
        else:
            print("[%3d]parent=%3d '%16s' next=%3d collision=%3d"
                  " size=%10d block=%5d unk1=%10d unk2=%10d" % (
                      i, fileList[i].parentIndex, fileList[i].getName(),
                      fileList[i].nextIndex, fileList[i].nextCollision,
                      fileList[i].size, fileList[i].blockIndex,
                      fileList[i].u1, fileList[i].u2))

    # Verifies directory hash table
    for i in range(dirHashTableSize):
        current = dirHashTable[i]
        while current != 0:
            if dirList[current].getHash() % dirHashTableSize != i:
                print("Warning: directory wrong bucket")
            current = dirList[current].nextCollision

    # Verifies file hash table
    for i in range(fileHashTableSize):
        current = fileHashTable[i]
        while current != 0:
            if fileList[current].getHash() % fileHashTableSize != i:
                print("Warning: file wrong bucket")
            current = fileList[current].nextCollision

    # Parses FAT
    fatList = []
    for i in range(1, fatSize + 1):  # skip the first entry
        fatList.append(
            FatEntry(saveImage[fatOff + i * 8: fatOff + (i + 1) * 8]))

    def ExtractDir(i, parent):
        if output_dir is not None:
            dir = os.path.join(output_dir, parent, dirList[i].getName())
            if not os.path.isdir(dir):
                os.mkdir(dir)

        # Extracts subdirectories
        if dirList[i].firstDirIndex != 0:
            ExtractDir(dirList[i].firstDirIndex,
                       os.path.join(parent, dirList[i].getName()))

        # Extract files
        if dirList[i].firstFileIndex != 0:
            ExtractFile(dirList[i].firstFileIndex,
                        os.path.join(parent, dirList[i].getName()))

        # Extract sibling directories
        if dirList[i].nextIndex != 0:
            ExtractDir(dirList[i].nextIndex, parent)

    def ExtractFile(i, parent):
        full_name = os.path.join(parent, fileList[i].getName())
        if output_dir is not None:
            file = open(os.path.join(output_dir, full_name), 'wb')
        else:
            file = None
        fileSize = fileList[i].size
        if fileSize != 0:
            currentBlock = fileList[i].blockIndex
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

                tranSize *= blockSize
                tranSize = min(fileSize, tranSize)
                pos = currentBlock * blockSize
                if file is not None:
                    file.write(dataRegion[pos: pos + tranSize])
                fileSize -= tranSize
                if fileSize <= 0:
                    if fatList[currentBlock].v != -1:
                        print("Warning: file end before block end")
                    break
                previousBlock = currentBlock
                currentBlock = fatList[currentBlock].v

        if file is not None:
            file.close()

        # Extract sibling files
        if fileList[i].nextIndex != 0:
            ExtractFile(fileList[i].nextIndex, parent)

    # Extracts ALL
    ExtractDir(1, "")
    print("Finished!")


if __name__ == "__main__":
    main()
