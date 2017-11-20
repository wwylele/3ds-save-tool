import os
import os.path
import struct


def trimBytes(bs):
    """ Trims trailing zeros in a byte string """
    n = bs.find(b'\0')
    if n != -1:
        return bs[:n]
    return bs


class Header(object):
    def __init__(self, raw, hasData):
        x00, self.blockSize, \
            self.dirHashTableOff, self.dirHashTableSize, self.dirHashTableUnk, \
            self.fileHashTableOff, self.fileHashTableSize, self.fileHashTableUnk, \
            self.fatOff, self.fatSize, self.fatUnk, \
            self.dataRegionOff, self.dataRegionSize, self.dataRegionUnk, \
            = struct.unpack('<IIQIIQIIQIIQII',
                            raw[0: 0x48])

        if x00 != 0:
            print("Warning: unknown 0 = 0x%X in filesystem header" % x00)

        print("Info: dirHashTableSize = %d" % self.dirHashTableSize)
        print("Info: dirHashTableUnk = %d" % self.dirHashTableUnk)
        print("Info: fileHashTableSize = %d" % self.fileHashTableSize)
        print("Info: fileHashTableUnk = %d" % self.fileHashTableUnk)
        print("Info: fatSize = %d" % self.fatSize)
        print("Info: fatUnk = %d" % self.fatUnk)
        print("Info: dataRegionSize = %d" % self.dataRegionSize)
        print("Info: dataRegionUnk = %d" % self.dataRegionUnk)
        if self.fatSize != self.dataRegionSize:
            printf("Warning: fatSize != dataRegionSize")

        if not hasData:
            dirTableBlockIndex, dirTableBlockCount, self.dirMaxCount, self.dirUnk, \
                fileTableBlockIndex, fileTableBlockCount, self.fileMaxCount, self.fileUnk \
                = struct.unpack('<IIIIIIII', raw[0x48:0x68])
            self.dirTableOff = self.dataRegionOff + dirTableBlockIndex * self.blockSize
            self.fileTableOff = self.dataRegionOff + fileTableBlockIndex * self.blockSize
        else:
            self.dirTableOff, self.dirMaxCount, self.dirUnk, \
                self.fileTableOff, self.fileMaxCount, self.fileUnk, \
                = struct.unpack('<QIIQII', raw[0x48:0x68])

        print("Info: dirMaxCount = %d" % self.dirMaxCount)
        print("Info: dirUnk = %d" % self.dirUnk)
        print("Info: fileMaxCount = %d" % self.fileMaxCount)
        print("Info: fileUnk = %d" % self.fileUnk)


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
            print("Warning: unknown = %d" % self.unknown)

        # Reads dummy entry data
        self.count, self.maxCount, self.nextDummyIndex \
            = struct.unpack('<II28xI', raw)

    def getName(self):
        return trimBytes(self.name).decode()

    def printEntry(self, i, dirCount):
        if self.count == dirCount:
            print("[%3d]~~Dummy~~ count=%3d max=%3d next=%3d" % (
                i, self.count, self.maxCount,
                self.nextDummyIndex))
        else:
            print("[%3d]parent=%3d '%16s' next=%3d child=%3d"
                  " file=%3d collision=%3d unknown=%d" % (
                      i, self.parentIndex, self.getName(),
                      self.nextIndex, self.firstDirIndex,
                      self.firstFileIndex,
                      self.nextCollision, self.unknown))


class FileEntry(HashableEntry):
    """ File table entry """

    def __init__(self, raw):
        # Reads normal entry data
        self.parentIndex, self.name, \
            self.nextIndex, self.u1, self.blockIndex, self.size, \
            self.u2, self.nextCollision \
            = struct.unpack('<I16sIIIQII', raw)

        # for extdata
        self.uniqueId = self.size

        # Reads dummy entry data
        self.count, self.maxCount, self.nextDummyIndex \
            = struct.unpack('<II36xI', raw)

    def getName(self):
        return trimBytes(self.name).decode()

    def printDummyEntry(self, i):
        print("[%3d]~~Dummy~~ count=%3d max=%3d next=%3d" % (
            i, self.count, self.maxCount,
            self.nextDummyIndex))

    def printEntryAsSave(self, i, fileCount):
        if self.count == fileCount:
            self.printDummyEntry(i)
        else:
            print("[%3d]parent=%3d '%16s' next=%3d collision=%3d"
                  " size=%10d block=%5d unk1=%10d unk2=%10d" % (
                      i, self.parentIndex, self.getName(),
                      self.nextIndex, self.nextCollision,
                      self.size, self.blockIndex,
                      self.u1, self.u2))

    def printEntryAsExtdata(self, i, fileCount):
        if self.count == fileCount:
            self.printDummyEntry(i)
        else:
            print("[%3d]parent=%3d '%16s' next=%3d collision=%3d"
                  " ID=0x%016X unk1=%10d unk2=%10d" % (
                      i, self.parentIndex, self.getName(),
                      self.nextIndex, self.nextCollision,
                      self.uniqueId, self.u1, self.u2))


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


def getHashTable(offset, size, partitionImage):
    hashTable = []
    for i in range(size):
        hashTable.append(struct.unpack('<I', partitionImage[
            offset + i * 4: offset + (i + 1) * 4])[0])
    return hashTable


def getDirList(offset, partitionImage):
    dirList = [DirEntry(partitionImage[offset:offset + 0x28])]
    dirCount = dirList[0].count
    for i in range(1, dirCount):
        dirList.append(DirEntry(partitionImage[
            offset + i * 0x28: offset + (i + 1) * 0x28]))
    return dirList


def getFileList(offset, partitionImage):
    fileList = [FileEntry(
        partitionImage[offset:offset + 0x30])]
    fileCount = fileList[0].count
    for i in range(1, fileCount):
        fileList.append(FileEntry(partitionImage[
            offset + i * 0x30: offset + (i + 1) * 0x30]))
    return fileList


def verifyHashTable(hashTable, entryList):
    for i in range(len(hashTable)):
        current = hashTable[i]
        while current != 0:
            if entryList[current].getHash() % len(hashTable) != i:
                print("Warning: wrong bucket")
            current = entryList[current].nextCollision


def extractAll(dirList, fileList, outputDir, fileDumper):
    def ExtractDir(i, parent):
        if outputDir is not None:
            dir = os.path.join(outputDir, parent, dirList[i].getName())
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
        if outputDir is not None:
            file = open(os.path.join(outputDir, full_name), 'wb')
        else:
            file = None

        fileDumper(fileList[i], file, i)

        if file is not None:
            file.close()

        # Extract sibling files
        if fileList[i].nextIndex != 0:
            ExtractFile(fileList[i].nextIndex, parent)

    # Extracts ALL
    ExtractDir(1, "")
