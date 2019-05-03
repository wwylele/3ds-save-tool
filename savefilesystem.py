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
            self.dirHashTableOff, self.dirHashTableSize, \
            self.fileHashTableOff, self.fileHashTableSize, \
            self.fatOff, self.fatSize, \
            self.dataRegionOff, self.dataRegionSize, \
            = struct.unpack('<IIQI4xQI4xQI4xQI4x', raw[0: 0x48])

        if x00 != 0:
            print("Warning: unknown 0 = 0x%X in filesystem header" % x00)

        print("Info: dirHashTableSize = %d" % self.dirHashTableSize)
        print("Info: fileHashTableSize = %d" % self.fileHashTableSize)
        print("Info: fatSize = %d" % self.fatSize)
        print("Info: dataRegionSize = %d" % self.dataRegionSize)
        if self.fatSize != self.dataRegionSize:
            print("Warning: fatSize != dataRegionSize")

        if not hasData:
            self.dirTableBlockIndex, self.dirTableBlockCount, self.dirMaxCount, \
                self.fileTableBlockIndex, self.fileTableBlockCount, self.fileMaxCount \
                = struct.unpack('<III4xIII4x', raw[0x48:0x68])
            self.dirTableOff = 0
            self.fileTableOff = 0
            self.tableInDataRegion = True
            print("Info: dirTableBlockCount = %d" % self.dirTableBlockCount)
            print("Info: fileTableBlockCount = %d" % self.fileTableBlockCount)
        else:
            self.dirTableOff, self.dirMaxCount, \
                self.fileTableOff, self.fileMaxCount, \
                = struct.unpack('<QI4xQI4x', raw[0x48:0x68])
            self.tableInDataRegion = False

        print("Info: dirMaxCount = %d" % self.dirMaxCount)
        print("Info: fileMaxCount = %d" % self.fileMaxCount)


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

        self.isDummy = False  # will be set later

    def getName(self):
        return trimBytes(self.name).decode()

    def printEntry(self, i):
        if self.isDummy:
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

    def entrySize():
        return 0x28


class FileEntry(HashableEntry):
    """ File table entry """

    def __init__(self, raw):
        # Reads normal entry data
        self.parentIndex, self.name, \
            self.nextIndex, self.blockIndex, self.size, \
            self.u2, self.nextCollision \
            = struct.unpack('<I16sI4xIQII', raw)

        # for extdata
        self.uniqueId = self.size

        # Reads dummy entry data
        self.count, self.maxCount, self.nextDummyIndex \
            = struct.unpack('<II36xI', raw)

        self.isDummy = False  # will be set later

    def getName(self):
        return trimBytes(self.name).decode()

    def printDummyEntry(self, i):
        print("[%3d]~~Dummy~~ count=%3d max=%3d next=%3d" % (
            i, self.count, self.maxCount,
            self.nextDummyIndex))

    def printEntryAsSave(self, i):
        if self.isDummy:
            self.printDummyEntry(i)
        else:
            print("[%3d]parent=%3d '%16s' next=%3d collision=%3d"
                  " size=%10d block=%5d unknown=%10d" % (
                      i, self.parentIndex, self.getName(),
                      self.nextIndex, self.nextCollision,
                      self.size, self.blockIndex, self.u2))

    def printEntryAsExtdata(self, i):
        if self.isDummy:
            self.printDummyEntry(i)
        else:
            print("[%3d]parent=%3d '%16s' next=%3d collision=%3d"
                  " ID=0x%016X unknown=%10d" % (
                      i, self.parentIndex, self.getName(),
                      self.nextIndex, self.nextCollision,
                      self.uniqueId, self.u2))

    def entrySize():
        return 0x30


class TdbHashableEntry(object):
    def getHash(self):
        hash = self.parentIndex ^ 0x091A2B3C
        hash = ((hash >> 1) | (hash << 31)) & 0xFFFFFFFF
        hash ^= self.titleId & 0xFFFFFFFF
        hash = ((hash >> 1) | (hash << 31)) & 0xFFFFFFFF
        hash ^= self.titleId >> 32
        return hash


class TdbDirEntry(TdbHashableEntry):
    """ Tite database directory table entry """

    def __init__(self, raw):
        # Reads normal entry data
        self.parentIndex, self.nextIndex, self.firstDirIndex, self.firstFileIndex, \
            self.unk1, self.unk2, self.unk3, self.nextCollision \
            = struct.unpack('<IIIIIIII', raw)

        # Reads dummy entry data
        self.count, self.maxCount, self.nextDummyIndex \
            = struct.unpack('<II20xI', raw)

        self.titleId = 0

        self.isDummy = False  # will be set later

    def getName(self):
        return ""

    def printEntry(self, i):
        if self.isDummy:
            print("[%3d]~~Dummy~~ count=%3d max=%3d next=%3d" % (
                i, self.count, self.maxCount,
                self.nextDummyIndex))
        else:
            print("[%3d]parent=%3d '%16s' next=%3d child=%3d"
                  " file=%3d collision=%3d unk1=%10d unk2=%10d unk3=%10d" % (
                      i, self.parentIndex, self.getName(),
                      self.nextIndex, self.firstDirIndex,
                      self.firstFileIndex,
                      self.nextCollision, self.unk1, self.unk2, self.unk3))

    def entrySize():
        return 0x20


class TdbFileEntry(TdbHashableEntry):
    """ Title databse file table entry """

    def __init__(self, raw):
        # Reads normal entry data
        self.parentIndex, self.titleId, \
            self.nextIndex, self.unk1, self.blockIndex, self.size, \
            self.unk2, self.unk3, self.nextCollision \
            = struct.unpack('<IQIIIQIII', raw)

        # Reads dummy entry data
        self.count, self.maxCount, self.nextDummyIndex \
            = struct.unpack('<II32xI', raw)

        self.isDummy = False  # will be set later

    def getName(self):
        return "%016X" % self.titleId

    def printDummyEntry(self, i):
        print("[%3d]~~Dummy~~ count=%3d max=%3d next=%3d" % (
            i, self.count, self.maxCount,
            self.nextDummyIndex))

    def printEntry(self, i):
        if self.isDummy:
            self.printDummyEntry(i)
        else:
            print("[%3d]parent=%3d '%16s' next=%3d collision=%3d"
                  " size=%10d block=%5d unk1=%10d unk2=%10d unk3=%10d" % (
                      i, self.parentIndex, self.getName(),
                      self.nextIndex, self.nextCollision,
                      self.size, self.blockIndex, self.unk1, self.unk2, self.unk3))

    def entrySize():
        return 0x2C


class FATEntry(object):
    """ FAT entry """

    def __init__(self, raw):
        self.u, self.v = struct.unpack('II', raw)
        if self.u >= 0x80000000:
            self.u -= 0x80000000
            self.uFlag = True
        else:
            self.uFlag = False
        if self.v >= 0x80000000:
            self.v -= 0x80000000
            self.vFlag = True
        else:
            self.vFlag = False

        self.visited = False


class FAT(object):
    def __init__(self, fsHeader, partitionImage):
        self.fatList = []
        for i in range(0, fsHeader.fatSize + 1):  # the actual FAT size is one larger
            self.fatList.append(FATEntry(
                partitionImage[fsHeader.fatOff + i * 8: fsHeader.fatOff + (i + 1) * 8]))

    def walk(self, start, blockHandler):
        start += 1  # shift index
        current = start
        previous = 0
        while current != 0:
            if current == start:
                if not self.fatList[current].uFlag:
                    print("Warning: first node not marked start @ %i" % current)
            else:
                if self.fatList[current].uFlag:
                    print("Warning: other node marked start @ %i" % current)
            if self.fatList[current].u != previous:
                print("Warning: previous node mismatch @ %i" % current)

            if self.fatList[current].vFlag:
                nodeEnd = self.fatList[current + 1].v
                if self.fatList[current + 1].u != current:
                    print("Warning: expansion node first block mismatch @ %i" %
                          (current + 1))
                if not self.fatList[current + 1].uFlag:
                    print("Warning: expansion node first block not marked @ %i" % (
                        current + 1))
                if self.fatList[current + 1].vFlag:
                    print("Warning: expansion node first block with wrong mark @ %i" % (
                        current + 1))
                if self.fatList[nodeEnd].u != current or \
                        self.fatList[nodeEnd].v != nodeEnd:
                    print("Warning: expansion node last block mismatch @ %i" % nodeEnd)
                if not self.fatList[nodeEnd].uFlag:
                    print(
                        "Warning: expansion node first block not marked @ %i" % nodeEnd)
                if self.fatList[nodeEnd].vFlag:
                    print(
                        "Warning: expansion node last block with wrong mark @ %i" % nodeEnd)
            else:
                nodeEnd = current

            for i in range(current, nodeEnd + 1):
                if self.fatList[i].visited:
                    print("Warning: already visited @ %i" % i)
                blockHandler(i - 1)  # shift index back
                self.fatList[i].visited = True

            previous = current
            current = self.fatList[current].v

    def visitFreeBlock(self):
        self.fatList[0].visited = True
        if self.fatList[0].u != 0:
            print("Warning: free leading block has u = %d" % fatList[0].u)
        if self.fatList[0].uFlag or self.fatList[0].vFlag:
            print("Warning: free leading block has flag set")
        start = self.fatList[0].v
        self.walk(start - 1, lambda _: None)

    def allVisited(self):
        for i in range(len(self.fatList)):
            if not self.fatList[i].visited:
                print("Warning: block %d not visited" % i)


def getHashTable(offset, size, partitionImage):
    hashTable = []
    for i in range(size):
        hashTable.append(struct.unpack('<I', partitionImage[
            offset + i * 4: offset + (i + 1) * 4])[0])
    return hashTable


def scanDummyEntry(list):
    list[0].isDummy = True
    i = list[0].nextDummyIndex
    count = list[0].count
    maxCount = list[0].maxCount
    while i != 0:
        if list[i].count != count or list[i].maxCount != maxCount:
            print("Warning: dummy entries have different content")
        list[i].isDummy = True
        i = list[i].nextDummyIndex


def getAllocatedList(dataRegion, blockSize, fat, index, count):
    result = bytearray()
    left = count

    def transferBlock(i):
        nonlocal count
        if count == 0:
            print("Warning: excessive block")
            return
        result.extend(dataRegion[blockSize * i: blockSize * (i + 1)])
        count -= 1
    fat.walk(index, transferBlock)
    if count != 0:
        print("Warning: not enough block")
    return result


def getDirList(fsHeader, partitionImage, dataRegion, fat, DirEntryT=DirEntry):
    offset = fsHeader.dirTableOff
    if fsHeader.tableInDataRegion:
        data = getAllocatedList(dataRegion, fsHeader.blockSize, fat,
                                fsHeader.dirTableBlockIndex, fsHeader.dirTableBlockCount)
    else:
        data = partitionImage
    dirList = [DirEntryT(data[offset: offset + DirEntryT.entrySize()])]
    dirCount = dirList[0].count
    for i in range(1, dirCount):
        dirList.append(DirEntryT(data[
            offset + i * DirEntryT.entrySize(): offset + (i + 1) * DirEntryT.entrySize()]))
    scanDummyEntry(dirList)
    return dirList


def getTdbDirList(fsHeader, dataRegion, fat):
    return getDirList(fsHeader, None, dataRegion, fat, TdbDirEntry)


def getFileList(fsHeader, partitionImage, dataRegion, fat, FileEntryT=FileEntry):
    offset = fsHeader.fileTableOff
    if fsHeader.tableInDataRegion:
        data = getAllocatedList(dataRegion, fsHeader.blockSize, fat,
                                fsHeader.fileTableBlockIndex, fsHeader.fileTableBlockCount)
    else:
        data = partitionImage
    fileList = [FileEntryT(data[offset: offset + FileEntryT.entrySize()])]
    fileCount = fileList[0].count
    for i in range(1, fileCount):
        fileList.append(FileEntryT(data[
            offset + i * FileEntryT.entrySize(): offset + (i + 1) * FileEntryT.entrySize()]))
    scanDummyEntry(fileList)
    return fileList


def getTdbFileList(fsHeader, dataRegion, fat):
    return getFileList(fsHeader, None, dataRegion, fat, TdbFileEntry)


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
