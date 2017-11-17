# Python 3

import os
import os.path
import struct
import sys
import hashlib


class PartEntry(object):
    """ Partition table entry

     Consists of DIFI header, IVFC descriptor,
     DPFS descriptor and partition hash.
    """

    def __init__(self, raw):
        # Reads DIFI header
        DIFI, ver, \
            IVFCOff, IVFCSize, DPFSOff, DPFSSize, hashOff, hashSize, \
            isData, self.DPFSL1Selector, zero, self.IVFCL4OffExt \
            = struct.unpack('<IIQQQQQQBBHQ', raw[0:0x44])

        if DIFI != 0x49464944:
            print("Error: Wrong DIFI magic")
            exit(1)

        if ver != 0x00010000:
            print("Error: Wrong DIFI version")
            exit(1)

        if isData == 0:
            self.isData = False
        elif isData == 1:
            self.isData = True
        else:
            print("Error: Wrong isData value %d" % isData)
            exit(1)

        if self.DPFSL1Selector > 1:
            print("Error: Wrong DPFSL1Selector value %d" % DPFSL1Selector)
            exit(1)

        # Reads IVFC descriptor
        IVFC, ver, masterHashSize, \
            self.IVFCL1Off, self.IVFCL1Size, IVFCL1BlockSize, \
            self.IVFCL2Off, self.IVFCL2Size, IVFCL2BlockSize, \
            self.IVFCL3Off, self.IVFCL3Size, IVFCL3BlockSize, \
            self.IVFCL4Off, self.IVFCL4Size, IVFCL4BlockSize, \
            unknown = struct.unpack(
                '<IIQQQQQQQQQQQQQQ', raw[IVFCOff: (IVFCOff + IVFCSize)])

        if IVFC != 0x43465649:
            print("Error: Wrong IVFC magic")
            exit(1)

        if ver != 0x00020000:
            print("Error: Wrong IVFC version")
            exit(1)

        if masterHashSize != 0x20:
            print("Error: Wrong master hash size %d" % masterHashSize)
            exit(1)

        if unknown != 0x78:
            print("Warning: unknown = 0x%X" % unknown)

        self.IVFCL1BlockSize = 2 ** IVFCL1BlockSize
        self.IVFCL2BlockSize = 2 ** IVFCL2BlockSize
        self.IVFCL3BlockSize = 2 ** IVFCL3BlockSize
        self.IVFCL4BlockSize = 2 ** IVFCL4BlockSize

        # Reads DPFS descriptor
        DPFS, ver, \
            self.DPFSL1Off, self.DPFSL1Size, DPFSL1BlockSize, \
            self.DPFSL2Off, self.DPFSL2Size, DPFSL2BlockSize, \
            self.DPFSL3Off, self.DPFSL3Size, DPFSL3BlockSize \
            = struct.unpack('<IIQQQQQQQQQ', raw[DPFSOff: (DPFSOff + DPFSSize)])

        if DPFS != 0x53465044:
            print("Error: Wrong DPFS magic")
            exit(1)

        if ver != 0x00010000:
            print("Error: Wrong DPFS version")
            exit(1)

        self.DPFSL1BlockSize = 2 ** DPFSL1BlockSize
        self.DPFSL2BlockSize = 2 ** DPFSL2BlockSize
        self.DPFSL3BlockSize = 2 ** DPFSL3BlockSize

        # Reads partition hash
        self.hash = raw[hashOff: (hashOff + hashSize)]


def getDPFSLevel(part, off, size):
    """ Gets the data pair of a DPFS level """
    return (part[off: off + size], part[off + size: off + 2 * size])


def applyDPFSLevel(selector, data, dataBlockSize):
    """ Reconstructs active data of a DPFS level using the previous level """
    dataPos = 0
    selectorPos = 0
    output = bytearray()
    dataLen = len(data[0])
    while True:
        u32, = struct.unpack('<I', selector[selectorPos: selectorPos + 4])
        for i in range(32):
            bit = (u32 >> (31 - i)) & 1
            tranSize = min(dataLen, dataBlockSize)
            output.extend(data[bit][dataPos: dataPos + tranSize])
            dataPos += tranSize
            dataLen -= tranSize
            if dataLen <= 0:
                return output

        selectorPos += 4


def unwrapDPFS(part, entry):
    """ Reconstructs active data of the most inner DPFS level """
    l1 = getDPFSLevel(part, entry.DPFSL1Off, entry.DPFSL1Size)
    l2 = getDPFSLevel(part, entry.DPFSL2Off, entry.DPFSL2Size)
    l3 = getDPFSLevel(part, entry.DPFSL3Off, entry.DPFSL3Size)
    l1active = l1[entry.DPFSL1Selector]
    l2active = applyDPFSLevel(l1active, l2, entry.DPFSL2BlockSize)
    l3active = applyDPFSLevel(l2active, l3, entry.DPFSL3BlockSize)
    return l3active


def getIVFCLevel(part, off, size):
    """ Gets the data of a IVFC level """
    return part[off: off + size]


def applyIVFCLevel(hash, data, dataBlockSize):
    """ Poisons unhashed data of a IVFC level using the hash from the previous level """
    hashPos = 0
    dataPos = 0
    output = bytearray()
    dataLen = len(data)
    while (hashPos < len(hash)):
        hashChunk = hash[hashPos: hashPos + 0x20]
        tranSize = min(dataLen, dataBlockSize)
        dataChunk = data[dataPos: dataPos + tranSize]
        dataChunkAlign = dataChunk + b'\x00' * (dataBlockSize - tranSize)
        if hashlib.sha256(dataChunkAlign).digest() == hashChunk:
            output.extend(dataChunk)
        else:
            # fill unhashed data with 0xDD
            output.extend(b'\xDD' * len(dataChunk))
        hashPos += 0x20
        dataPos += dataBlockSize
        dataLen -= tranSize
        if dataLen <= 0:
            break
    return output


def unwrapIVFC(partActive, entry, l4=None):
    """ Poisons IVFC tree to the most inner level """
    l1 = getIVFCLevel(partActive, entry.IVFCL1Off, entry.IVFCL1Size)
    l2 = getIVFCLevel(partActive, entry.IVFCL2Off, entry.IVFCL2Size)
    l3 = getIVFCLevel(partActive, entry.IVFCL3Off, entry.IVFCL3Size)
    if l4 is None:
        l4 = getIVFCLevel(partActive, entry.IVFCL4Off, entry.IVFCL4Size)

    l1p = applyIVFCLevel(entry.hash, l1, entry.IVFCL1BlockSize)
    l2p = applyIVFCLevel(l1p, l2, entry.IVFCL2BlockSize)
    l3p = applyIVFCLevel(l2p, l3, entry.IVFCL3BlockSize)
    l4p = applyIVFCLevel(l3p, l4, entry.IVFCL4BlockSize)

    return l4p


def trimBytes(bs):
    """ Trims trailing zeros in a byte string """
    n = bs.find(b'\0')
    if n != -1:
        return bs[:n]
    return bs


class DirEntry(object):
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


class FileEntry(object):
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
    if len(sys.argv) < 3:
        print("Usage: %s [DISA file] [output dir]" % sys.argv[0])
        exit(1)

    disa = open(sys.argv[1], 'rb')
    output_dir = sys.argv[2]

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
    saveEntry = PartEntry(partTable[savePartEntryOff: (
        savePartEntryOff + savePartEntrySize)])
    if saveEntry.isData:
        print("Error: SAVE partition is marked as DATA")
        exit(1)
    disa.seek(savePartOff, os.SEEK_SET)
    savePart = disa.read(savePartSize)
    saveActive = unwrapDPFS(savePart, saveEntry)
    saveImage = unwrapIVFC(saveActive, saveEntry)

    # Reads and unwraps DATA image
    if hasData:
        dataEntry = PartEntry(partTable[dataPartEntryOff: (
            dataPartEntryOff + dataPartEntrySize)])
        if not dataEntry.isData:
            print("Error: DATA partition is not marked as DATA")
            exit(1)
        disa.seek(dataPartOff, os.SEEK_SET)
        dataPart = disa.read(dataPartSize)
        dataL4 = dataPart[dataEntry.IVFCL4OffExt: dataEntry.IVFCL4OffExt +
                          dataEntry.IVFCL4Size]
        dataActive = unwrapDPFS(dataPart, dataEntry)
        dataRegion = unwrapIVFC(dataActive, dataEntry, dataL4)

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
            dirHashTableOff + i * 4:dirHashTableOff + (i + 1) * 4]))

    fileHashTable = []
    for i in range(fileHashTableSize):
        fileHashTable.append(struct.unpack('<I', saveImage[
            fileHashTableOff + i * 4:fileHashTableOff + (i + 1) * 4]))

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

    # Parses FAT
    fatList = []
    for i in range(1, fatSize + 1):  # skip the first entry
        fatList.append(
            FatEntry(saveImage[fatOff + i * 8: fatOff + (i + 1) * 8]))

    def ExtractDir(i, parent):
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
        file = open(os.path.join(output_dir, full_name), 'wb')
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
                file.write(dataRegion[pos: pos + tranSize])
                fileSize -= tranSize
                if fileSize <= 0:
                    if fatList[currentBlock].v != -1:
                        print("Warning: file end before block end")
                    break
                previousBlock = currentBlock
                currentBlock = fatList[currentBlock].v

        file.close()

        # Extract sibling files
        if fileList[i].nextIndex != 0:
            ExtractFile(fileList[i].nextIndex, parent)

    # Extracts ALL
    ExtractDir(1, "")


if __name__ == "__main__":
    main()
