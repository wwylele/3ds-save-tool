#!/usr/bin/env python3

import os
import os.path
import struct
import sys
import hashlib

import difi
import savefilesystem
import key_engine

try:
    from secrets import Secrets
except:
    class Secrets(object):
        pass


def getDigestBlock(saveType, saveId, header):
    if saveType == "nand":
        return b"CTR-SYS0" + struct.pack("<Q", saveId) + header
    sav0Block = hashlib.sha256(b"CTR-SAV0" + header).digest()
    return b"CTR-SIGN" + struct.pack("<Q", saveId) + sav0Block


def cryptoUnwrap(disa, saveType, saveId, key):
    if saveType != "sd":
        print("Error: only SD save supports decryption.")
        return None

    if saveId is None:
        print("Error: ID needed to decrypt the save.")
        return None

    if key is None:
        print("No enough secrets provided to decrypt.")
        return None

    high = saveId >> 32
    low = saveId & 0xFFFFFFFF
    path = "/title/%08x/%08x/data/00000001.sav" % (high, low)

    import sd_decrypt
    return sd_decrypt.DecryptSdFile(disa, path, key)


def main():
    if len(sys.argv) < 2:
        print("Usage: %s input [output] [OPTIONS]" % sys.argv[0])
        print("")
        print("Arguments:")
        print("  input            A DISA file")
        print("  output           The directory for storing extracted files")
        print("")
        print("The following arguments are optional and needed for CMAC verification.")
        print("You need to provide secrets.py to enable CMAC verification.")
        print("  -sd              Specify that the DISA file is a SD save file")
        print("  -nand            Specify that the DISA file is a NAND save file")
        print("  -id ID           The save ID of the file in hex")
        print("Decryption for SD save is also supported by the following option")
        print("  -decrypt         Decrypt SD save. Requires -sd and -id arguments")

        exit(1)

    inputPath = None
    outputPath = None
    saveId = None
    saveType = None
    decrypt = False

    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "-id":
            i += 1
            saveId = int(sys.argv[i], 16)
        elif sys.argv[i] == "-sd":
            saveType = "sd"
        elif sys.argv[i] == "-nand":
            saveType = "nand"
        elif sys.argv[i] == "-card":
            saveType = "card"
        elif sys.argv[i] == "-decrypt":
            decrypt = True
        else:
            if inputPath is None:
                inputPath = sys.argv[i]
            else:
                outputPath = sys.argv[i]
        i += 1

    if inputPath is None:
        print("Error: no input file given.")
        exit(1)

    disa = open(inputPath, 'rb')

    secretsDb = Secrets()
    keyEngine = key_engine.KeyEngine(secretsDb)

    if decrypt:
        disa = cryptoUnwrap(disa, saveType, saveId,
                            keyEngine.getKeySdDecrypt())
        if disa is None:
            exit(1)

    Cmac = disa.read(0x10)
    disa.seek(0x100, os.SEEK_SET)
    header = disa.read(0x100)

    if outputPath is None:
        print("No output directory given. Will only do data checking.")

    if saveType is None:
        print("No save type specified. Will skip CMAC verification.")
    elif saveType == "nand" or saveType == "sd":
        if saveId is None:
            print("No save ID specified. Will skip CMAC verification.")
        else:
            key = keyEngine.getKeySdNandCmac()
            if key is None:
                print("No enough secrets provided. Will skip CMAC verification.")
            else:
                digest = hashlib.sha256(getDigestBlock(
                    saveType, saveId, header)).digest()
                import cmac
                if Cmac != cmac.AesCmac(digest, key):
                    print("Error: CMAC mismatch.")
                    exit(1)
                else:
                    print("Info: CMAC verified.")
    else:
        print("Unsupported save type. Will skip CMAC verification.")

    # Reads DISA header
    disa.seek(0x100, os.SEEK_SET)
    DISA, ver, \
        partCount, secPartTableOff, priPartTableOff, partTableSize, \
        partADiscriptorOff, partADiscriptorSize, \
        partBDiscriptorOff, partBDiscriptorSize, \
        partAOff, partASize, partBOff, partBSize, \
        activeTable, tableHash = struct.unpack(
            '<III4xQQQQQQQQQQQB3x32s116x', header)

    if DISA != 0x41534944:
        print("Error: Not a DISA format")
        exit(1)

    if ver != 0x00040000:
        print("Error: Wrong DISA version")
        exit(1)

    if partCount == 1:
        hasData = False
        print("Info: No partition B")
    elif partCount == 2:
        hasData = True
        print("Info: Has partition B")
    else:
        print("Error: Wrong partition count %d" % partCount)
        exit(1)

    if activeTable == 0:
        partTableOff = priPartTableOff
    elif activeTable == 1:
        partTableOff = secPartTableOff
    else:
        print("Error: Wrong active table ID %d" % activeTable)
        exit(1)

    # Verify partition table hash
    disa.seek(partTableOff, os.SEEK_SET)
    partTable = disa.read(partTableSize)

    if hashlib.sha256(partTable).digest() != tableHash:
        print("Error: Partition table hash mismatch!")
        exit(1)

    # Reads and unwraps SAVE image
    partADescriptor = partTable[partADiscriptorOff:
                                partADiscriptorOff + partADiscriptorSize]
    disa.seek(partAOff, os.SEEK_SET)
    partA = disa.read(partASize)
    partAInner, externalIVFCL4 = difi.unwrap(partADescriptor, partA)
    if externalIVFCL4:
        print("Warning: partition A has an external IVFC level 4")

    # Reads and unwraps DATA image
    if hasData:
        partBDescriptor = partTable[partBDiscriptorOff:
                                    partBDiscriptorOff + partBDiscriptorSize]
        disa.seek(partBOff, os.SEEK_SET)
        partB = disa.read(partBSize)
        dataRegion, externalIVFCL4 = difi.unwrap(partBDescriptor, partB)
        if not externalIVFCL4:
            print("Warning: partition B does not have an external IVFC level 4")

    disa.close()

    # Reads SAVE header
    SAVE, ver, filesystemHeaderOff, imageSize, imageBlockSize, x00 \
        = struct.unpack('<IIQQII', partAInner[0:0x20])

    if SAVE != 0x45564153:
        print("Error: Wrong SAVE magic")
        exit(1)

    if ver != 0x00040000:
        print("Error: Wrong SAVE version")
        exit(1)

    if x00 != 0:
        print("Warning: unknown 0 = 0x%X in SAVE header" % x00)

    fsHeader = savefilesystem.Header(
        partAInner[filesystemHeaderOff:filesystemHeaderOff + 0x68], hasData)

    if not hasData:
        dataRegion = partAInner[
            fsHeader.dataRegionOff: fsHeader.dataRegionOff +
            fsHeader.dataRegionSize * fsHeader.blockSize]

    # Parses hash tables
    dirHashTable = savefilesystem.getHashTable(fsHeader.dirHashTableOff,
                                               fsHeader.dirHashTableSize,
                                               partAInner)

    fileHashTable = savefilesystem.getHashTable(fsHeader.fileHashTableOff,
                                                fsHeader.fileHashTableSize,
                                                partAInner)

    # Parses FAT
    fat = savefilesystem.FAT(fsHeader, partAInner)

    # Parses directory & file entry table
    dirList = savefilesystem.getDirList(
        fsHeader, partAInner, dataRegion, fat)

    print("Directory list:")
    for i in range(len(dirList)):
        dirList[i].printEntry(i)

    fileList = savefilesystem.getFileList(
        fsHeader, partAInner, dataRegion, fat)

    print("File list:")
    for i in range(len(fileList)):
        fileList[i].printEntryAsSave(i)

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
