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


def cryptoUnwrap(diff, saveType, saveId, saveSubId, key):
    if saveId is None:
        print("Error: ID needed to decrypt the save.")
        return None

    if key is None:
        print("No enough secrets provided to decrypt.")
        return None

    if saveType is None:
        print("Error: save type needed to decrypt the save.")
        return None
    elif saveType == "extdata":
        if saveSubId is None:
            print("Error: sub ID needed to decrypt the save.")
            return None
        high = saveId >> 32
        low = saveId & 0xFFFFFFFF
        subHigh = saveSubId >> 32
        subLow = saveSubId & 0xFFFFFFFF
        path = "/extdata/%08x/%08x/%08x/%08x" % (high, low, subHigh, subLow)
    elif saveType == "titledb":
        if saveId == 2:
            fileName = "title.db"
        elif saveId == 3:
            fileName = "import.db"
        path = "/dbs/" + fileName

    import sd_decrypt
    return sd_decrypt.DecryptSdFile(diff, path, key)


def unwrapDIFF(filePath, expectedUniqueId=None, saveType=None, saveId=None,
               saveSubId=None, decrypt=False):
    diff = open(filePath, 'rb')

    secretsDb = Secrets()
    keyEngine = key_engine.KeyEngine(secretsDb)

    if decrypt:
        diff = cryptoUnwrap(diff, saveType, saveId,
                            saveSubId, keyEngine.getKeySdDecrypt())
        if diff is None:
            exit(1)

    key = keyEngine.getKeySdNandCmac()

    Cmac = diff.read(0x10)
    diff.seek(0x100, os.SEEK_SET)
    header = diff.read(0x100)

    digestBlock = None
    if key is None:
        print("No enough secrets provided. Will skip CMAC verification.")
    elif saveType is None:
        print("No save type specified. Will skip CMAC verification.")
    elif saveId is None:
        print("No save ID specified. Will skip CMAC verification.")
    elif saveType == "extdata":
        if saveSubId is None:
            saveSubId = 0
            quotaFlag = 0
        else:
            quotaFlag = 1
        digestBlock = b"CTR-EXT0" + \
            struct.pack("<QIQ", saveId, quotaFlag, saveSubId) + header
    elif saveType == "titledb":
        digestBlock = b"CTR-9DB0" + struct.pack("<I", saveId) + header
    else:
        print("Unknown save type. Will skip CMAC verification.")

    if digestBlock is not None:
        import cmac
        if Cmac != cmac.AesCmac(hashlib.sha256(digestBlock).digest(), key):
            print("Error: CMAC mismatch.")
            exit(1)
        else:
            print("Info: CMAC verified.")

    DIFF, ver, \
        secPartTableOff, priPartTableOff, partTableSize, \
        partOff, partSize, \
        activeTable, tableHash, uniqueId, \
        = struct.unpack('<IIQQQQQI32sQ164x', header)

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

    print("Info: Unique ID = %016X" % uniqueId)
    if expectedUniqueId is not None:
        if expectedUniqueId != uniqueId:
            print("Warning: unique ID mismatch")

    # Verify partition table hash
    diff.seek(partTableOff, os.SEEK_SET)
    partTable = diff.read(partTableSize)
    if hashlib.sha256(partTable).digest() != tableHash:
        print("Error: Partition table hash mismatch!")
        exit(1)

    # Reads and unwraps partition
    diff.seek(partOff, os.SEEK_SET)
    part = diff.read(partSize)
    image, externalIVFCL4 = difi.unwrap(partTable, part)
    if externalIVFCL4:
        print("Info: external IVFC level 4")

    diff.close()
    return image


def trimBytes(bs):
    """ Trims trailing zeros in a byte string """
    n = bs.find(b'\0')
    if n != -1:
        return bs[:n]
    return bs


def extractExtdata(extdataDir, outputDir, saveId, decrypt):
    def extdataFileById(idHigh, idLow):
        return os.path.join(extdataDir, "%08x" % idHigh, "%08x" % idLow)
    vsxe = unwrapDIFF(extdataFileById(0, 1), saveType="extdata",
                      saveId=saveId, saveSubId=1, decrypt=decrypt)
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

    dataRegion = vsxe[
        fsHeader.dataRegionOff: fsHeader.dataRegionOff +
        fsHeader.dataRegionSize * fsHeader.blockSize]

    # parse FAT
    fat = savefilesystem.FAT(fsHeader, vsxe)

    # parse hash tables
    dirHashTable = savefilesystem.getHashTable(fsHeader.dirHashTableOff,
                                               fsHeader.dirHashTableSize,
                                               vsxe)

    fileHashTable = savefilesystem.getHashTable(fsHeader.fileHashTableOff,
                                                fsHeader.fileHashTableSize,
                                                vsxe)

    # Parses directory & file entry table
    dirList = savefilesystem.getDirList(
        fsHeader, vsxe, dataRegion, fat)

    print("Directory list:")
    for i in range(len(dirList)):
        dirList[i].printEntry(i)

    fileList = savefilesystem.getFileList(
        fsHeader, vsxe, dataRegion, fat)

    print("File list:")
    for i in range(len(fileList)):
        fileList[i].printEntryAsExtdata(i)

    # Verifies directory & file hash table
    print("Verifying directory hash table")
    savefilesystem.verifyHashTable(dirHashTable, dirList)
    print("Verifying file hash table")
    savefilesystem.verifyHashTable(fileHashTable, fileList)

    # Walks through free blocks
    print("Walking through free blocks")
    fat.visitFreeBlock()

    fat.allVisited()

    def extFileDumper(fileEntry, file, index):
        print("Extracting %s" % fileEntry.getName())
        fileId = index + 1
        dirCapacity = 126  # ???
        idHigh = fileId // dirCapacity
        idLow = fileId % dirCapacity
        content = unwrapDIFF(extdataFileById(idHigh, idLow), expectedUniqueId=fileEntry.uniqueId,
                             saveType="extdata", saveId=saveId, saveSubId=(idHigh << 32) | idLow, decrypt=decrypt)
        if file is not None:
            file.write(content)

    savefilesystem.extractAll(dirList, fileList, outputDir, extFileDumper)

    print("Finished!")


def main():
    if len(sys.argv) < 2:
        print("Usage: %s input [output] [OPTIONS]" % sys.argv[0])
        print("")
        print("Arguments:")
        print("  input            A DIFF file or an extdata directory")
        print("       (extdata directory is extdata/<ExtdataID-High>/<ExtdataID-low>)")
        print("  output           The directory for storing extracted files")
        print("")
        print("The following arguments are optional and are only needed for CMAC verification.")
        print("You need to provide secrets.py to enable CMAC verification.")
        print("  -extdata         Specify that the DIFF file is a subfile in an extdata")
        print("  -titledb         Specify that the DIFF file is a title database file")
        print("                   Note: NAND title database CMAC verification is unimplemented")
        print("  -id ID           The save ID of the file in hex")
        print("  -subid ID        The subfile ID of the file in hex")
        print("                   Only need for extdata subfile, except for Quota.dat")
        print("Decryption for SD save is also supported by the following option")
        print("  -decrypt         Decrypt SD save. Requires -extdata or -titledb options unless")
        print("                   a extdata directory is given as the input. -id is also required")
        print("                   -subid is required for single extdata file")
        exit(1)

    inputPath = None
    outputPath = None
    saveId = None
    saveSubId = None
    saveType = None
    decrypt = False

    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "-id":
            i += 1
            saveId = int(sys.argv[i], 16)
        elif sys.argv[i] == "-subid":
            i += 1
            saveSubId = int(sys.argv[i], 16)
        elif sys.argv[i] == "-extdata":
            saveType = "extdata"
        elif sys.argv[i] == "-titledb":
            saveType = "titledb"
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

    if outputPath is None:
        print("No output directory given. Will only do data checking.")

    if os.path.isdir(inputPath):
        extractExtdata(inputPath, outputPath, saveId, decrypt)
        exit(0)

    image = unwrapDIFF(inputPath, saveType=saveType,
                       saveId=saveId, saveSubId=saveSubId, decrypt=decrypt)

    if outputPath is not None:
        output_file = open(outputPath, "wb")
        output_file.write(image)
        output_file.close()


if __name__ == "__main__":
    main()
