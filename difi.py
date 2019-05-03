# Python 3

import struct
import hashlib


class PartDiscriptor(object):
    """ Partition discriptor

     Consists of DIFI header, IVFC descriptor,
     DPFS descriptor and partition hash.
    """

    def __init__(self, raw):
        # Reads DIFI header
        DIFI, ver, \
            IVFCOff, IVFCSize, DPFSOff, DPFSSize, hashOff, hashSize, \
            externalIVFCL4, self.DPFSL1Selector, self.IVFCL4OffExt \
            = struct.unpack('<IIQQQQQQBB2xQ', raw[0:0x44])

        if DIFI != 0x49464944:
            print("Error: Wrong DIFI magic")
            exit(1)

        if ver != 0x00010000:
            print("Error: Wrong DIFI version")
            exit(1)

        if externalIVFCL4 == 0:
            self.externalIVFCL4 = False
        elif externalIVFCL4 == 1:
            self.externalIVFCL4 = True
        else:
            print("Error: Wrong externalIVFCL4 value %d" % externalIVFCL4)
            exit(1)

        if self.DPFSL1Selector > 1:
            print("Error: Wrong DPFSL1Selector value %d" % self.DPFSL1Selector)
            exit(1)

        # Reads IVFC descriptor
        IVFC, ver, masterHashSize, \
            self.IVFCL1Off, self.IVFCL1Size, IVFCL1BlockSize, \
            self.IVFCL2Off, self.IVFCL2Size, IVFCL2BlockSize, \
            self.IVFCL3Off, self.IVFCL3Size, IVFCL3BlockSize, \
            self.IVFCL4Off, self.IVFCL4Size, IVFCL4BlockSize, \
            unknown = struct.unpack(
                '<IIQQQI4xQQI4xQQI4xQQI4xQ', raw[IVFCOff: (IVFCOff + IVFCSize)])

        if IVFC != 0x43465649:
            print("Error: Wrong IVFC magic")
            exit(1)

        if ver != 0x00020000:
            print("Error: Wrong IVFC version")
            exit(1)

        if masterHashSize != hashSize:
            print("Error: Master hash size mismatch")
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
            = struct.unpack('<IIQQI4xQQI4xQQI4x', raw[DPFSOff: (DPFSOff + DPFSSize)])

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


def unwrapDPFS(part, discriptor):
    """ Reconstructs active data of the most inner DPFS level """
    l1 = getDPFSLevel(part, discriptor.DPFSL1Off, discriptor.DPFSL1Size)
    l2 = getDPFSLevel(part, discriptor.DPFSL2Off, discriptor.DPFSL2Size)
    l3 = getDPFSLevel(part, discriptor.DPFSL3Off, discriptor.DPFSL3Size)
    l1active = l1[discriptor.DPFSL1Selector]
    l2active = applyDPFSLevel(l1active, l2, discriptor.DPFSL2BlockSize)
    l3active = applyDPFSLevel(l2active, l3, discriptor.DPFSL3BlockSize)
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


def unwrapIVFC(partActive, discriptor, l4):
    """ Poisons IVFC tree to the most inner level """
    l1 = getIVFCLevel(partActive, discriptor.IVFCL1Off, discriptor.IVFCL1Size)
    l2 = getIVFCLevel(partActive, discriptor.IVFCL2Off, discriptor.IVFCL2Size)
    l3 = getIVFCLevel(partActive, discriptor.IVFCL3Off, discriptor.IVFCL3Size)
    if l4 is None:
        l4 = getIVFCLevel(partActive, discriptor.IVFCL4Off,
                          discriptor.IVFCL4Size)

    l1p = applyIVFCLevel(discriptor.hash, l1, discriptor.IVFCL1BlockSize)
    l2p = applyIVFCLevel(l1p, l2, discriptor.IVFCL2BlockSize)
    l3p = applyIVFCLevel(l2p, l3, discriptor.IVFCL3BlockSize)
    l4p = applyIVFCLevel(l3p, l4, discriptor.IVFCL4BlockSize)

    return l4p


def unwrap(discriptorRaw, partitionRaw):
    """ Unwraps DPFS and IVFC tree of a partition according to the partiton discriptor """
    discriptor = PartDiscriptor(discriptorRaw)
    active = unwrapDPFS(partitionRaw, discriptor)
    if discriptor.externalIVFCL4:
        IVFCL4 = partitionRaw[discriptor.IVFCL4OffExt:
                              discriptor.IVFCL4OffExt + discriptor.IVFCL4Size]
    else:
        IVFCL4 = None
    return (unwrapIVFC(active, discriptor, IVFCL4), discriptor.externalIVFCL4)
