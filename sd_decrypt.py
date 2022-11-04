import hashlib
import struct
import io

try:
    from Cryptodome.Hash import CMAC
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter
except:
    from Crypto.Hash import CMAC
    from Crypto.Cipher import AES
    from Crypto.Util import Counter


def DecryptSdFile(file, filePath, key):
    utf16Path = (filePath + '\0').encode(encoding='utf_16_le')
    pathHash = hashlib.sha256(utf16Path).digest()
    low = pathHash[0:16]
    high = pathHash[16:32]
    mixed = bytes([a ^ b for (a, b) in zip(low, high)])
    ctra, ctrb = struct.unpack(">QQ", mixed)
    ctr = Counter.new(128, initial_value=(ctra << 64) | ctrb)
    decrypted = AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(file.read())
    return io.BytesIO(decrypted)
