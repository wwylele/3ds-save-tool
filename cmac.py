try:
    from Crypto.Hash import CMAC
    from Crypto.Cipher import AES
except:
    from Cryptodome.Hash import CMAC
    from Cryptodome.Cipher import AES


def AesCmac(data, key):
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(data)
    return cobj.digest()
