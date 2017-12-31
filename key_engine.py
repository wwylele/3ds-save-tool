
def rol(val, r_bits, max_bits):
    return (val << r_bits % max_bits) & (2 ** max_bits - 1) |\
        ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))


def scrambleKey(x, y, c):
    return rol((rol(x, 2, 128) ^ y) + c, 87, 128).to_bytes(0x10, 'big')


class KeyEngine(object):
    def __init__(self, secrets):
        self.secrets = secrets

    def getKeySdNandCmac(self):
        try:
            return scrambleKey(self.secrets.key0x30X, self.secrets.keyMovable, self.secrets.keyConst)
        except AttributeError:
            return None

    def getKeySdDecrypt(self):
        try:
            return scrambleKey(self.secrets.key0x34X, self.secrets.keyMovable, self.secrets.keyConst)
        except AttributeError:
            return None
