from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex


def add_to_16(prand):
    if len(prand) % 16:
        add = 16 - (len(prand) % 16)
    else:
        add = 0
    prand_new = b'\x00' * add + prand
    return prand_new


def encrypt(key, data):
    mode = AES.MODE_ECB
    cryptos = AES.new(key, mode)
    cipher_text = cryptos.encrypt(data)
    cipher_text_hex = b2a_hex(cipher_text)
    text = cipher_text_hex[-6:]
    return text


if __name__ == '__main__':
    IRK = 'e2aabfd5a812aea7e9c05df3c5eeed9d'
    IRK_en = a2b_hex(IRK)[::-1]
    prand = '59dbd3'
    prand_byte = a2b_hex(prand)
    prand_pad = add_to_16(prand_byte)
    hash = encrypt(IRK_en, prand_pad)
    address = b2a_hex(prand_byte) + hash
    print(address)
