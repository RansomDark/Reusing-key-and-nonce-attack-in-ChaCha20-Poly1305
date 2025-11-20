import struct

P = (1 << 130) - 5

def pad16(data):
    """Return padding for the Associated Authenticated Data"""
    if len(data) % 16 == 0:
        return bytearray(0)
    else:
        return bytearray(16-(len(data)%16))

def divceil(divident, divisor):
    """Integer division with rounding up"""
    quot, r = divmod(divident, divisor)
    return quot + int(bool(r))

def num_to_16_le_bytes(num):
    """Convert number to 16 bytes in little endian format"""
    ret = [0]*16
    for i, _ in enumerate(ret):
        ret[i] = num & 0xff
        num >>= 8
    return bytearray(ret)

def le_bytes_to_num(data):
    """Convert a number from little endian byte format"""
    ret = 0
    for i in range(len(data) - 1, -1, -1):
        ret <<= 8
        ret += data[i]
    return ret


def num_to_16_le_bytes_inv(b: bytearray) -> int:
    return int.from_bytes(b, byteorder='little')

def create_tag(data, r, s):
        """Calculate authentication tag for data"""
        acc = 0
        r = r & 0x0ffffffc0ffffffc0ffffffc0fffffff
        for i in range(0, divceil(len(data), 16)):
            n = le_bytes_to_num(data[i*16:(i+1)*16] + b'\x01')
            acc += n
            acc = (r * acc) % P
        acc += s
        return num_to_16_le_bytes(acc)

def get_poly_coeffs(data):
    """Calculate the coefficients of a polynomial"""
    coeffs = []
    for i in range(0, divceil(len(data), 16)):
        n = le_bytes_to_num(data[i*16:(i+1)*16] + b'\x01')
        coeffs.append(n)
    return coeffs

def get_payload(c1, c2, p1, goal):
    c1 = bytes.fromhex(c1)
    c2 = bytes.fromhex(c2)

    ct1 = c1[:-28]
    tag1 = c1[-28:-12]
    nonce = c1[-12:]

    ct2 = c2[:-28]
    tag2 = c2[-28:-12]

    keystream = bytes(a ^ b for a, b in zip(ct1, p1))
    evil_cipher = bytes(a ^ b for a, b in zip(keystream, goal))

    mac_data1 = ct1 + pad16(ct1)
    mac_data1 += struct.pack('<Q', len(bytearray(0)))
    mac_data1 += struct.pack('<Q', len(ct1))

    mac_data2 = ct2 + pad16(ct2)
    mac_data2 += struct.pack('<Q', len(bytearray(0)))
    mac_data2 += struct.pack('<Q', len(ct2))

    a1 = get_poly_coeffs(mac_data1)
    a2 = get_poly_coeffs(mac_data2)
    for i in range(4, 256):
        for j in range(256):
            t1 = num_to_16_le_bytes_inv(tag1 + bytes([i]))
            t2 = num_to_16_le_bytes_inv(tag2 + bytes([j]))
            r = 0
            s = 0
            for k in range(-4, 5):
                coeffs = [(x - y) % P for x, y in zip(a1, a2)]
                coeffs.append((t2 - t1 + k * pow(2, 128)) % P)
                coeffs = coeffs[::-1]
                R = PolynomialRing(GF(P), 'r')
                f = R(coeffs)
                ex_r = f.roots()
                if ex_r:
                    ex_r = int(ex_r[0][0])
                    coeffs2 = [(-x) % P for x in a1]
                    coeffs2.append((t1) % P)
                    coeffs2 = coeffs2[::-1]
                    f2 = R(coeffs2)
                    ex_s = int(f2(ex_r) % P)
                    ex_t1 = create_tag(mac_data1, ex_r, ex_s)
                    if num_to_16_le_bytes(t1) == ex_t1:
                        r, s = ex_r, ex_s
                        evil_mac_data = evil_cipher + pad16(evil_cipher)
                        evil_mac_data += struct.pack('<Q', len(bytearray(0)))
                        evil_mac_data += struct.pack('<Q', len(evil_cipher))
                        evil_tag = create_tag(evil_mac_data, r, s)
                        return evil_cipher.hex() + evil_tag.hex() + nonce.hex()


goal = b"But it's only secure if used correctly!"
p1 = b"Did you know that ChaCha20-Poly1305 is an authenticated encryption algorithm?" 
c1 = 'f0075f3b9eb1c513ec9c0133163698348795a28e00fb2847e2780ec4ff0c587c409b3b805cd025677e8ec37cc134aa5fefa153650177612a2e3f0866466fc875bcba45f618b01714675e110833df7e8fb1dec09da73028d4f2b4909bce39b59892b83c01acd380ad36' 
# c1 = hex(ChaCha20(p1) + tag1 + nonce)
c2 = 'e0065a6fc7b3d552e9814e2d426280279cc1848515cb6044bf3c4bb4e408446d10c460c65cc7606864c7c365dc28b611faa654241c7c716f2c230260463fd37af3b004e315f6802206876433c1d7d4fa76c959911bc139b59892b83c01acd380ad36' 
# c2 = hex(ChaCha20(p2) + tag2 + nonce)
payload = get_payload(c1, c2, p1, goal) 
# payload = hex(ChaCha20(goal) + tag_goal + nonce)
print(payload)
