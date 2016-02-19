# Homework 1 (CS5830) Intro to Cryptography
#Length Preserving Encryption
# Author: Daniel Speiser and Haiwei Su


"""
Why Feistel Encryption needs as least 4 round

Solution: 
For 1 round Feistel, since after encryption, the new left part is the same as original message right side which reveals the message.

For 2 round Feistel, let’s define the process: 
L’  <- R
R’ <- L⊕f(R)
L’’ <- R’
R’’ <- L’⊕f(R’)

where f() is round function. We can see that two messages with the same right half such that m1 = L1R, m2 = L2R. We also notice that for 2nd round Feistel, L1’’ = L1 ⊕ f(R), and L2’’ = L2⊕f(R). Therefore, we have L1’’ ⊕ L2’’ = L1 ⊕L2 which is equivalent to say using a one time pad on the left side.

For 3 round Feistel, let function F be the following algorithm:
(1). F get input L1 and R1 from input data, and put them into the encrypt function encrypt(L1, R1) to get encrypted ciphertext, S1, and T1 respectively. 
(2). F then chooses an element L2 != L1 and get encrypted text such that encrypt(L2, R1) to get corresponding encrypted cipher text S2 and T2. 
(3). Finally, we perform a decrypt where decrypt(S2, T2 ⊕ L1 ⊕ L2)  to S3 and T3. If we test if R3 = S2 ⊕S1⊕R1 and this is always true if only 3 round.

Reference:

https://courses.cs.washington.edu/courses/cse599b/06wi/lecture4.pdf

https://eprint.iacr.org/2008/036.pdf
"""
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
import base64
import binascii
import os

def xor(a,b):
    """
    xors two raw byte streams.
    """
    assert len(a) == len(b), "Lengths of two strings are not same. a = {}, b = {}".format(len(a), len(b))
    return ''.join(chr(ord(ai)^ord(bi)) for ai,bi in zip(a,b))

class MyFeistel:
    def __init__(self, key, num_rounds, backend=None):
        if backend is None:
            backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 16:
            raise ValueError(
                "Key must be 16 url-safe base64-encoded bytes. Got: {} ({})".format(key, len(key))
            )
        self._num_rounds = num_rounds
        self._encryption_key = key
        self._backend = backend
        self._round_keys = [self._encryption_key \
                            for _ in xrange(self._num_rounds)]
        for i  in xrange(self._num_rounds):
            if i==0: continue
            self._round_keys[i] = self._SHA256hash(self._round_keys[i-1])
        self._iv = os.urandom(16)

    def _SHA256hash(self, data):
        h = hashes.Hash(hashes.SHA256(), self._backend)
        h.update(data)
        return h.finalize()

    ################################################################################
    ## Below are some free utitlity functions. How/where to use them is up to you. ###

    def _pad_string(self, data):
        """Pad @data if required, returns a tuple containing a boolean
        (whether it is padded), and the padded string.
        """
        h_data = data.encode('hex')
        n = len(data)
        if n%2 == 0:
            return False, data
        l,r = h_data[:n], h_data[n:]
        l = '0' + l # I am padding at the beginning, you can do it in
                    # the end as well. Remember to update the unpad
                    # function accordingly.
        r = '0' + r
        return True, (l+r).decode('hex')

    def _unpad_string(self, is_padded, padded_str): # Not tested!
        if not is_padded:
            return padded_str
        n = len(padded_str)
        assert n%2 == 0, "Padded string must of even length. You are "\
            "probably sending something wrong. Note it contains both "\
            "left and right part. Otherwise, just do this unpadding in "\
            "your function"
        l, r = padded_str[:n/2], padded_str[n/2:]
        return (l.encode('hex')[1:] + r.encode('hex')[1:]).decode('hex')

    def _prf(self, key, data):
        """If you haven't figured this out already, this function instanctiate
        AES in CBC mode with static IV, to act as a round function,
        a.k.a. pseudorandom function generator.
        
        WARNING: I am leaving an intentional bug in the
        function. Figure that out, if you want to use this function.
        """
        padder = padding.PKCS7(ciphers.algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = ciphers.Cipher(ciphers.algorithms.AES(key),
                                   ciphers.modes.CBC(self._iv),
                                   self._backend).encryptor()
        return  (encryptor.update(padded_data) + encryptor.finalize())[:len(data)]
    
    def _prf_hash(self, key, data):
        """Just FYI, you can also instantiate round function ushig SHA256 hash
        function. You don't have to use this function.
        """
        out = self.SHA256hash(data+key) # TODO: SecCheck
        while len(out)<len(data):
            out += self.SHA256hash(out+key)
        return out[:len(data)]

    def _clear_most_significant_four_bits(self, s):
        """
        Clear the first four bits of s and set it to 0.
        e.g, 0xa1 --> 0x01, etc.
        """
        assert len(s) == 1, "You called _clear_most_significant_four_bits function, "\
            "and I only work with 1 byte"
        return ('0' + s.encode('hex')[1]).decode('hex')

    ## END-OF-FREE-LUNCH
    ################################################################################
    
    #Here, for Feistel encryption, for each round encryption, we first check if 
    #given data message needed to get padded. The function self._pad_string will
    #handle the padding part if needed. Next, we call self._feistel_round_enc for 
    #each round encryption and unpad the message before going to the next round. 
    #Finally, iterate till meet the round requirement. 
    def encrypt(self, data):
        ctx = data
        for i in range(self._num_rounds):
            is_padded, padded_data = self._pad_string(ctx)
            ctx = self._feistel_round_enc(padded_data, i)
            ctx = self._unpad_string(is_padded, ctx)
        return ctx

    #Decryption part has similar algorithm as encryption part except that 
    #the iterator of round is reverse of encryption round. The rest are the 
    #same as encryption. 
    def decrypt(self, ctx):
        data = ctx
        for i in range(self._num_rounds - 1, -1, -1):
            is_padded, padded_ctx = self._pad_string(data)
            data = self._feistel_round_dec(padded_ctx, i)
            data = self._unpad_string(is_padded, data)
        return data

    #According definition of feistle cipher, we first divide input
    #message inout left and right part with equal length
    #next, we xor the the left part of message and right part
    #message whose combines with round function
    #Finally, the new left part message is the xor message and new
    #right part of message is the left part of orginal message. We
    #concate them together as output message. 
    def _feistel_round_enc(self, data, round_num):
        """This function implements one round of Fiestel encryption block.
        """
        mid = len(data) / 2
        L, R = data[:mid], data[mid:]
        Ri = xor(L, self._prf(self._round_keys[round_num], R))
        
        print "ENC Round {0} key: {1}".format(round_num, binascii.b2a_hex(self._round_keys[round_num]))
        print "ENC Round {0} ctx: {1}".format(round_num, binascii.b2a_hex(Ri + R))
        
        return Ri + R
    #The idea of decrypt is the same as encryption. 
    def _feistel_round_dec(self, data, round_num):
        """This function implements one round of Fiestel decryption block.
        """
        mid = len(data) / 2
        Ri = data[mid:]
        Li = xor(data[:mid], self._prf(self._round_keys[round_num], Ri))

        print "DEC Round {0} key: {1}".format(round_num, binascii.b2a_hex(self._round_keys[round_num]))
        print "DEC Round {0} ctx: {1}".format(round_num, binascii.b2a_hex(Li + Ri))

        return Li + Ri
#This class is the instantiate of what we've implemented above with specific length
class LengthPreservingCipher(object):
    def __init__(self, key, length=5):
        self._length = length
        self._num_rounds = 10 # Hard code this. Don't leave this kind
                              # of parameter upto the developers.
        self._feistel = MyFeistel(key, self._num_rounds)

    def encrypt(self, data):
        assert len(data) == self._length, "Data size must equal the length defined in the instantiation of LengthPreservingCipher."
        return self._feistel.encrypt(data)

    def decrypt(self, data):
        assert len(data) == self._length, "Data size must equal the length defined in the instantiation of LengthPreservingCipher."
        return self._feistel.decrypt(data)