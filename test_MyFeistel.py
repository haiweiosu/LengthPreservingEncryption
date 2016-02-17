from MyFeistel import MyFeistel, LengthPreservingCipher
import pytest
import base64
import os

class TestMyFeistel:
    def test_Functionality(self):
        key = base64.urlsafe_b64encode(os.urandom(16))
        feistel = MyFeistel(key, 10)

        # decrypt(encrypt(msg)) == msg
        for i in xrange(20):
            msg = os.urandom(40)
            assert feistel.decrypt(feistel.encrypt(msg)) == msg

    def test_AllLengthMessages(self):
        key = base64.urlsafe_b64encode(os.urandom(16))
        fstl = MyFeistel(key, 10)
        for i in xrange(101):
            txt = os.urandom(i+1)
            dtxt = fstl.decrypt(fstl.encrypt(txt))
            assert dtxt == txt


class TestLengthPreservingCipher:
    def test_Functionality(self):
        key = base64.urlsafe_b64encode(os.urandom(16))
        lpc = LengthPreservingCipher(key, length=5)

        # decrypt(encrypt(msg)) == msg
        for i in xrange(20):
            msg = os.urandom(5)
            assert lpc.decrypt(lpc.encrypt(msg)) == msg
