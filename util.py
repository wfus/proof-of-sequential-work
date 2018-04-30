import hashlib
import random
import networkx as nx


"""
Hashes an int using the sha256 algorithm, you have to first convert
to string first and back to an integer after getting the hex output
"""
def sha256(x, secure=True):
    if secure:
        raise NotImplementedError
    else:
        h = hashlib.sha256()
        h.update(str(x).encode('utf-8'))
        return '{0:0256b}'.format(int(h.hexdigest(), 16))


"""
Takes in two integers, a nonce and x, to serve as our oracle function.
This can be replaced with another function that can be used.  
"""
def sha256H(nonce, x, secure=True):
    if secure:
        raise NotImplementedError
    else:
        h = hashlib.sha256()
        first = str(nonce).encode('utf-8')
        second = str(x).encode('utf-8')
        h.update(first+second)
        return '{0:0256b}'.format(int(h.hexdigest(), 16))