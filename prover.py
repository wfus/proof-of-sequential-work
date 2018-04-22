"""
Relevant Parameters described in the paper

    N: The time parameter which we assume is of the form
    2^n-1 for an integer n

    H: (0, 1)^{<= w(n+1)} -> (0, 1)^w as a random oracle

    t: A statistical security parameter

    M: Memory available to the prover, of the form
        (t + n*t + 1 + 2^{m+1})w, 
    0 <= m <= n
"""

import hashlib
import random

"""
Hashes an int using the sha256 algorithm, you have to first convert
to string first and back to an integer after getting the hex output
"""
def sha256(x):
    h = hashlib.sha256()
    h.update(str(x).encode('utf-8'))
    return int(h.hexdigest(), 16)


def prover():
    raise NotImplementedError


def verifier():
    raise NotImplementedError



def random_tests(): 
    print(sha256(100))
    print(sha256(200))
    print(sha256(100))

if __name__ == '__main__':
    random_tests() 


