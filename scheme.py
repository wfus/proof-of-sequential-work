"""
Relevant Parameters described in the paper

    N: The time parameter which we assume is of the form
    2^n-1 for an integer n

    H: (0, 1)^{<= w(n+1)} -> (0, 1)^w as a random oracle

    t: A statistical security parameter
    
    w: A statistical security parameter

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



"""
Selects chi from (0, 1)^w as the nonce
"""
def statement(w, t=1023, N=10000):
    return random.randint(0, 2**w - 1)


def compute_posw():
    raise NotImplementedError


def opening_challenge():
    raise NotImplementedError 


def open():
    raise NotImplementedError  


def verify():
    raise NotImplementedError 



def random_tests(): 
    print("Selecting from (0, 1)^1")
    print(statement(1))
    print(statement(1))
    print(statement(1))
    print(statement(1))

    print("Selecting from (0, 1)^3")
    print(statement(3))
    print(statement(3))
    print(statement(3))
    print(statement(3))

if __name__ == '__main__':
    random_tests() 


