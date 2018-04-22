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
Takes in two integers, a nonce and x, to serve as our oracle function.
This can be replaced with another function that can be used.  
"""
def sha256H(nonce, x):
    h = hashlib.sha256()
    first = str(nonce).encode('utf-8')
    second = str(x).encode('utf-8')
    h.update(first+second)
    return int(h.hexdigest(), 16) 




DEFAULT_w = 10
DEFAULT_t = 2**10 - 1
DEFAULT_N = 10000

"""
Selects chi from (0, 1)^w as the nonce
"""
def statement(w=DEFAULT_w, t=DEFAULT_t, N=DEFAULT_N):
    return random.randint(0, 2**w - 1)


def compute_posw(w=DEFAULT_w, t=DEFAULT_t, N=DEFAULT_N):
    raise NotImplementedError

"""
Samples a random challenge gamma <- (0, 1)^{w * t}, essentially a list
of random gamma_1, ..., gamma_t sampled from (0, 1)^w
"""
def opening_challenge(w=DEFAULT_w, t=DEFAULT_t, N=DEFAULT_N):
    return [random.randint(0, 2**w - 1) for i in range(t)]

"""
Prover computes tau := open^H(chi, N, phi_P, gamma) and sends it to 
the Verifier
"""
def open(chi, phi_P, gamma, N=DEFAULT_N):
    raise NotImplementedError  

"""
Verifier computes and outputs verify^H(chi, N, phi, gamma, tau)
given either {accept, reject}
We will let accept be True and reject be False
"""
def verify(chi, phi, gamma, tau, N=DEFAULT_N):
    raise NotImplementedError 



def random_tests(): 
    print("Selecting from (0, 1)^1")
    print(opening_challenge(t=10))

    print(sha256H(1, 10))
    print(sha256H(11, 0))
    print(sha256H(100, 1))
    print(sha256H(11, 100))


if __name__ == '__main__':
    random_tests() 


