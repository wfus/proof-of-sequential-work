import random
import networkx as nx
from util import sha256, sha256H


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


# Need to construct a custom class for binary string, 
# since for our DAG we have to differentiate 
# 01 and 1, unfortunately.
# Therefore we will need both the length of the binary string 
# and the value converted into an integer.
# The {EMPTY} binary string will be length 0, intvalue 0  
class BinaryString:
    def __init__(self, length, intvalue):
        assert(2 ** length > intvalue)
        self.length = length
        self.intvalue = intvalue
    
    def __eq__(self, other):
        return other and self.length == other.length and self.intvalue == other.intvalue

    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __hash__(self):
        return hash((self.length, self.intvalue))

    def __str__(self):
        first = "Length {}".format(self.length)
        second = ",{0:b}".format(self.intvalue)
        return first + second
    
    # Flips the n^th least significant bit from 0 to 1 or vice versa
    def flipbit(self, n):
        assert(length > n)
        raise NotImplementedError

    def get_bit_list(self):
        lst = []
        curr_int = self.intvalue
        for x in range(self.length):
            lst = [curr_int % 2] + lst
            curr_int = (curr_int >> 1)
        return lst 


    def truncate_last_bit(self, n):
        new_bin = BinaryString(self.length, self.intvalue)
        new_bin.intvalue = (self.intvalue >> 1)
        new_bin.length = self.length-1
        return new_bin
        raise NotImplementedError

DEFAULT_w = 10
DEFAULT_t = 2**10 - 1
DEFAULT_N = 2**10 



"""
Selects chi from (0, 1)^w as the nonce
"""
def statement(w=DEFAULT_w, t=DEFAULT_t, N=DEFAULT_N):
    return random.randint(0, 2**w - 1)


"""
Computes the function PoSW^Hx(N). It stores the the labels 
phi_P of the m highest layers, and sends the root label
phi = l_epsilon to the Verifier
"""
def compute_posw(w=DEFAULT_w, t=DEFAULT_t, n=10, N=DEFAULT_N, H=sha256H):
    G = nx.DiGraph()
    # Create a DAG with vertex set {0, ..., N-1}
    # and first make the full binary tree, then add extra relationships
    #               {empty}
    #               /     \
    #            {0}       {1}
    #           /   \     /   \
    #        {00}  {01} {10}  {11}
    #        /  \  /  \ /  \  /  \
    #      ... ... ... ... ... ... ... 
    #          ( to n levels deep )
    # Additionally, we will use the alternating path to the leaf. We will connect
    # the leaf to the left siblings only for the path. Look at figure 3 in the 
    # paper for more information
    for level in range(n+1):
        binstrs = [BinaryString(level, i) for i in range(2**level)]
        G.add_nodes_from(binstrs)
    
    return G


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
def open(chi, phi_P, gamma, N=DEFAULT_N, H=sha256H):
    # On a challenge gamma = [gamma_1, ..., gamma_n]
    # tau containa
    raise NotImplementedError  

"""
Verifier computes and outputs verify^H(chi, N, phi, gamma, tau)
given either {accept, reject}
We will let accept be True and reject be False
"""
def verify(chi, phi, gamma, tau, N=DEFAULT_N, H=sha256H):
    raise NotImplementedError 



def random_tests(): 
    print("Selecting from (0, 1)^1")
    print(opening_challenge(t=10))

    print(sha256H(1, 10))
    print(sha256H(11, 0))
    print(sha256H(100, 1))
    print(sha256H(11, 100))

    g = nx.DiGraph()
    g.add_node(1)
    g.add_nodes_from([2, 3])
    g.add_edge(1, 2)    
    print(g.nodes)

    print(BinaryString(3, 3))
    print(BinaryString(7, 31))
    print(BinaryString(1, 1))
    print(BinaryString(1, 0))


def graph_tests():
    G = compute_posw()
    print(G.nodes)


def class_tests():
    test1 = BinaryString(5, 10)
    test2 = BinaryString(1, 1)
    test3 = BinaryString(0, 0)
    test4 = BinaryString(10, 231)
    print(test1.get_bit_list())
    print(test2.get_bit_list())
    print(test3.get_bit_list())
    print(test4.get_bit_list())

if __name__ == '__main__':
    # random_tests() 
    # graph_tests()
    class_tests()
