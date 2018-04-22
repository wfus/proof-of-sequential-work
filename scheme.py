import random
import networkx as nx
import math
from util import sha256, sha256H
import copy
import matplotlib.pyplot as plt


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
        return ''.join(list(map(str, self.get_bit_list())))
    
    # Flips the n^th least significant bit from 0 to 1 or vice versa
    def flip_bit(self, n):
        assert(self.length > n)
        if self.get_bit(n) == 0:
            self.intvalue = self.intvalue + (2 ** n) 
        else:
            self.intvalue = self.intvalue - (2 ** n) 
        return BinaryString(self.length, self.intvalue)

    def set_bit(self, n, bitvalue):
        assert(self.length > n)
        assert(bitvalue == 1 or bitvalue == 0)
        if bitvalue == 0:
            if get_bit(self, n) == 1:
                flip_bit(self, n)
        else:
            if get_bit(self, n) == 0:
                flip_bit(self, n)


    # Gets the nth least significant bit. 
    def get_bit(self, n):
        assert(self.length > n)
        return (self.intvalue >> n) % 2
    
    def get_bit_list(self):
        lst = []
        curr_int = self.intvalue
        for x in range(self.length):
            lst = [curr_int % 2] + lst
            curr_int = (curr_int >> 1)
        return lst 


    def truncate_last_bit(self):
        new_bin = BinaryString(self.length, self.intvalue)
        new_bin.intvalue = (self.intvalue >> 1)
        new_bin.length = self.length-1
        return new_bin



DEFAULT_w = 10
DEFAULT_t = 2**10 - 1
DEFAULT_n = 10
DEFAULT_m = 10
DEFAULT_N = 2**(DEFAULT_n + 1) - 1 



"""
Selects chi from (0, 1)^w as the nonce
"""
def statement(w=DEFAULT_w, t=DEFAULT_t, N=DEFAULT_N):
    return random.randint(0, 2**w - 1)

def bits_to_int(bit_list):
    val = 0
    for i in range(len(bit_list)):
        val *= 2
        val += int(bit_list[i])
    return val

def construct_dag(N=DEFAULT_N):
    G = nx.DiGraph()
    n = int(math.log(N + 1, 2) - 1)
    binstrs = []
    for level in range(n+1):
        binstrs = [BinaryString(level, i) for i in range(2 ** level)]
        G.add_nodes_from(binstrs)
        if level > 0:
            for node in binstrs:
                bit_list = node.get_bit_list()
                G.add_edge(node, BinaryString(level - 1, bits_to_int(bit_list[:level - 1])))
    for leaf in binstrs:
        bit_list = leaf.get_bit_list()
        for i in range(1, len(bit_list) + 1):
            if bit_list[i - 1] == 1:
                G.add_edge(BinaryString(i, bits_to_int(bit_list[:i - 1] + [0])), leaf)
    return G

"""
Computes the function PoSW^Hx(N). It stores the the labels 
phi_P of the m highest layers, and sends the root label
phi = l_epsilon to the Verifier
"""
def compute_posw(chi, N=DEFAULT_N, H=sha256H):
    G = construct_dag(N)
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
    for elem in nx.topological_sort(G):
        hash_str = str(elem)
        for parent in G.predecessors(elem):
            hash_str += str(G.node[parent]['label'])
        G.node[elem]['label'] = H(chi, hash_str)
    return G


"""
Samples a random challenge gamma <- (0, 1)^{w * t}, essentially a list
of random gamma_1, ..., gamma_t sampled from (0, 1)^w
"""
def opening_challenge(n=DEFAULT_n, t=DEFAULT_t, N=DEFAULT_N):
    return [BinaryString(n, random.randint(0, 2**n - 1)) for i in range(t)]


"""
Takes in an instance of class BinaryString and returns a list of the 
siblings of the nodes of the path to to root of a binary tree. Also
returns the node itself, so there are N+1 items in the list for a 
tree with length N. 
"""
def path_siblings(bitstring):
    path_lst = [bitstring]
    new_bitstring = BinaryString(bitstring.length, bitstring.intvalue)
    for i in range(bitstring.length):
        path_lst += [new_bitstring.flip_bit(0)]
        new_bitstring = new_bitstring.truncate_last_bit() 
    return path_lst


"""
Prover computes tau := open^H(chi, N, phi_P, gamma) and sends it to 
the Verifier. phi_P will be passed in using a NetworkX graph G
Returns a list of tuples described by
    (l_{gamma_i}, [l_{the alternate siblings}])
"""
def open(chi, phi_P, gamma, H=sha256H):
    # On a challenge gamma = [gamma_1, ..., gamma_n]
    # tau the label of node gamma_i, l_{gamma_i}, and all the 
    # labels of the siblings of the nodes of path from gamma_i to root.
    # Example for gamma_i = 0101
    # tau contains labels of: 0101, 0100, 011, 00 and 1
    tuple_lst = []
    # First get the list 
    for gamma_i in gamma:
        label_gamma_i = phi_P.node[gamma_i]['label']
        label_gamma_i_siblings = [phi_P.node[x]['label'] for x in path_siblings(gamma_i)]
        tuple_lst += [(label_gamma_i, label_gamma_i_siblings)]
    return tuple_lst 

"""
Verifier computes and outputs verify^H(chi, N, phi, gamma, tau)
given either {accept, reject}
We will let accept be True and reject be False
"""
def verify(chi, phi, gamma, tau, H=sha256H):
    # Check validity of l_{gamma_i}
    for i in range(len(gamma)):
        tag, parent_tags = tau[i]
        print(tag, H(chi, str(gamma[i]).join(parent_tags)))
        if tag != H(chi, str(gamma[i]).join(parent_tags)):
            return False
    return True



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


def test_path_siblings():
    for x in path_siblings(BinaryString(5, 10)):
        print(x)

    for x in path_siblings(BinaryString(4, 10)):
        print(x)


if __name__ == '__main__':
    # random_tests() 
    # graph_tests()
    # class_tests()
    # test_path_siblings()
    chi = statement()
    G = compute_posw(chi)
    gamma = opening_challenge()
    tau = open(chi, G, gamma)
    print(verify(chi, G.node[BinaryString(0, 0)]['label'], gamma, tau))
