import random
import networkx as nx
import math
from util import sha256, sha256H
import secrets
import argparse


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

"""
Need to construct a custom class for binary string, 
since for our DAG we have to differentiate 01 and 1.
Therefore we will need both the length of the binary string 
and the value converted into an integer.
The {EMPTY} binary string will be length 0, intvalue 0  
"""
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

    def __gt__(self, other):
        if self.length > other.length:
            return True
        elif self.length < other.length:
            return False
        return self.intvalue > other.intvalue

    def __str__(self):
        return ''.join(list(map(str, self.get_bit_list())))
    
    # Flips the n^th least significant bit from 0 to 1 or vice versa
    # Returns a new BinaryString object, does not modify original
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
            if self.get_bit(self, n) == 1:
                self.flip_bit(self, n)
        else:
            if self.get_bit(self, n) == 0:
                self.flip_bit(self, n)


    # Gets the nth least significant bit.  
    def get_bit(self, n):
        assert(self.length > n)
        return (self.intvalue >> n) % 2

    # Gets the list of the bit representation. Returns a list of 
    # 0s and 1s as integers. Starts with least significant bit. 
    def get_bit_list(self):
        lst = []
        curr_int = self.intvalue
        for _ in range(self.length):
            lst = [curr_int % 2] + lst
            curr_int = (curr_int >> 1)
        return lst 

    # Truncates the least significant bit of the binary string. Returns
    # a new binary string object. 
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
Converts bit list to integer
"""
def bits_to_int(bit_list):
    val = 0
    for i in range(len(bit_list)):
        val *= 2
        val += int(bit_list[i])
    return val


"""
Get parents of a node in the DAG
"""
def get_parents(binary_str, n=DEFAULT_n):
    parents = []
    bit_list = binary_str.get_bit_list()
    length = binary_str.length
    if length == n:
        for i in range(1, length + 1):
            if bit_list[i - 1] == 1:
                parents.append(BinaryString(i, bits_to_int(bit_list[:i - 1] + [0])))
    else:
        parents.append(BinaryString(length + 1, bits_to_int(bit_list + [0])))
        parents.append(BinaryString(length + 1, bits_to_int(bit_list + [1])))
    return sorted(parents)
    

"""
Creates the DAG for a given size of graph
"""
def construct_dag(n=DEFAULT_n):
    G = nx.DiGraph()
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
Selects chi from (0, 1)^w as the nonce
"""
def statement(w=DEFAULT_w, secure=True):
    if secure:
        return secrets.randbelow(2**w - 1)
    else:
        return random.randint(0, 2**w - 1)


"""
Computes the function PoSW^Hx(N). It stores the the labels 
phi_P of the m highest layers, and sends the root label
phi = l_epsilon to the Verifier
"""
def compute_posw(chi, n=DEFAULT_n, H=sha256H):
    G = construct_dag(n)
    for elem in nx.topological_sort(G):
        hash_str = str(elem)
        for parent in get_parents(elem, n):
            hash_str += str(G.node[parent]['label'])
        G.node[elem]['label'] = H(chi, hash_str)
    return G


"""
Samples a random challenge gamma <- (0, 1)^{w * t}, essentially a list
of random gamma_1, ..., gamma_t sampled from (0, 1)^w
"""
def opening_challenge(n=DEFAULT_n, t=DEFAULT_t, secure=True, s=None):
    if not secure and s:
        random.seed(s)
    challenged_leaf = secrets.randbelow(2**n) if secure else random.randint(0, 2**n - 1)
    return [BinaryString(n, challenged_leaf) for _ in range(t)]


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
    (l_{gamma_i}, dict{alternate_siblings: l_{the alternate siblings})
"""
def compute_open(chi, G, gamma):
    # On a challenge gamma = [gamma_1, ..., gamma_n]
    # tau the label of node gamma_i, l_{gamma_i}, and all the 
    # labels of the siblings of the nodes of path from gamma_i to root.
    # Example for gamma_i = 0101
    # tau contains labels of: 0101, 0100, 011, 00 and 1
    tuple_lst = []
    # First get the list 
    for gamma_i in gamma:
        label_gamma_i = G.node[gamma_i]['label']
        label_gamma_i_siblings = {}
        for sib in path_siblings(gamma_i):
            label_gamma_i_siblings[sib] = G.node[sib]['label']
        tuple_lst += [(label_gamma_i, label_gamma_i_siblings)]
    return tuple_lst 


"""
Verifier computes and outputs verify^H(chi, N, phi, gamma, tau)
given either {accept, reject}
We will let accept be True and reject be False
"""
def compute_verify(chi, phi, gamma, tau, n=DEFAULT_n, H=sha256H):
    for i in range(len(gamma)):
        # Check validity of l_{gamma_i}
        tag, s_tags = tau[i]
        s_tags[gamma[i]] = tag
        hash_str = str(gamma[i])
        for parent in get_parents(gamma[i], n):
            if parent not in s_tags:
                return False
            hash_str += s_tags[parent]
        if tag != H(chi, hash_str):
            return False
        # Check "Merkle-like commitment"
        for j in reversed(range(n)):
            hash_str = str(gamma[i])[:j]
            gamma_l_0 = bits_to_int(gamma[i].get_bit_list()[:j] + [0])
            gamma_l_1 = bits_to_int(gamma[i].get_bit_list()[:j] + [1])
            gamma_l = bits_to_int(gamma[i].get_bit_list()[:j])
            hash_str += s_tags[BinaryString(j + 1, gamma_l_0)]
            hash_str += s_tags[BinaryString(j + 1, gamma_l_1)]
            s_tags[BinaryString(j, gamma_l)] = H(chi, hash_str)
        if phi != s_tags[BinaryString(0, 0)]:
            return False
    return True


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Runs a test prover-verifier proof of sequential work'
        + ' assuming both parties are honest.')
    parser.add_argument('-n', type=int, help='depth of the DAG', default=DEFAULT_n)
    parser.add_argument('-t', type=int,help='number of challenges in gamma', default=DEFAULT_t)
    args = parser.parse_args()

    print("\nStarting test run with honest Prover and Verifier...")
    chi = statement()
    print("\tGenerated statement: {}".format(chi))
    G = compute_posw(chi, n=args.n)
    print("\tComputed PoSW.".format(chi))
    gamma = opening_challenge(t=args.t)
    print("\tCreated challenge gamma with {} challenges.".format(len(gamma)))
    tau = compute_open(chi, G, gamma)
    print("\tComputed proof tau.")
    print("\tVerification: {}".format(compute_verify(chi, G.node[BinaryString(0, 0)]['label'], gamma, tau)))
    print("")
