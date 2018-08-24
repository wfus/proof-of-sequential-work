import secrets
import random
import time
from posw import *
from util import *


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
    chi = statement()
    G = compute_posw(chi)
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
    print("Starting tests.")
    random_tests()
    graph_tests()
    class_tests()
    test_path_siblings()
