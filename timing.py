from posw import *
from util import sha256, sha256H
import matplotlib.pyplot as plt
import time
import timeit

MAX_N_LEN = 20 

def time_posw_construction():
    time_posw = []
    time_verify = []
    for n in range(1, MAX_N_LEN):
        chi = statement()
        start = time.time()
        G = compute_posw(chi, n=n)
        diff = time.time() - start
        print(diff)
        time_posw.append(diff)
        gamma = opening_challenge(n=n)
        tau = compute_open(chi, G, gamma)
        start = time.time()
        compute_verify(chi, G.node[BinaryString(0, 0)]['label'], gamma, tau, n=n)
        diff = time.time() - start
        print(diff)
        time_verify.append(diff)
    print(time_posw)
    print(time_verify)


    plt.title("POSW compute time vs DAG depth ")
    plt.xlabel("n")
    plt.ylabel("Time (s)")
    plt.plot(range(1, MAX_N_LEN), time_posw)
    plt.show()
    plt.title("Verification time vs DAG depth")
    plt.xlabel("n")
    plt.ylabel("Time (s)")
    plt.plot(range(1, MAX_N_LEN), time_verify)
    plt.show()


if __name__ == '__main__':
    print(timeit.timeit("statement()", setup="from posw import statement", number=1000))