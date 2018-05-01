from posw import *
from util import sha256, sha256H
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
    statement_time = timeit.timeit("statement()", setup="from posw import statement", number=1000)
    print("Average statement time: {}".format(statement_time / 1000.0))
    balloon_hash_time = timeit.timeit("balloon_hash('ht', 'kung', space=100, time=100)", setup="from balloon import balloon_hash", number=10)
    print("Average balloon hash time with t=100: {}".format(balloon_hash_time / 10.0))
    balloon_hash_time = timeit.timeit("balloon_hash('ht', 'kung', space=100, time=200)", setup="from balloon import balloon_hash", number=10)
    print("Average balloon hash time with t=200: {}".format(balloon_hash_time / 10.0))
    balloon_hash_time = timeit.timeit("balloon_hash('ht', 'kung', space=100, time=300)", setup="from balloon import balloon_hash", number=10)
    print("Average balloon hash time with t=300: {}".format(balloon_hash_time / 10.0))
    balloon_hash_time = timeit.timeit("balloon_hash('ht', 'kung', space=100, time=400)", setup="from balloon import balloon_hash", number=10)
    print("Average balloon hash time with t=400: {}".format(balloon_hash_time / 10.0))
