from scheme import *
from util import sha256, sha256H
import matplotlib.pyplot as plt
import time

times = []
for n in range(1, 20):
    G = construct_dag(2 ** (n+1) - 1)
    chi = statement()
    G_prove = compute_posw(chi, G, n=n)
    gamma = opening_challenge(n=n)
    tau = compute_open(chi, G_prove, gamma)
    start = time.time()
    compute_verify(chi, G, G_prove.node[BinaryString(0, 0)]['label'], gamma, tau, n=n)
    diff = time.time() - start
    print(diff)
    times.append(diff)
print(times)
plt.plot(range(1, 15), times)
plt.show()