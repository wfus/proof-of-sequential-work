from scheme import statement, compute_posw, opening_challenge, verify, open, BinaryString
from util import sha256, sha256H

DEFAULT_w = 10
DEFAULT_t = 100 
DEFAULT_n = 10
DEFAULT_N = 2**(DEFAULT_n + 1) - 1 


def verifier_init(w=DEFAULT_w):
    return statement(w=w)


def prover_init(chi, N=DEFAULT_N, H=sha256H):
    return compute_posw(chi, N=N, H=H)

def verifier_challenge(n=DEFAULT_n, t=DEFAULT_t):
    return opening_challenge(n=n, t=t)


def prover_challenge(chi, G, gamma):
    return open(chi, G, gamma)


def verifier_check(chi, phi, gamma, tau, n=DEFAULT_n, N=DEFAULT_N, H=sha256H):
    return verify(chi, phi, gamma, tau, n=n, N=N, H=H) 



if __name__ == '__main__':
    print('Raymond.')
    chi = verifier_init()
    G = prover_init(chi)
    challenge_gamma = verifier_challenge()
    tau = prover_challenge(chi, G, challenge_gamma)
    print(verifier_check(chi, G.node[BinaryString(0, 0)]['label'], challenge_gamma, tau))


