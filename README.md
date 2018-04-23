# proof-of-sequential-work
Small repo for implementing the 2018 EUROCRYPT paper ["Simple Proofs of Sequential Work" by Cohen and Pietrzak](https://eprint.iacr.org/2018/183.pdf). Also used as part of our CS244 project in Professor Kung's class at Harvard University.

## Usage

Most of the scheme is implemented in ```scheme.py``` and the main functions for 
the prover and the verifier are listed in ```posw.py``` that can be imported
for use in other areas. You can run a small test by running 
```python3 posw.py``` 
which should return true. The file simulates running the scheme for an honest 
prover and verifier. 

## Parameters 

The parameters described in the paper (and are named in the same way in the source code) are
* __N__: The time parameter which we assume is of the form
    2^n-1 for an integer n
* __w__: A statistical security parameter from which the random nonce is generated from
* __H__: A random oracle 

## Scheme
The scheme is described in the paper as 

![Overall Scheme](docs/overallscheme.png)

The DAG used for the scheme is also constructed with specifications

![DAG Specifications](docs/graphdef.png)

## Acknowledgements
Many thanks to Professor Kung for his intellectually interesting discussions, as well as Marcus Comiter for all the help in the class. 

