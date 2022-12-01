# Exercise

This exercise consists in:

-   proposing a compartmentalization policy for the rsa module of mbedtls (see library/rsa.c)
-   implementing a mechanism to enforce the policy, using mprotect ("mprotect() changes the access protections for the calling process's memory pages")

## Compartmentailzation policy

The goal of the policy is to prevent unauthorized accesses from the program using the rsa module to the rsa private key (by an attacker that manages to exploit the program). To this aim, we will only enable reading or writing of the mbedtls_rsa_context struct in the functions of rsa.c that should be allowed to work on it.

## Mechanism

In rsa.c, we add the necessary calls to mprotect and add functions to safely allocate a new mbedtls_rsa_context.
