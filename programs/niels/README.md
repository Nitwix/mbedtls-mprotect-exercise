# Exercise

This exercise consists in:

-   proposing a compartmentalization policy for the rsa module of mbedtls (see library/rsa.c)
-   implementing a mechanism to enforce the policy, using mprotect ("mprotect() changes the access protections for the calling process's memory pages")

## Compartmentailzation policy

The goal of the policy is to prevent unauthorized accesses from the program using the rsa module to the rsa private key (by an attacker that manages to exploit the program). To this aim, we will only enable reading or writing of the mbedtls_rsa_context struct in the functions of rsa.c that should be allowed to work on it. This way, we also respect the principle of least privilege.

## Mechanism

In rsa.c, we add the necessary calls to mprotect and add functions to safely allocate a new mbedtls_rsa_context.
More precisely, the following was done:
- `mbedtls_rsa_context *mbedtls_alloc_rsa_context()` was added to rsa.c. It allows to allocate a new rsa context struct on the heap (as opposed to previously where the struct was on the stack), and it performs the appropriate call to mprotect to disable access to the struct once it has been allocated. This call allocates a whole page, from start to finish, otherwise other parts of the programs might allocate memory adjacent to the struct (on the same page) and cause segmentation faults when trying to access it. This is because mprotect protects the whole page.
- `int mbedtls_safe_print_public_params(mbedtls_rsa_context *rsa)` was added to rsa.c. It prints the public RSA parameters from the RSA context provided as an argument. This calls mprotect at the start and finish of the function, to enable reading and then disable it again.
- `void mbedtls_rsa_init(mbedtls_rsa_context *ctx)` was modified in rsa.c. Similarly as in the previous function, we need to call mprotect before and after using the struct. What's different is that in this function we need write access.
- `int mbedtls_rsa_gen_key(mbedtls_rsa_context *ctx, ...)` was modified in rsa.c. Similar modification as before, except that this function needs read and write access.
- `void mbedtls_rsa_free(mbedtls_rsa_context *ctx)` was modified in rsa.c. Similarly, we need to enable read and write at the start (to be able to clean the struct's internal values). But contrary to all the other modifications, at the end of the function, we don't want to re-enable memory protection, because we consider that this memory doesn't belong to this program anymore. Another modification that was needed was to free the struct itself, because it is now allocated on the heap.

Note: not all functions were modified because the modification is essentially always the same, and the goal was really to demonstrate how mprotect can be used to protect a memory region, not to implement a fully mprotected rsa module.

## Demo program: rsa_genkey_mprotect.c
This program demonstrates how we could use the modified rsa.c module to prevent a malicious access to the rsa context struct that exposes the private exponent d.

### A malicious backdoor...
The (not very realistic) scenario is that a malicious actor managed to insert `int malicious_print_rsa_params(mbedtls_rsa_context *rsa)` as a backdoor into a program that normally only generates and prints public RSA parameters. The backdoor functions by providing a backdoor password as a command line argument. If it is correct, `malicious_print_public_params` gets called and prints the public *and private* parameters. Otherwise, `mbedtls_safe_print_public_params(rsa);` is executed and safely prints the public RSA paramaters.

### How safety is achieved
Because `malicious_print_rsa_params` accesses the rsa context struct without disabling its protection (provided via mprotect), the call causes a SIGSEGV which prevents the malicious behaviour (printing the private RSA parameters).

### Building
To build the demonstration program, execute `make programs` in the top-level directory of this repository.

### Executing
From this directory (`programs/niels`):
- as an attacker attempting to use his backdoor: `./rsa_genkey_mprotect 1234`. This should result in a SIGSEGV, as expected.
- as a regular user expecting to print freshly generated public parameters: `./rsa_genkey_mprotect`. This should print freshly generated public parameters.