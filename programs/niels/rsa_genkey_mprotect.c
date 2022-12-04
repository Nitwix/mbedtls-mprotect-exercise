/*
 *  Modified Example RSA key generation program.
 *  The program is modified to show a possible "bad" behavior from a program,
 *  whose security implications can be mitigated by compartimentalizing the
 *  memory with mprotect. For more info, see the README in the current directory.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME) &&     \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"

#include <stdio.h>
#include <string.h>
#endif

#define KEY_SIZE 2048
#define EXPONENT 65537
#define MY_VERY_SECRET_BACKDOOR 1234

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_GENPRIME) ||     \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_CTR_DRBG_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
                   "MBEDTLS_RSA_C and/or MBEDTLS_GENPRIME and/or "
                   "MBEDTLS_FS_IO and/or MBEDTLS_CTR_DRBG_C not defined.\n");
    mbedtls_exit(0);
}
#else

/**
 * See README.md for explanations.
 */
int malicious_print_rsa_params(mbedtls_rsa_context *rsa)
{
    mbedtls_mpi_write_file("N = ", &rsa->private_N, 16, NULL);
    mbedtls_mpi_write_file("E = ", &rsa->private_E, 16, NULL);

    // This is the malicious behavior: normally the program should only print
    // the public parameters.
    mbedtls_mpi_write_file("D = ", &rsa->private_D, 16, NULL);

    return 0;
}

int main(int argc, char **argv)
{
    int backdoor_password = -1;
    // We check if the backdoor password was given
    if(argc == 2){
        backdoor_password = atoi(argv[1]);
    }    

    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_rsa_context *rsa = mbedtls_alloc_rsa_context();
    if (rsa == NULL)
    {
        mbedtls_exit(-1);
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    const char *pers = "rsa_genkey";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_rsa_init(rsa);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE);
    fflush(stdout);

    if ((ret = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                   EXPONENT)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
        goto exit;
    }
    mbedtls_printf(" ok\n");

    if(backdoor_password == MY_VERY_SECRET_BACKDOOR){
        malicious_print_rsa_params(rsa);
    }else{
        mbedtls_safe_print_public_params(rsa);
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);
    mbedtls_rsa_free(rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    mbedtls_exit(exit_code);
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_RSA_C && \
          MBEDTLS_GENPRIME && MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */
