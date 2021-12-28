#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a) {
    // Convert the BIGNUM to hex string
    char *hex_str = BN_bn2hex(a);
    // Print out the hex string
    printf("%s %s\n", msg, hex_str);
    // Free the dynamically allocated memory
    OPENSSL_free(hex_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *n = BN_new();

    BIGNUM *p_sub_1 = BN_new();
    BIGNUM *q_sub_1 = BN_new();
    BIGNUM *lambda = BN_new();

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    BN_one(one);

    BN_sub(p_sub_1, p, one);
    BN_sub(q_sub_1, q, one);
    BN_mul(lambda, p_sub_1, q_sub_1, ctx);

    BN_mod_inverse(d, e, lambda, ctx);

    printBN("d = ", d);

    return 0;
}
