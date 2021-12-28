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

    BIGNUM *m = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *signature = BN_new();
    BIGNUM *dec = BN_new();


    BN_hex2bn(&m, "49206f776520796f752024323030302e");
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&e, "010001");

    BN_mod_exp(signature, m, d, n, ctx);

    printBN("signature =", signature);

    BN_mod_exp(dec, signature, e, n, ctx);

    printBN("decrypted message =", dec);
    
    BN_CTX_free(ctx);

    return 0;
}