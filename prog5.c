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

    BIGNUM *signature = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *message = BN_new();

    BN_hex2bn(&signature, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    BN_mod_exp(message, signature, e, n, ctx);

    printBN("message(hex) =", message);

    BN_CTX_free(ctx);

    return 0;
}