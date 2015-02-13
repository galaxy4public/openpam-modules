#pragma once

struct salt_parameters {
    int id;
    long rounds;
};

struct logindefs {
    int encrypt_method;
    long min_rounds;
    long max_rounds;
    long rounds;
    int pass_warn_age;
    int login_retries;
};

int logindefs_parse(struct logindefs* ctx);

// strcmp() implementation that will not short-circuit, which should thwart timing
// attacks on password checking. If the lengths of s1 and s2 differ, then behavior is
// undefined.
inline int safe_strcmp(const char* s1, const char* s2) {
    size_t i = 0;
    unsigned char d = 0U;
    while(s1[i] != '\0' && s2[i] != '\0') {
        d |= s1[i] ^ s2[i];
        i += 1;
    }

    return ((1 & ((d - 1) >> 8)) - 1);
}
