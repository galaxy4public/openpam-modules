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
