#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/openpam.h>
#include <security/pam_mod_misc.h>
#include "util.h"

#define LOGIN_DEFS "/etc/login.defs"

#define SALT_ID_SHA256		5
#define SALT_ID_SHA512		6
#define DEFAULT_SALT_ID		SALT_ID_SHA512
#define DEFAULT_SALT_ROUNDS	10000

#define HARD_MIN_ROUNDS		1000
#define HARD_MAX_ROUNDS		999999999

#define MAX_RETRIES 		3
#define DEFAULT_WARN		(2L * 7L) /* two weeks */

// A locale-independent isspace-implementation
// Config file grammar should not depend on locale
static bool simple_isspace(unsigned char b) {
    switch(b) {
        case ' ':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
        case '\v':
            return true;
    }

    return false;
}

// Initialize a login.defs configuration context with default values. These
// will be used if login.defs could not be found, or if a value is not defined.
static void logindefs_init(struct logindefs* ctx) {
    ctx->pass_warn_age = DEFAULT_WARN;
    ctx->encrypt_method = DEFAULT_SALT_ID;
    ctx->min_rounds = DEFAULT_SALT_ROUNDS;
    ctx->max_rounds = DEFAULT_SALT_ROUNDS;
    ctx->rounds = DEFAULT_SALT_ROUNDS;
    ctx->login_retries = MAX_RETRIES;
}

// Parse a single field in login.defs
static void logindefs_parse_field(const char* key, const char* val, struct logindefs* ctx) {
    if(val == NULL || key == NULL) { return; }

    if(!strcasecmp(key, "PASS_WARN_AGE")) {
        ctx->pass_warn_age = atoi(val);
    } else if(!strcasecmp(key, "ENCRYPT_METHOD")) {
		if(!strcasecmp(key, "SHA512")) { ctx->encrypt_method = SALT_ID_SHA512; }
		else if(!strcasecmp(key, "SHA256")) { ctx->encrypt_method = SALT_ID_SHA256; }
    } else if(!strcasecmp(key, "LOGIN_RETRIES")) {
        ctx->login_retries = atoi(val);
    } else {
        PAM_LOG("Unknown login.defs field: %s", key);
    }
}

int logindefs_parse(struct logindefs* ctx) {
    char* buf = NULL;
    size_t buflen = 0;
    FILE* f = fopen(LOGIN_DEFS, "r");

    logindefs_init(ctx);

    if(f == NULL) {
        PAM_WARN("Could not open %s", LOGIN_DEFS);
        return 1;
    }

    while(!feof(f)) {
        ssize_t n = getline(&buf, &buflen, f);
        if(n < 0) { break; }

        char* cursor = buf;

        // Skip leading whitespace
        while(simple_isspace((int)*cursor)) { ++cursor; }

        // Skip comments
        char* comment = strchr(buf, '#');
        if(comment != NULL) { *comment = '\0'; }

        // Skip lines with no remaining content
        if(*cursor == '\0') { continue; }

        // Strip trailing newlines
        {
            const size_t len = strlen(cursor);
            if(cursor[len - 1] == '\n') {
                cursor[len - 1] = '\0';
            }
        }

        char* field_key = strsep(&cursor, " \t=");
        if(cursor != NULL) {
            while(simple_isspace((int)*cursor) || *cursor == '=') {
                ++cursor;
            }
        }

        logindefs_parse_field(field_key, cursor, ctx);
    }

    free(buf);
    fclose(f);

    // Finalization
	long rounds = (ctx->min_rounds > ctx->max_rounds) ? ctx->min_rounds : ctx->max_rounds;
	if(rounds == 0) { rounds = DEFAULT_SALT_ROUNDS; }
	else if(rounds < HARD_MIN_ROUNDS) { rounds = HARD_MIN_ROUNDS; }
	else if(rounds > HARD_MAX_ROUNDS) { rounds = HARD_MAX_ROUNDS; }
	ctx->rounds = rounds;

    return 0;
}
