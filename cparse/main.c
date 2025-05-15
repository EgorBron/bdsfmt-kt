#define fail(msg) { fprintf(stderr, "%s %s in %s at %s:%d: %s", __DATE__, __TIME__, __FILE__, __func__, __LINE__, msg); __fastfail(-1); }
#define assert(cond, msg) {if (!(cond)) fail(msg)}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum BDSFTypeEnum {
    EOT,
    Byte,
    Binary,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Int128,
    UInt128,
    BigInt,
    UBigInt,
    Float32,
    Double64,
    Decimal,
    String,
    String16,
    String32,
    Bool,
    DynamicArray,
    TypedArray,
    Dict,
    TypedDict,
    Timestamp32,
    Timestamp64,
    Null,
    ItemID16,
    ItemID32,
    LenArray,
    LenTypedArray,
    LenDict,
    LenTypedDict,
    EnumVal,
    LenString,

    Pair = 0xFE,
    Document = 0xFF,
} bdftype_t;

typedef struct BDSFPair {
    bdftype_t keyType;
    unsigned int offset;
} bdfpair_t;

typedef struct BDSDocKeyPair {
    char* key;
    bdfpair_t* type;
} bdfdockeypair_t;

unsigned char getByte(FILE* fptr) {
    int res = fgetc(fptr);
    if (res == EOF) goto err;
    return res;
    err:
    fclose(fptr);
    fail("failed to read next byte\n");
}

unsigned char* getBytes(FILE* fptr, int count) {
    unsigned char* b = malloc(count);
    if (b == NULL) goto err;
    unsigned char* res = fgets(b, count, fptr);
    if (res == NULL) goto err;
    return b;
    err:
    unsigned char* str;
    sprintf(str, "failed to read next %d bytes (read %d)\n", count, res);
    fclose(fptr);
    fail(str);
}

int main() {
    FILE* fptr;
    fptr = fopen("test.bdf", "rb");
    if (!fptr) fail("failed to open file\n");

    unsigned char docType = getByte(fptr);
    if (!docType) {
        fail("reading singledoc is not supported\n");
    }

    bdfdockeypair_t** pairs = NULL;
    int pairCount = 0;
    while (1) {
        unsigned char pairType = getByte(fptr);
        printf("pair type: %d\n", pairType);
        printf("read: %d (%d pairs)\n", ftell(fptr), pairCount);
        assert(pairType == Pair || pairType == Document || pairType == EOT, "expected pair type\n");

        if (pairType == EOT) continue;

        if (pairType == Document) {
            printf("document\n");
            fseek(fptr, -1, SEEK_CUR);
            break;
        }

        // allocate pair
        bdfdockeypair_t* docpair = malloc(sizeof(bdfdockeypair_t));
        bdfpair_t* pair = malloc(sizeof(bdfpair_t));
        if (docpair == NULL || pair == NULL) fail("failed to allocate memory for pair\n");
        docpair->key = NULL;
        (*docpair).type = pair;

        unsigned char keyType = getByte(fptr);
        printf("key type: %d\n", keyType);

        // read string until null terminator
        char* key = malloc(1);
        if (key == NULL) fail("failed to allocate memory for key\n");
        int len = 0;
        while (1) {
            char b = getByte(fptr);
            printf("current byte: %d, %d\n", b, b==0);
            // char* tkey = key;
            key = realloc(key, len + 1);
            printf("realloc\n");
            key[len++] = b;
            if (b == 0) {
                printf("breaking\n");
                break;
            }
        }
        printf("key: %s\n", key);
        (*pair).keyType = keyType;
        (*docpair).key = key;
        printf("assigned\n");

        // read offset
        // unsigned char* offsetBytes = getBytes(fptr, 3);
        // printf("offset bytes: %u %u %u %u\n", offsetBytes[0], offsetBytes[1], offsetBytes[2], offsetBytes[3]);
        // (*pair).offset = offsetBytes[0] | offsetBytes[1] << 8 | offsetBytes[2] << 16 | offsetBytes[3] << 24;

        (*pair).offset = getByte(fptr);

        printf("offset: %u\n", pair->offset);


        pairs = realloc(pairs, (pairCount + 1) * sizeof(bdfdockeypair_t*));
        if (pairs == NULL) fail("failed to allocate memory for pairs\n");
        pairs[pairCount++] = docpair;
    }

    // while (1) {
    // }
    fclose(fptr);
    fptr = NULL;

    if (pairs != NULL) {
        for (int i = 0; i < pairCount; i++) {
            bdfdockeypair_t* pair = pairs[i];
            // deconstruct values of pair
            char* key = pair->key;
            bdfpair_t* type = pair->type;
            printf("key %s No. %d: %d:%d\n", key, i, type->keyType, type->offset);
        }
        free(pairs);
    }
    return 0;
}