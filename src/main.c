#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/rand.h>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
    #define SYS_PAUSE() if(system(NULL)){system("PAUSE");}
#else
    #define SYS_PAUSE()
#endif

const uint8_t ALL_CHARS[] =
{
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '!', '#', '$', '%', '&', '*'
};

const uint8_t SYMBOL_CHARS[] =
{
    '!', '#', '$', '%', '&', '*'
};

bool bignum_to_size_t(BIGNUM* bn, size_t* out)
{
    char* str = BN_bn2dec(bn);

    if (str == NULL)
    {
        return false;
    }

    if (sscanf(str, "%zu", out) != 1)
    {
        OPENSSL_free(str);
        return false;
    }

    OPENSSL_free(str);
    return true;
}

int gen_password(size_t length, uint8_t* buffer)
{
    BIGNUM* rnd = BN_new();

    if (rnd == NULL)
    {
        return 0;
    }

    BIGNUM* range = BN_new();

    if (range == NULL)
    {
        BN_free(rnd);
        return 0;
    }

    int error;
    size_t symbol_count = 0;
    bool symbol;
    uint8_t new_char;
    size_t char_index;

    for (size_t i = 0; i < length; ++i)
    {
        if (RAND_poll() == 0)
        {
            BN_free(rnd);
            BN_free(range);
            return 1;
        }

        if (i == length - 1 && symbol_count == 0)
        {
            BN_set_word(range, 6);
            symbol = true;
        }
        else
        {
            BN_set_word(range, 68);
            symbol = false;
        }

        BN_zero(rnd);

        if (BN_rand_range(rnd, range) == 0)
        {
            BN_free(rnd);
            BN_free(range);
            return 1;
        }

        if (bignum_to_size_t(rnd, &char_index) == false)
        {
            BN_free(rnd);
            BN_free(range);
            return 1;
        }

        if (symbol)
        {
            new_char = SYMBOL_CHARS[char_index];
        }
        else
        {
            new_char = ALL_CHARS[char_index];

            if (char_index > 61)
            {
                ++symbol_count;
            }
        }

        buffer[i] = new_char;
    }

    BN_free(rnd);
    BN_free(range);
    return 1;
}

int main(int argc, char** argv)
{
    printf("Welcome to password generator v1.1!\n");

    size_t length = 0;

    if (argc == 2)
    {
        length = strtoull(argv[1], NULL, 10);
    }
    else
    {
        printf("Enter password length: ");
        char input[100];

        if (scanf("%s", input))
        {
            length = strtoull(input, NULL, 10);
        }
    }
    
    if (errno == ERANGE || length < 1 || length > 4096)
    {
        printf("Password length must be 1-4096 characters.\n");
        SYS_PAUSE()
        return EXIT_FAILURE;
    }
    
    printf("Generating a password of length %zu...\n", length);
    uint8_t* buffer = malloc(length + 1);
    buffer[length] = 0;

    if (!gen_password(length, buffer))
    {
        memset(buffer, 0, length + 1);
        free(buffer);
        printf("Couldn't create password.\n");
        return EXIT_FAILURE;
    }

    printf("Generated password: %s\n", buffer);
    memset(buffer, 0, length + 1);
    free(buffer);
    SYS_PAUSE()
    return EXIT_SUCCESS;
}