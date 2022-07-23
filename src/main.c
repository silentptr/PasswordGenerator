#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#ifdef __WIN32
    #define SYS_PAUSE() if(system(NULL)){system("PAUSE");}
#elif
    #define SYS_PAUSE()
#endif

struct __SecureBuffer
{
    uint8_t* ptr;
    size_t length;
};

typedef struct __SecureBuffer* Buffer;

Buffer NewBuffer(size_t length)
{
    Buffer buffer = malloc(sizeof(struct __SecureBuffer));

    if (buffer == NULL)
    {
        return NULL;
    }

    buffer->length = length;
    buffer->ptr = malloc(length);

    if (buffer->ptr == NULL)
    {
        free(buffer);
        return NULL;
    }
    
    memset(buffer->ptr, 0, length);
    return buffer;
}

void DeleteBuffer(Buffer buffer)
{
    memset(buffer->ptr, 0, buffer->length);
    free(buffer->ptr);
    free(buffer);
}

#define CHECK_NULL_BUFFER(buff) if(buff==NULL){printf("An error has occured.\n");SYS_PAUSE();return 1;}

Buffer BufferToBase64(Buffer input)
{
    Buffer temp = NewBuffer(input->length * 2);

    if (temp == NULL)
    {
        return NULL;
    }

    size_t len = EVP_EncodeBlock(temp->ptr, input->ptr, input->length);
    Buffer result = NewBuffer(len + 1);

    if (result == NULL)
    {
        DeleteBuffer(temp);
        return NULL;
    }

    memcpy(result->ptr, temp->ptr, len + 1);
    DeleteBuffer(temp);
    return result;
}

int main(int argc, char** argv)
{
    printf("Welcome to password generator v1!\n");

    size_t length;

    if (argc == 2)
    {
        length = strtoull(argv[1], NULL, 10);
    }
    else
    {
        printf("Enter password length: ");
        char input[100];
        scanf("%s", input);
        length = strtoull(input, NULL, 10);
    }
    
    if (errno == ERANGE || length < 1 || length > 4096)
    {
        printf("Password length must be 1-4096 characters.\n");
        SYS_PAUSE();
        return 1;
    }
    
    printf("Generating a password of length %i...\n", length);
    Buffer randBuffer = NewBuffer(length);
    CHECK_NULL_BUFFER(randBuffer);

    if (RAND_bytes(randBuffer->ptr, length) != 1)
    {
        DeleteBuffer(randBuffer);
        printf("OpenSSL is fucked\n");
        SYS_PAUSE();
        return 1;
    }

    Buffer encodedBuffer = BufferToBase64(randBuffer);
    CHECK_NULL_BUFFER(encodedBuffer);
    DeleteBuffer(randBuffer);
    Buffer finalBuffer = NewBuffer(length + 1);
    CHECK_NULL_BUFFER(finalBuffer);
    memcpy(finalBuffer->ptr, encodedBuffer->ptr, length);
    DeleteBuffer(encodedBuffer);
    printf("Generated password: %s\n", finalBuffer->ptr);
    DeleteBuffer(finalBuffer);
    SYS_PAUSE();
    return 0;
}