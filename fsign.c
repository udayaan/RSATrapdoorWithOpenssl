
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


int readShadow(char* uname, char** saltptr, char** passptr){

    FILE *f;
    f = fopen("/etc/shadow","r");
    if(f==NULL) {
        printf("Cannot open /etc/shadow/.\n");
        exit(0);
    }

    fseek(f,0L,SEEK_END);
    long int size = ftell(f);
    fclose(f);

    // printf("%ld\n",size);
    f = fopen("/etc/shadow","r");
    if(f==NULL) {
        printf("Cannot open /etc/shadow/.\n");
        exit(EXIT_FAILURE);
    }

    char buff[size+1];
    char c;
    long int i=0;
    c = fgetc(f);
    while(c!=EOF) {
        buff[i++] = c;
        c = fgetc(f);
    }
    buff[i++]='\0';
    fclose(f);
    // printf("%s\n",buff);

    i=0;
    char* pass;
    char* salt;
    while(i<=size) {
        if(buff[i]==uname[0]){
            long int j = i; 
            int k = 0;
            int namelen = strlen(uname);
            while(buff[j++]==uname[k++]) {
                if(k==namelen) break;
            }
            if(k!=namelen) {i++;continue;}

            int cdollar = 0;
            while(cdollar<2) {
                if(buff[j++]=='$') cdollar++;
            }
            salt = (char *)malloc(sizeof(char));
            pass = (char *)malloc(sizeof(char));
            int saltlen = 0;
            int passlen = 0;
            while(buff[j]!='$') {
                salt[saltlen++] = buff[j++];
                salt = (char*)realloc(salt,sizeof(char)*(saltlen+1));
            }
            salt[saltlen] = '\0';
            j++;
            while(buff[j]!=':') {
                pass[passlen++] = buff[j++];
                pass = (char*)realloc(pass,sizeof(char)*(passlen+1));
            }
            pass[passlen] = '\0';
        }
        i++;
    }
    if(strlen(salt)==0 || strlen(pass)==0) return -1;
    *saltptr = salt;
    *passptr = pass;
    return 0;
}

void HMAC_sign(FILE* in, FILE* out, EVP_PKEY* pkey) {

    EVP_MD_CTX* ctx;
    char* sign; size_t siglen;

    ctx = EVP_MD_CTX_create();

    if(EVP_DigestInit_ex(ctx,EVP_get_digestbyname("SHA256"),NULL)!=1) {
        printf("EVP_DigestInit_ex Failed.\n");
        EVP_MD_CTX_destroy(ctx);
        abort();
    }

    if(EVP_DigestSignInit(ctx,NULL,EVP_get_digestbyname("SHA256"),NULL,pkey)!=1) {
        printf("EVP_DigestSignInit Failed.\n");
        EVP_MD_CTX_destroy(ctx);
        abort();
    }

    while(1) {
        char* inbuf=malloc(sizeof(char)*17);
        size_t inlen = fread(inbuf,1,16,in);

        if(inlen<=0) break;

        if(EVP_DigestSignUpdate(ctx,inbuf,inlen)!=1) {
            printf("EVP_DigestSignUpdate Failed.\n");
            EVP_MD_CTX_destroy(ctx);
            abort();
        }

        free(inbuf);
    }

    size_t len;
    if(EVP_DigestSignFinal(ctx, NULL, &len)!=1) {
        printf("EVP_DigestSignFinal(1) Failed.\n");
        EVP_MD_CTX_destroy(ctx);
        abort();
    }

    sign = (char*)malloc(sizeof(char)*len);
    siglen = len;

    if(EVP_DigestSignFinal(ctx, sign, &siglen)!=1) {
        printf("EVP_DigestSignFinal(2) Failed.\n");
        EVP_MD_CTX_destroy(ctx);
        abort();
    }

    fwrite(sign,1,siglen,out);

    EVP_MD_CTX_destroy(ctx);
    return;
}

int main(int argc, char *argv[])
{
    uid_t ruid = getuid();
    struct passwd* user;
    user = getpwuid(ruid);

    char** saltptr=(char**)malloc(0);
    char** passptr=(char**)malloc(0);
    readShadow(user->pw_name,saltptr,passptr);

    EVP_PKEY *key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,NULL,*passptr,strlen(*passptr));

    char* filesign=argv[1];
    strcat(filesign,".sign");

    FILE* out = fopen(filesign,"wb");
    HMAC_sign(stdin,out,key);
    fclose(out);

    exit(EXIT_SUCCESS);
}