#include<stdio.h>
#include<stdlib.h>
#include<time.h>
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


long long gen_rand(int len) {
    long long base = 1;
    for (int i=0;i<len-1;++i) {
        base = base*10;
    }

    srand(time(0)); 
    int r = rand();
    long long num = r;
    if(r<base) {
        num = base + r;
    }
    else if(r>=base && r<base*10) {
        num = r;
    }
    else if(r>=base*10) {
        num = r%(base*10);
    }
    return num;
}

void ltoa(long long num,char* dest,int len){
    long long sub =0;
    long long base = 10;
    int start = len-1;
    while (num>0) 
    {
        long d = num%base;
        sub = d;
        d = d/(base/10);
        dest[start--] = '0'+d;
        base=base*10;
        num -= sub;
    }
    dest[len] = '\0';
    return;
}

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

int do_crypt(FILE *in, FILE *out, char* key, char* iv, int do_encrypt)
{
    /* Allow enough space in output buffer for additional block */
    unsigned char *inbuf, *outbuf;
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;
    

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    while(1)
    {
        inbuf = (char*)malloc(sizeof(char)*16);
        outbuf = (char*)malloc(sizeof(char)*32);
        inlen = fread(inbuf, 1, 16, in);
        if(inlen <=0) break;

        if(!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen))
        {
            /* Error */
            EVP_CIPHER_CTX_free(ctx);
            abort();
        }
        fwrite(outbuf, 1, outlen, out);
        free(inbuf);
        free(outbuf);
    }
    outbuf = (char*)malloc(sizeof(char)*32);
    if(!EVP_CipherFinal_ex(ctx, outbuf, &outlen))
    {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        abort();
    }
    fwrite(outbuf, 1, outlen, out);
    free(outbuf);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

void create_sign(char* filepath, char* number) {
    char* args[5];
    args[0] = "./fsign.o";
    args[1] = filepath;
    args[4] = '\0';

    int exit_status;
    int fd[2];
    if(pipe(fd)!=0) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    pid_t p = fork();
    if(p==0) {
        close(0);
        dup(fd[0]);
        close(fd[1]);

        if(execv(args[0],args)!=0) {
            exit(EXIT_FAILURE);
        }

    }

    close(fd[0]);
    write(fd[1],number,strlen(number));
    close(fd[1]);
    waitpid(p,&exit_status,0);

    return;
}

int main(int argc, char  *argv[])
{
    int len = atoi(argv[1]);
    long long randnum = gen_rand(len);
    char* number = (char*)malloc(sizeof(char)*(len+1));
    ltoa(randnum,number,len);

    char* filename = argv[2];
    char* path = "/home/";
    char* filepath = (char*)malloc(sizeof(char)*7);
    strcpy(filepath,path);
    strcat(filepath,filename);

    uid_t ruid = getuid();
    struct passwd* user;
    user = getpwuid(ruid);

    char **saltptr=(char**)malloc(0);
    char **passptr=(char**)malloc(0);
    readShadow(user->pw_name,saltptr,passptr);

    char*key = (char*)malloc(sizeof(char)*17);
    char* iv = (char*)malloc(sizeof(char)*17);

    EVP_BytesToKey(EVP_aes_128_cbc(),EVP_sha1(),*saltptr,*passptr,strlen(*passptr),1000,key,iv);

    fwrite(number,1,len,stdin);
    fclose(stdin);

    
    FILE* f = fopen(filepath,"wb");
    do_crypt(stdin,f,key,iv,1);
    fclose(f);

    create_sign(filepath, number);

    exit(EXIT_SUCCESS);
}


