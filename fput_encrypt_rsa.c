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
#include "acl.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int isdir(char* path) 
{
    struct stat path_stat;
    if(stat(path,&path_stat)!=0) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    return S_ISDIR(path_stat.st_mode);
}

char* substring(char* target, char* string, int start, int end) {
    int j = 0;
    for(int i=start;i<end;++i)  {
        target[j] = string[i];
        j+=1;
    }
    target[j] = '\0';
    return target;
}

char* stringcat(char* dest, char* s) {
    int l = strlen(dest);
    dest = (char *)realloc(dest,(l+strlen(s)+1)*sizeof(char));
    for(int i=0;i<strlen(s);++i) {
        dest[l+i] = s[i];
    }
    dest[l+strlen(s)] = '\0';
    return dest;
}

char** comma_split(int* num, char* modf)
{
    int length = strlen(modf);

    int* indices = (int *)malloc(2*sizeof(int));
    indices[0] = -1;
    indices[1] = length;

    int i = 0;
    int n=1;
    while(i<length)
    {
        if(modf[i]-',' == 0) 
        {
            indices[n] = i;
            n+=1;
            indices = (int *)realloc(indices,(n+1)*sizeof(int));
            indices[n] = length; 
        }
        i+=1;
    }
    int numargs = n;
    if(length==0) 
    {
        numargs=0;
    }

    // make substrings

    char** args = (char **)malloc(numargs*sizeof(char*));
    for (int i=0;i<numargs;++i) {
        int slen = (indices[i+1] -  (indices[i]+1)) +1;
        args[i] = (char*)malloc(slen*sizeof(char));
        char* arg = args[i];
        int start = 0;
        arg = substring(arg,modf,indices[i]+1,indices[i+1]);
        // printf("%s\n",arg);
    }

    free(indices);
    *num = numargs;

    return args;
}

struct acl *load_acl(char *path)
{
    struct acl *meta = (struct acl *)malloc(sizeof(struct acl));
    int size;
    char buf[0];
    int bool_isdir = 0;
    
    
    bool_isdir = isdir(path);


    size = getxattr(path, OWNER, &buf, 0);
    ////acl_present(size);
    char *owner = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, OWNER, owner, size);
    owner[size] = '\0';

    size = getxattr(path, NAMED_USERS, &buf, 0);
    ////acl_present(size);
    char *named_users = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, NAMED_USERS, named_users, size);
    named_users[size] = '\0';

    size = getxattr(path, OWNER_GROUP, &buf, 0);
    ////acl_present(size);
    char *owner_group = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, OWNER_GROUP, owner_group, size);
    owner_group[size] = '\0';

    size = getxattr(path, NAMED_GROUPS, &buf, 0);
    ////acl_present(size);
    char *named_groups = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, NAMED_GROUPS, named_groups, size);
    named_groups[size] = '\0';

    size = getxattr(path, MASK, &buf, 0);
    ////acl_present(size);
    char *mask = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, MASK, mask, size);
    mask[size] = '\0';

    size = getxattr(path, OTHERS, &buf, 0);
    ////acl_present(size);
    char *others = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, OTHERS, others, size);
    others[size] = '\0';

    meta->isdir = bool_isdir;
    meta->owner = owner;
    meta->named_users = named_users;
    meta->onwer_group = owner_group;
    meta->named_groups = named_groups;
    meta->mask = mask;
    meta->others = others;

    if (bool_isdir==1) 
    {

        size = getxattr(path, DEFAULT_OWNER, &buf, 0);
        ////acl_present(size);
        char *default_owner = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_OWNER, default_owner, size);
        default_owner[size] = '\0';

        size = getxattr(path, DEFAULT_NAMED_USERS, &buf, 0);
        ////acl_present(size);
        char *default_named_users = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_NAMED_USERS, default_named_users, size);
        default_named_users[size] = '\0';

        size = getxattr(path, DEFAULT_OWNER_GROUP, &buf, 0);
        ////acl_present(size);
        char *default_owner_group = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_OWNER_GROUP, default_owner_group, size);
        default_owner_group[size] = '\0';

        size = getxattr(path, DEFAULT_NAMED_GROUPS, &buf, 0);
        ////acl_present(size);
        char *default_named_groups = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_NAMED_GROUPS, default_named_groups, size);
        default_named_groups[size] = '\0';

        size = getxattr(path, DEFAULT_MASK, &buf, 0);
        ////acl_present(size);
        char *default_mask = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_MASK, default_mask, size);
        default_mask[size] = '\0';

        size = getxattr(path, DEFAULT_OTHERS, &buf, 0);
        ////acl_present(size);
        char *default_others = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_OTHERS, default_others, size);
        default_others[size] = '\0';

        meta->default_owner = default_owner;
        meta->default_named_users = default_named_users;
        meta->default_onwer_group = default_owner_group;
        meta->default_named_groups = default_named_groups;
        meta->default_mask = default_mask;
        meta->default_others = default_others;
    
    }

    return meta;
}

void save_acl(char* path, struct acl* meta) {

    // printf("owner : %s\n",meta->owner);
    if (setxattr(path, OWNER, meta->owner, strlen(meta->owner), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, NAMED_USERS, meta->named_users, strlen(meta->named_users), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, OWNER_GROUP, meta->onwer_group, strlen(meta->onwer_group), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, NAMED_GROUPS, meta->named_groups, strlen(meta->named_groups), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, MASK, meta->mask, strlen(meta->mask), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, OTHERS, meta->others, strlen(meta->others), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if(meta->isdir==0){
        return;
    }
    if (setxattr(path, DEFAULT_OWNER, meta->default_owner, strlen(meta->default_owner), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, DEFAULT_NAMED_USERS, meta->default_named_users, strlen(meta->default_named_users), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, DEFAULT_OWNER_GROUP, meta->default_onwer_group, strlen(meta->default_onwer_group), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, DEFAULT_NAMED_GROUPS, meta->default_named_groups, strlen(meta->default_named_groups), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, DEFAULT_MASK, meta->default_mask, strlen(meta->default_mask), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, DEFAULT_OTHERS, meta->default_others, strlen(meta->default_others), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return;
}

void get_perm_value(char* value, char* mod) 
{
    int len = strlen(mod);
    int end = len-1;
    int size = 0;
    while(end>=0 && mod[end]-':'!=0) {
        size+=1;
        end-=1;
    }
    if(end<0){
        printf("Invalid arguments.\n");
        exit(EXIT_FAILURE);
    }
    value = (char*)realloc(value,(size+1)*sizeof(char));
    value = substring(value,mod,end+1,len);
    return;
}

void get_name(char* name, char* mod) {
    int len = strlen(mod);
    int colon[] = {-1,0};
    int pos=len-1;
    int x=1;
    while(pos>=0)
    {       
        if(mod[pos]-':'==0){
            if(x<0){
                break;
            }
            colon[x] = pos;
            x-=1;
        }
        pos-=1;
    }
    if(x==1){
        printf("YES %s\n",mod);
        printf("Invalid arguments.\n");
        exit(EXIT_FAILURE);
    }
    int size = colon[1]-colon[0]-1;
    name = realloc(name,(size+1)*sizeof(char));
    name = substring(name,mod,colon[0]+1,colon[1]);
    return;
}

int  checknameduser_or_grop_read_perm(char* username, struct acl* meta, int flag) {
    char* list;
    if(flag==0){
        list = meta->named_users;
    } 
    else if(flag==1) {
        list = meta->named_groups;
    }

    int len;
    char** names = comma_split(&len,list);
    char* perm = (char*)malloc(sizeof(char));
    perm[0] = '\0';
    char* mask = meta->mask;

    for (int i=0;i<len;++i) {
        char* ugname = (char*)malloc(sizeof(char));
        get_name(ugname,names[i]);
        if(strcmp(ugname,username)==0) {
            get_perm_value(perm,names[i]);
            free(ugname);
            break;   
        }
        free(ugname);
    }

    if(strlen(perm)!=0) {
        if(strlen(mask)==0 && perm[0]-'r'==0){
            free(perm);
            return 1;
        }
        else if(mask[0]-'r'==0 && perm[0]-'r'==0){
            free(perm);
            return 1;
        }
        else{
            free(perm);
            printf("Permission denied.\n");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}

void check_read_perm(uid_t ruid, gid_t gid, char* path) {

    struct acl* direc = load_acl(path);

    struct passwd* user; 
    if((user=getpwuid(ruid))==NULL) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct stat dirstat;
    if(stat(path,&dirstat)!=0) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    char* username = user->pw_name;
    char* perm;
    char* mask = direc->mask;

    if(dirstat.st_uid == ruid) {
        perm  = direc->owner;
        if(perm[0]-'r'==0){
            return;
        }
        else{
            printf("Permission denied.\n");
            exit(EXIT_FAILURE);
        }
    }
    if(dirstat.st_gid == gid) {
        perm = direc->onwer_group;
        if(strlen(mask)==0 && perm[0]-'r'==0){
            return;
        }
        else if(mask[0]-'r'==0 && perm[0]-'r'==0){
            return;
        }
        else{
            printf("Permission denied.\n");
            exit(EXIT_FAILURE);
        }
    }

    int flag;
    flag =  checknameduser_or_grop_read_perm(username,direc,0);
    if(flag==1){
        return;
    }
    
    int ngrps=1000;
    int* grps=(int*)malloc(ngrps*sizeof(gid_t));
    getgrouplist(username,gid,grps,&ngrps);
    struct group* gp;
    for(int j=0;j<ngrps;++j) {
        gid_t g = grps[j];
        gp = getgrgid(g);
        if(gp!=NULL){
            flag =  checknameduser_or_grop_read_perm(gp->gr_name,direc,1);
            if(flag==1){
                return;
            }
        } 
    }

    perm = direc->others;
    if(strlen(mask)==0 && perm[0]-'r'==0){

        return;
    }
    else if(mask[0]-'r'==0 && perm[0]-'r'==0){
        return;
    }
    else{
        printf("Permission denied.\n");
        exit(EXIT_FAILURE);
    }
}

int  checknameduser_or_grop_write_perm(char* username, struct acl* meta, int flag) {
    char* list;
    if(flag==0){
        list = meta->named_users;
    } 
    else if(flag==1) {
        list = meta->named_groups;
    }

    int len;
    char** names = comma_split(&len,list);
    char* perm = (char*)malloc(sizeof(char));
    perm[0] = '\0';
    char* mask = meta->mask;

    for (int i=0;i<len;++i) {
        char* ugname = (char*)malloc(sizeof(char));
        get_name(ugname,names[i]);
        if(strcmp(ugname,username)==0) {
            get_perm_value(perm,names[i]);
            free(ugname);
            break;   
        }
        free(ugname);
    }

    if(strlen(perm)!=0) {
        if(strlen(mask)==0 && perm[1]-'w'==0){
            free(perm);
            return 1;
        }
        else if(mask[1]-'w'==0 && perm[1]-'w'==0){
            free(perm);
            return 1;
        }
        else{
            free(perm);
            printf("Permission denied.\n");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}

void check_write_perm(uid_t ruid, gid_t gid, char* path) {

    struct acl* direc = load_acl(path);

    struct passwd* user; 
    if((user=getpwuid(ruid))==NULL) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct stat dirstat;
    if(stat(path,&dirstat)!=0) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    char* username = user->pw_name;
    char* perm;
    char* mask = direc->mask;

    if(dirstat.st_uid == ruid) {
        perm  = direc->owner;
        if(perm[1]-'w'==0){
            return;
        }
        else{
            printf("Permission denied.\n");
            exit(EXIT_FAILURE);
        }
    }
    if(dirstat.st_gid == gid) {
        perm = direc->onwer_group;
        if(strlen(mask)==0 && perm[1]-'w'==0){
            return;
        }
        else if(mask[1]-'w'==0 && perm[1]-'w'==0){
            return;
        }
        else{
            printf("Permission denied.\n");
            exit(EXIT_FAILURE);
        }
    }
    int flag;
    flag =  checknameduser_or_grop_write_perm(username,direc,0);
    if(flag==1){
        return;
    }
    
    int ngrps=1000;
    int* grps=(int*)malloc(ngrps*sizeof(gid_t));
    getgrouplist(username,gid,grps,&ngrps);
    struct group* gp;
    for(int j=0;j<ngrps;++j) {
        gid_t g = grps[j];
        gp = getgrgid(g);
        if(gp!=NULL){
            flag =  checknameduser_or_grop_write_perm(gp->gr_name,direc,1);
            if(flag==1){
                return;
            }
        } 
    }
    perm = direc->others;
    if(strlen(mask)==0 && perm[1]-'w'==0){
        return;
    }
    else if(mask[1]-'w'==0 && perm[1]-'w'==0){
        return;
    }
    else{
        printf("Permission denied.\n");
        exit(EXIT_FAILURE);
    }
}

char* readfile(char* path)
{
    char* agrs1[] = {"/bin/cat",path,(char*)0};
    int size=0;
    char* content = (char*)malloc(sizeof(char));
    content[0] = '\0';

    int exit_status;
    int fd[2];
    pipe(fd);

    int p = fork();

    if(p==0) {

        close(1);
        dup(fd[1]);
        close(fd[0]);
        close(fd[1]);

        if((exit_status = execv(agrs1[0],agrs1))!=0) {
            printf("%s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }
    
    else if (p>0) {
        close(fd[1]);
        waitpid(p,&exit_status,0);
        
        char buf[1];
        while(read(fd[0],buf,1)>0) {
            content[size] = buf[0];
            size+=1;
            content = (char*)realloc(content,(size+1)*sizeof(char));
        }
        content[size]='\0';
        close(fd[0]);
    }
    return content;
}

char* parentdirname(char* path) 
{
    char * prevdir = (char*)malloc(sizeof(char));
    prevdir[0] = '\0';
    int len = strlen(path);
    int end = len-1;
    int lastslash = 0;
    while (end>=0)
    {
        if(path[end]-'/'==0) {
            lastslash = end;
            break;
        }
        end-=1;
    }
    
    prevdir = (char*)realloc(prevdir,(lastslash)*sizeof(char));

    int start=0;
    while (start<lastslash) 
    {
        prevdir[start] = path[start];
        start+=1;
    }
    prevdir[start] = '\0';
    return prevdir;
}

void copy_default(char* path, struct acl* meta) 
{
    char * prevdir = parentdirname(path);

    if(strlen(prevdir)==0) {
        return;
    }
    struct acl* parentacl = load_acl(prevdir);

    if(parentacl->owner[0]-'r'!=0 && parentacl->owner[0]-'-'!=0) {
        /* acls not present in parent dir */
        return;
    }

    if(strlen(parentacl->default_owner)!=0) {
        meta->owner = parentacl->default_owner;
    }
    if(strlen(parentacl->default_named_users)!=0) {
        meta->named_users = parentacl->default_named_users;
    }
    if(strlen(parentacl->default_onwer_group)!=0) {
        meta->onwer_group = parentacl->default_onwer_group;
    }
    if(strlen(parentacl->default_named_groups)!=0) {
        meta->named_groups = parentacl->default_named_groups;
    }
    if(strlen(parentacl->default_mask)!=0) {
        meta->mask = parentacl->default_mask;
    }
    if(strlen(parentacl->default_others)!=0) {
        meta->others = parentacl->default_others;
    }
    if(meta->isdir==0) {
        return;
    }
    if(strlen(parentacl->default_owner)!=0) {
        meta->default_owner = parentacl->default_owner;
    }
    if(strlen(parentacl->default_named_users)!=0) {
        meta->default_named_users = parentacl->default_named_users;
    }
    if(strlen(parentacl->default_onwer_group)!=0) {
        meta->default_onwer_group = parentacl->default_onwer_group;
    }
    if(strlen(parentacl->default_named_groups)!=0) {
        meta->default_named_groups = parentacl->default_named_groups;
    }
    if(strlen(parentacl->default_mask)!=0) {
        meta->default_mask = parentacl->default_mask;
    }
    if(strlen(parentacl->default_others)!=0) {
        meta->default_others = parentacl->default_others;
    }
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

int main(int argc, char *argv[])
{
    char* keyfile = argv[1];
    char* privkey = argv[2];
    char* pubkey = argv[2];

    /* decrypt the random number file and obtain the random number */

    uid_t ruid = getuid();
    struct passwd* user;
    user = getpwuid(ruid);

    char **saltptr=(char**)malloc(0);
    char **passptr=(char**)malloc(0);
    readShadow(user->pw_name,saltptr,passptr);

    char*key = (char*)malloc(sizeof(char)*17);
    char* iv = (char*)malloc(sizeof(char)*17);

    EVP_BytesToKey(EVP_aes_128_cbc(),EVP_sha1(),*saltptr,*passptr,strlen(*passptr),1000,key,iv);



    return 0;
}
