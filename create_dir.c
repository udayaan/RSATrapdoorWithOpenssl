/*
write perm
use do_exec to mkdir
set default acls
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <errno.h>
#include "acl.h"
#include<dirent.h>
#include <pwd.h>
#include <grp.h>

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

int main(int argc, char *argv[])
{
    printf("Current effective user id:%d\n",geteuid());
    
    uid_t ruid = getuid();
    gid_t gid = getgid();

    char* parentdir = parentdirname(argv[1]);
    check_write_perm(ruid,gid,parentdir);
    free(parentdir);

    if(mkdir(argv[1],0777)!=0) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    chown(argv[1],ruid,gid);
    chmod(argv[1],0600);

    struct acl* meta = load_acl(argv[1]);
    meta->owner="rw-";
    meta->onwer_group="r--";
    meta->others = "r--";
    copy_default(argv[1],meta);
    save_acl(argv[1],meta);
    
    setuid(getuid());
    printf("Current effective user id:%d\n",geteuid());

    exit(EXIT_SUCCESS);
}
