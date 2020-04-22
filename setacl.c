#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <errno.h>
#include "acl.h"
#include <pwd.h>
#include <grp.h>

void acl_present(int status) 
{
    if(status==-1)
    {
        printf("ACLs not present in this file.\n");
        exit(EXIT_FAILURE);
    }
    return;
}

int isdir(char* path) 
{
    struct stat path_stat;
    if(stat(path,&path_stat)!=0) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    return S_ISDIR(path_stat.st_mode);
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
    // TODO
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
    if(isdir(path)==0){
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

char* substring(char* target, char* string, int start, int end) {
    int j = 0;
    for(int i=start;i<end;++i)  {
        target[j] = string[i];
        j+=1;
    }
    target[j] = '\0';
    return target;
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

char* comma_concat(int num, char** names) {
    if(num==0) {
        free(names);
        char* value = (char*)malloc(sizeof(char));
        value[0] = '\0';
        return value;
    }
    
    for(int i=0;i<num-1;++i) {
        names[0] = strcat(names[0],",");
        names[0] = strcat(names[0],names[i+1]);
        free(names[i+1]);
    }
    return names[0];
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
        printf("Invalid arguments.\n");
        exit(EXIT_FAILURE);
    }
    int size = colon[1]-colon[0]-1;
    name = realloc(name,(size+1)*sizeof(char));
    name = substring(name,mod,colon[0]+1,colon[1]);
    return;
}

void add_named_user_or_group(struct acl* meta,int flag, char* name, char* value) 
{
    // flag == 0 then user, flag==1 then group, flag==2  for default user, flag==3 for default group
    int num;
    char** names;
    if(flag == 0) 
    {
        names = comma_split(&num,meta->named_users); 
    }
    else if(flag==1)
    {
        names = comma_split(&num,meta->named_groups);
    }
    else if(flag==2)
    {
        names = comma_split(&num,meta->default_named_users);
    }
    else if(flag==3)
    {
        names = comma_split(&num,meta->default_named_groups);
    }

    int i;

    for(i=0;i<num;++i) {
        char* ugname = (char*)malloc(sizeof(char));
        get_name(ugname,names[i]);
        if(strcmp(ugname,name)==0) {
            ugname = strcat(ugname,":");
            ugname = strcat(ugname,value);
            free(names[i]);
            names[i] = ugname;
            break;
        }

        free(ugname);
    }
    if(num==0) {
        num+=1;
        names = (char**)malloc(num*sizeof(char*));
        name = strcat(name,":");
        name = strcat(name,value);
        names[num-1] = name;
    }
    
    else if(num>0 && i==num) 
    {
        num+=1;
        names = (char**)realloc(names,num*sizeof(char*));
        name = strcat(name,":");
        name = strcat(name,value);
        free(names[num-1]);
        names[num-1] = name;
    }
    
    char* newval = comma_concat(num,names);
    
    if(flag==0) {
        free(meta->named_users);
        meta->named_users = newval;    
    }    
    else if(flag==1) {
        free(meta->named_groups);
        meta->named_groups = newval;
    }
    else if(flag==2) {
        free(meta->default_named_users);
        meta->default_named_users = newval;
    }
    else if(flag==3) {
        free(meta->default_named_groups);
        meta->default_named_groups = newval;
    }

    return;
}

void update_user_perm(struct acl* meta, char* mod, int flag) {
    /* flag == 0 for user, flag == 1 for default user */

    if(mod[1]-':'==0 && mod[2]-':'==0) {
        char* value = (char*)malloc(sizeof(char));
        get_perm_value(value,mod);
        if(flag==0) {
            free(meta->owner);
            meta->owner = value;
        }
        else if(flag==1) {
            free(meta->default_owner);
            meta->default_owner = value;    
        }   
    }
    else {
        char* value = (char*)malloc(sizeof(char));
        get_perm_value(value,mod);
        char* name = (char*)malloc(sizeof(char));
        get_name(name,mod);
        if(flag==0) {
            add_named_user_or_group(meta,0,name,value);
        }
        else if (flag==1) {
            add_named_user_or_group(meta,2,name,value);
        }
    }
}

void update_group_perm(struct acl* meta, char* mod, int flag) {
    /* flag == 0 for group, flag == 1 for default group */

    if(mod[1]-':'==0 && mod[2]-':'==0) {
        char* value = (char*)malloc(sizeof(char));
        get_perm_value(value,mod);
        if(flag==0){
            free(meta->onwer_group);
            meta->onwer_group = value;
        }
        else if (flag==1)
        {
            free(meta->default_onwer_group);
            meta->default_onwer_group = value;
        }
    }
    else {
        char* value = (char*)malloc(sizeof(char));
        get_perm_value(value,mod);
        char* name = (char*)malloc(sizeof(char));
        get_name(name,mod);
        if(flag==0)
        {
            add_named_user_or_group(meta,1,name,value);
        }
        else if(flag==1)
        {
            add_named_user_or_group(meta,3,name,value);
        }
    }
}

void modify_acl(int numargs, char** argmods, struct acl* meta, char* path) 
{
    for (int i=0;i<numargs;++i) {
        char* mod = argmods[i];
        char first = mod[0];
        if (first-'u'==0) 
        {
            update_user_perm(meta,mod, 0);
        }
        else if(first-'g'==0) 
        {
            update_group_perm(meta, mod, 0);
        }
        else if(first-'m'==0) {
            char* value = (char*)malloc(sizeof(char));
            get_perm_value(value,mod);
            free(meta->mask);
            meta->mask = value;
        }
        else if(first-'o'==0) {
            char* value = (char*)malloc(sizeof(char));
            get_perm_value(value,mod);
            free(meta->others);
            meta->others = value;
        }

        else if(first-'d'==0) {
    
            int bool_isidr = isdir(path);
            if(bool_isidr==0)
            {
                printf("%s: Only directories can have default ACLs.", path);
                exit(EXIT_FAILURE);
            }
            if(strlen(mod)<5) {
                printf("Invalid arguments.\n");
                exit(EXIT_FAILURE);
            }
            char c = mod[2];
            char* newmod = (char*)malloc(sizeof(char));
            newmod = substring(newmod,mod,2,strlen(mod));

            if(c-'u'==0) {
                update_user_perm(meta,newmod,1);
            }
            else if(c-'g'==0) {
                update_group_perm(meta,newmod,1);
            }
            else if(c-'m'==0) {
                char* value = (char*)malloc(sizeof(char));
                get_perm_value(value,newmod);
                free(meta->default_mask);
                meta->default_mask = value;
            }
            else if(c-'o'==0) {
                char* value = (char*)malloc(sizeof(char));
                get_perm_value(value,newmod);
                free(meta->default_others);
                meta->default_others = value;
            }

            // setting default values of default owner, default other and default group
            if(strlen(meta->default_owner)==0) {
                char* value = (char*)malloc(sizeof(char));
                value = substring(value,"rwx",0,3);
                free(meta->default_owner);
                meta->default_owner = value;
            }
            if(strlen(meta->default_onwer_group)==0) {
                char* value = (char*)malloc(sizeof(char));
                value = substring(value,"r-x",0,3);
                free(meta->default_onwer_group);
                meta->default_onwer_group = value;
            }
            if(strlen(meta->default_others)==0) {
                char* value = (char*)malloc(sizeof(char));
                value = substring(value,"r-x",0,3);
                free(meta->default_others);
                meta->default_others = value;   
            }
        } 
    }
}

void remove_named_user_or_group(struct acl* meta, int flag, char* name) 
{
    // flag == 0 then user, flag==1 then group, flag==2  for default user, flag==3 for default group
    int num;
    char** names;
    if(flag == 0) 
    {
        names = comma_split(&num,meta->named_users); 
    }
    else if(flag==1)
    {
        names = comma_split(&num,meta->named_groups);
    }
    else if(flag==2)
    {
        names = comma_split(&num,meta->default_named_users);
    }
    else if(flag==3)
    {
        names = comma_split(&num,meta->default_named_groups);
    }

    char** newnames = (char**)malloc(sizeof(char*));
    int newsize = 0;
    int i=0;
    for (i=0;i<num;++i) {
        char* ugname = (char*)malloc(sizeof(char));
        get_name(ugname,names[i]);
        if(strcmp(ugname,name)!=0) {
            newsize+=1;
            newnames = (char**)realloc(newnames,newsize*sizeof(char*));
            newnames[newsize-1] = names[i];
        }
        else {
            free(names[i]);
        }
        free(ugname);
    }

    char* newval = comma_concat(newsize,newnames);
    
    if(flag==0) {
        free(meta->named_users);
        meta->named_users = newval;    
    }    
    else if(flag==1) {
        free(meta->named_groups);
        meta->named_groups = newval;
    }
    else if(flag==2) {
        free(meta->default_named_users);
        meta->default_named_users = newval;
    }
    else if(flag==3) {
        free(meta->default_named_groups);
        meta->default_named_groups = newval;
    }

    return;
}

void remove_acl(int numargs, char** argmods, struct acl* meta, char* path) 
{
    for (int i=0;i<numargs;++i) 
    {
        char* mod = argmods[i];
        char first = mod[0];
        if(first-'u'==0) {
            char* name = (char*)malloc(sizeof(char));
            get_perm_value(name,mod);
            remove_named_user_or_group(meta,0,name);
        }
        else if(first-'g'==0) {
            char* name = (char*)malloc(sizeof(char));
            get_perm_value(name,mod);
            remove_named_user_or_group(meta,1,name);
        }
        else if(first-'m'==0) {
            char* value = (char*)malloc(sizeof(char));
            value[0]='\0';
            free(meta->mask);
            meta->mask = value;
        }
        else if (first-'d'==0) 
        {
            int bool_isidr = isdir(path);
            if(bool_isidr==0)
            {
                printf("%s: Only directories can have default ACLs.", path);
                exit(EXIT_FAILURE);
            }

            if(strlen(meta->default_owner)==0) {
                continue;
            }

            if(strlen(mod)==3 && (mod[2]-'u'==0)) {
                char* value = (char*)malloc(sizeof(char));
                value = substring(value,"rwx",0,3);
                free(meta->default_owner);
                meta->default_owner = value;
            }
            else if(strlen(mod)>3 && (mod[2]-'u'==0)) {
                char* name = (char*)malloc(sizeof(char));
                get_perm_value(name,mod);
                remove_named_user_or_group(meta,2,name);   
            }
            else if(strlen(mod)==3 && (mod[2]-'g'==0)) {
                char* value = (char*)malloc(sizeof(char));
                value = substring(value,"r-x",0,3);
                free(meta->default_onwer_group);
                meta->default_onwer_group = value;
            }
            else if(strlen(mod)>3 && (mod[2]-'g'==0)) {
                char* name = (char*)malloc(sizeof(char));
                get_perm_value(name,mod);
                remove_named_user_or_group(meta,3,name);
            }
            else if(strlen(mod)==3 && (mod[2]-'m'==0)) {
                char* value = (char*)malloc(sizeof(char));
                value[0]='\0';
                free(meta->default_mask);
                meta->default_mask = value;
            }
            else if(strlen(mod)==3 && (mod[2]-'o'==0)) {
                char* value = (char*)malloc(sizeof(char));
                value=substring(value,"r-x",0,3);
                free(meta->default_others);
                meta->default_others = value;
            }
            else if(strlen(mod)==1 && (mod[0]-'d'==0)) {
                char* value = (char*)malloc(sizeof(char));
                value=substring(value,"rwx",0,3);
                free(meta->default_owner);
                meta->default_owner = value;
                
                value = (char*)malloc(sizeof(char));
                value=substring(value,"r-x",0,3);
                free(meta->default_onwer_group);
                meta->default_onwer_group = value;
                free(meta->default_others);
                meta->default_others = value;

                value = (char*)malloc(sizeof(char));
                value[0]='\0';
                free(meta->default_named_users);
                meta->default_named_users = value;
                free(meta->default_named_groups);
                meta->default_named_groups = value;
                free(meta->default_mask);
                meta->default_mask = value;
                
            }
        }
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

void display_acl(struct acl* s) {
    printf("OWNER:%s\n",s->owner);
    printf("NAMED_USERS:%s\n",s->named_users);
    printf("OWNER_GROUP:%s\n",s->onwer_group);
    printf("NAMED_GROUPS:%s\n",s->named_groups);
    printf("MASK:%s\n",s->mask);
    printf("OTHERS:%s\n",s->others);
    if(s->isdir==1) 
    {
        printf("DEFAULT_OWNER:%s\n",s->default_owner);
        printf("DEFAULT_NAMED_USERS:%s\n",s->default_named_users);
        printf("DEFAULT_OWNER_GROUP:%s\n",s->default_onwer_group);
        printf("DEFAULT_NAMED_GROUPS:%s\n",s->default_named_groups);
        printf("DEFAULT_MASK:%s\n",s->default_mask);
        printf("DEFAULT_OTHERS:%s\n",s->default_others);  
    }
    return;
}

int main(int argc, char *argv[])
{   
    printf("Current effective user id:%d\n",geteuid());
    
    if(argc<4) 
    {
        printf("Invalid argumnets.");
        exit(EXIT_FAILURE);
    }

    uid_t ruid = getuid();
    gid_t gid = getgid();
    struct stat filestat;
    if(stat(argv[3],&filestat)!=0) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    uid_t ownuid = filestat.st_uid;
    struct passwd* fakeroot;
    fakeroot=getpwnam("fakeroot");
    if(ruid==ownuid) {
        /* do nothing */
    }
    else if (fakeroot!=NULL && fakeroot->pw_uid == ruid)
    {
        /* do nothing */
    }
    else
    {
        check_write_perm(ruid,gid,argv[3]);    
    }

    if(strcmp(argv[1],"-m")==0) 
    {
        //modify acl
        char* modf = argv[2];
        int numargs;
        char** argmods = comma_split(&numargs,modf);

        if(numargs==0) {
            printf("Invalid arguments.\n");
            exit(EXIT_FAILURE);
        }
        char* path = argv[3];
        struct acl* meta = load_acl(path);
        
        modify_acl(numargs,argmods,meta,path);
        // display_acl(meta);
        //save acl struct
        save_acl(path,meta);
    }
    else if (strcmp(argv[1],"-x")==0)
    {
        //remove acl entries
        char* modf = argv[2];
        int numargs;
        char** argmods = comma_split(&numargs,modf);
        if(numargs==0) {
            printf("Invalid arguments.\n");
            exit(EXIT_FAILURE);
        }
        char* path = argv[3];
        struct acl* meta = load_acl(path);

        remove_acl(numargs,argmods,meta, path);

        // display_acl(meta);
        // save acl
        save_acl(path,meta);
    }
    
    setuid(getuid());
    printf("Current effective user id:%d\n",geteuid());

    return 0;
}
