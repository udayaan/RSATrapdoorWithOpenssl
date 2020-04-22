#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <errno.h>
#include "acl.h"
#include<pwd.h>
#include<grp.h>

void acl_present(int status) 
{
    if(status==-1)
    {
        printf("ACLs not present in this file.\n");
        exit(EXIT_FAILURE);
    }
    return;
}

struct acl *load_acl(char *path)
{
    struct acl *meta = (struct acl *)malloc(sizeof(struct acl));
    int size;
    char buf[0];
    int bool_isdir = 0;
    
    struct stat path_stat;
    if(stat(path,&path_stat)!=0) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    bool_isdir = S_ISDIR(path_stat.st_mode);


    size = getxattr(path, OWNER, &buf, 0);
    acl_present(size);
    char *owner = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, OWNER, owner, size);
    owner[size] = '\0';

    size = getxattr(path, NAMED_USERS, &buf, 0);
    acl_present(size);
    char *named_users = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, NAMED_USERS, named_users, size);
    named_users[size] = '\0';

    size = getxattr(path, OWNER_GROUP, &buf, 0);
    acl_present(size);
    char *owner_group = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, OWNER_GROUP, owner_group, size);
    owner_group[size] = '\0';

    size = getxattr(path, NAMED_GROUPS, &buf, 0);
    acl_present(size);
    char *named_groups = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, NAMED_GROUPS, named_groups, size);
    named_groups[size] = '\0';

    size = getxattr(path, MASK, &buf, 0);
    acl_present(size);
    char *mask = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, MASK, mask, size);
    mask[size] = '\0';

    size = getxattr(path, OTHERS, &buf, 0);
    acl_present(size);
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
        acl_present(size);
        char *default_owner = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_OWNER, default_owner, size);
        default_owner[size] = '\0';

        size = getxattr(path, DEFAULT_NAMED_USERS, &buf, 0);
        acl_present(size);
        char *default_named_users = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_NAMED_USERS, default_named_users, size);
        default_named_users[size] = '\0';

        size = getxattr(path, DEFAULT_OWNER_GROUP, &buf, 0);
        acl_present(size);
        char *default_owner_group = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_OWNER_GROUP, default_owner_group, size);
        default_owner_group[size] = '\0';

        size = getxattr(path, DEFAULT_NAMED_GROUPS, &buf, 0);
        acl_present(size);
        char *default_named_groups = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_NAMED_GROUPS, default_named_groups, size);
        default_named_groups[size] = '\0';

        size = getxattr(path, DEFAULT_MASK, &buf, 0);
        acl_present(size);
        char *default_mask = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_MASK, default_mask, size);
        default_mask[size] = '\0';

        size = getxattr(path, DEFAULT_OTHERS, &buf, 0);
        acl_present(size);
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

void display_acl(struct acl* s, char* path) {
    struct stat file;
    if(stat(path, &file)!=0) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    struct passwd* user=getpwuid(file.st_uid);
    struct group* grp = getgrgid(file.st_gid);

    printf("#Owner:%s\n",user->pw_name);
    printf("#Group:%s\n",grp->gr_name);

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

    struct acl* p=load_acl(argv[1]);
    display_acl(p,argv[1]);

    setuid(getuid());
    printf("Current effective user id:%d\n",geteuid());

    return 0;
}
