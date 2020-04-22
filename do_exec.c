// Udayaan Nath
// 2017119, CSE
// udayaan17119@iiitd.ac.in

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <errno.h>
#include "acl.h"

int isdir(char *path)
{
    struct stat path_stat;
    if (stat(path, &path_stat) != 0)
    {
        printf("%s\n", strerror(errno));
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

    if (bool_isdir == 1)
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

/* 
get sub-array of argv to pass to execv
*/
int get_argv(int start, int end, char *argv[], char *ptr[])
{

    int i;
    int maxlen = 0;

    for (i = 0; i < end - start; i++)
    {
        ptr[i] = argv[start + i];
    }
    /* argv ends with a NULL pointer, 
    otherwise Bad address in execv */
    ptr[i] = (char *)0;

    return (end - start + 1);
}

int main(int argc, char *argv[])
{
    printf("Current Effective user id: %d\n", geteuid());

    uid_t ruid = getuid();

    // struct stat filestat;
    int exit_status;
    // if((exit_status = stat(argv[1],&filestat))!=0){
    //     printf("%s : %s\n", argv[1],strerror(errno));
    //     exit(EXIT_FAILURE);
    // }
    // uid_t owner_id = filestat.st_uid;

    // setuid(owner_id);
    struct acl *meta = load_acl(argv[1]);
    if (meta->owner[2] - 'x' != 0)
    {
        printf("Permission denied.\n");
        exit(EXIT_FAILURE);
    }

    int fd[2];
    pipe(fd);

    int p = fork();

    if (p == 0)
    {

        close(1);
        dup(fd[1]);
        close(fd[0]);
        close(fd[1]);

        if ((exit_status = execv(argv[1], argv + 1)) != 0)
        {
            printf("%s\n", strerror(errno));
            setuid(getuid());
            printf("Current Effective user id: %d\n", geteuid());
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }

    else if (p > 0)
    {
        close(fd[1]);
        waitpid(p, &exit_status, 0);

        char buf[1];
        while (read(fd[0], buf, 1) > 0)
        {
            printf("%s", buf);
        }
        printf("\n");

        setuid(getuid());
        printf("Current Effective user id: %d\n", geteuid());

        exit(exit_status);
    }
}