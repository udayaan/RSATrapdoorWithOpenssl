struct acl
{
    int isdir;
    char* owner;
    char* named_users;
    char* onwer_group;
    char* named_groups;
    char* mask;
    char* others;
    char* default_owner;
    char* default_named_users;
    char* default_onwer_group;
    char* default_named_groups;
    char* default_mask;
    char* default_others;

};

char* OWNER = "user.owner";
char* NAMED_USERS = "user.named_users";
char* OWNER_GROUP = "user.owner_group";
char* NAMED_GROUPS = "user.named_groups";
char* MASK = "user.mask";
char* OTHERS = "user.others";

char* DEFAULT_OWNER = "user.default_owner";
char* DEFAULT_NAMED_USERS = "user.default_named_users";
char* DEFAULT_OWNER_GROUP = "user.default_owner_group";
char* DEFAULT_NAMED_GROUPS = "user.default_named_groups";
char* DEFAULT_MASK = "user.default_mask";
char* DEFAULT_OTHERS = "user.default_others";
