//  pam_usermatch module, v1.0.0
//
//  by Martin Young <martin_young@live.cn>, 2023-10-21

#include <cstring>
#include <regex>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

using namespace std;

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int retval;
    bool allow, match;
    const char *puser;
    regex user_regex;

    switch(argc) {
    case 0:
        pam_syslog(pamh, LOG_ERR, "No option");
        return PAM_SERVICE_ERR;
    case 1:
        pam_syslog(pamh, LOG_ERR, "Less option");
        return PAM_SERVICE_ERR;
    default:
        if( strcmp(argv[1], "allow")==0 )
            allow = true;
        else if( strcmp(argv[1], "deny")==0 )
            allow = false;
        else {
            pam_syslog(pamh, LOG_ERR, "Bad option: \"%s\"", argv[1]);
            return PAM_SERVICE_ERR;
        }
    }

    if( (retval=pam_get_item(pamh, PAM_USER, (const void **)&puser)) != PAM_SUCCESS ) {
        pam_syslog(pamh, LOG_ERR, "Cannot determine username: %s", pam_strerror(pamh, retval));
        return retval;
    }
    if( !(puser && *puser) ) {
        pam_syslog(pamh, LOG_ERR, "Cannot determine username");
        return PAM_SERVICE_ERR;
    }

    try {
        user_regex = regex(argv[0], regex_constants::egrep);
    } catch(regex_error& e) {
        pam_syslog(pamh, LOG_ERR, "Regular expression error: %s", e.what());
        return PAM_SERVICE_ERR;
    }

    match = regex_match(puser, user_regex);

    if( !(allow = allow? match : !match) )
        pam_syslog(pamh, LOG_NOTICE, "Access denied: Invalid username string");

    return allow? PAM_SUCCESS:PAM_AUTH_ERR;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

int pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

int pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

int pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

int pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}
