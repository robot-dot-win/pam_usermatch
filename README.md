## DESCRIPTION
pam_usermatch is a Linux PAM module which provides a way to verify ```username``` against a regular expression that follows Egrep POSIX grammar.

If ```username``` matches the regular expression and the second argument is "allow", it succeeds.
If ```username``` does not matches the regular expression and the second argument is "deny", it succeeds.

On success it returns PAM_SUCCESS, otherwise it returns PAM_AUTH_ERR, PAM_SERVICE_ERR, PAM_BUF_ERR or PAM_PERM_DENIED.

No credentials are awarded by this module.
## BUILD
The source program is a single C++11 file.

Dependent package: pam-devel

```bash
g++ pam_usermatch.cpp -o pam_usermatch.so -shared -lpam -fPIC
```
## USAGE
```
pam_usermatch <reg_exp> allow|deny
```
Note that the ```reg_exp``` argument should be surrounded with square brackets if there are ```space```, ```'['``` or ```']'``` characters included in it, and a ```']'``` character should be written as ```'\]'```. For more details please refer to Linux-PAM Manual.

Examples:
```
auth   requisite   pam_usermatch.so   [[a-z0-9_\.-\]{2,30}]    allow
auth   requisite   pam_usermatch.so   .*(\.com|\.net|\.org)$   deny
```
## LICENSE
pam_usermatch is licensed under the [GPLv3](LICENSE) license.
