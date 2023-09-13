#ifndef RS_GET_LIMITED_PASSWORD_HPP
#define RS_GET_LIMITED_PASSWORD_HPP

struct RsComm;
struct getLimitedPasswordInp_t;
struct getLimitedPasswordOut_t;

int rsGetLimitedPassword(RsComm* rsComm,
                         getLimitedPasswordInp_t* getLimitedPasswordInp,
                         getLimitedPasswordOut_t** getLimitedPasswordOut);
int _rsGetLimitedPassword(RsComm* rsComm,
                          getLimitedPasswordInp_t* getLimitedPasswordInp,
                          getLimitedPasswordOut_t** getLimitedPasswordOut);

#endif
