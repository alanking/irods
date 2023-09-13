#ifndef RS_GET_LIMITED_PASSWORD_HPP
#define RS_GET_LIMITED_PASSWORD_HPP

struct RsComm;
struct GetLimitedPasswordInp;
struct GetLimitedPasswordOut;

int rsGetLimitedPassword(RsComm* rsComm,
                         GetLimitedPasswordInp* getLimitedPasswordInp,
                         GetLimitedPasswordOut** getLimitedPasswordOut);
int _rsGetLimitedPassword(RsComm* rsComm,
                          GetLimitedPasswordInp* getLimitedPasswordInp,
                          GetLimitedPasswordOut** getLimitedPasswordOut);

#endif
