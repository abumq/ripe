#ifndef RIPE_LOG_H
#define RIPE_LOG_H

#include "easylogging++.h"

#define RLOG(LEVEL) CLOG(LEVEL, "ripe")
#define RLOG_IF(condition, LEVEL) CLOG_IF(condition, LEVEL, "ripe")
#define RVLOG(vLevel) CVLOG(vLevel, "ripe")
#define DRVLOG(vLevel) DCVLOG(vLevel, "ripe") << "[DEBUG] "

#define RV_DEBUG 9
#define RV_DETAILS 8
#define RV_WARNING 5
#define RV_ERROR 3
#define RV_INFO 1

#endif // RIPE_LOG_H
