#include "test.h"
#   ifndef DISABLE_CURR_RIPE_TEST
#include "RipeTest.h"
#else
#   include "Ripe5Test.h"
#endif

INITIALIZE_EASYLOGGINGPP

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);
    el::Loggers::addFlag(el::LoggingFlag::ImmediateFlush);

    return ::testing::UnitTest::GetInstance()->Run();
}
