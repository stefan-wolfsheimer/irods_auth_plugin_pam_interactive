#include <catch.hpp>
#include <string>
#include "../whereami/whereami.hpp"

TEST_CASE("get_executable", "[UTIL]")
{
  std::string basename = WhereAmI::getExecutableBaseName();
  std::string dir = WhereAmI::getExecutableDir();
  std::pair<std::string, std::string> p = WhereAmI::getExecutablePath();
  REQUIRE(p.first == dir);
  REQUIRE(p.second == basename);
}
