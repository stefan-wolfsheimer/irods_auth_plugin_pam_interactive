#pragma once

#include <string>
#include <utility>

namespace WhereAmI
{
  std::string getExecutableBaseName();
  std::string getExecutableDir();
  std::pair<std::string, std::string> getExecutablePath();
}

