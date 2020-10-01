#include "whereami.hpp"
#include "whereami.h"
#include <stdlib.h>
#include <new>

std::string WhereAmI::getExecutableBaseName()
{
  char * path = NULL;
  int length, dirname_length;
  length = wai_getExecutablePath(NULL, 0, &dirname_length);
  if(length > 0)
  {
    path = (char*)malloc(length + 1);
    if (!path)
    {
      throw std::bad_alloc();      
    }
    wai_getExecutablePath(path, length, &dirname_length);
    path[length] = '\0';
    std::string basename(path + dirname_length + 1);
    free(path);
    return basename;
  }
  else
  {
    std::string empty;
    return empty;
  }
}

std::string WhereAmI::getExecutableDir()
{
  char * path = NULL;
  int length, dirname_length;
  length = wai_getExecutablePath(NULL, 0, &dirname_length);
  if(length > 0)
  {
    path = (char*)malloc(length + 1);
    if (!path)
    {
      throw std::bad_alloc();      
    }
    wai_getExecutablePath(path, length, &dirname_length);
    path[dirname_length] = '\0';
    std::string dirname(path);
    free(path);
    return dirname;
  }
  else
  {
    std::string empty;
    return empty;
  }
}

std::pair<std::string, std::string> WhereAmI::getExecutablePath()
{
  char * path = NULL;
  int length, dirname_length;
  length = wai_getExecutablePath(NULL, 0, &dirname_length);
  if(length > 0)
  {
    path = (char*)malloc(length + 1);
    if (!path)
    {
      throw std::bad_alloc();      
    }
    wai_getExecutablePath(path, length, &dirname_length);
    path[length] = '\0';
    path[dirname_length] = '\0';
    std::string basename(path + dirname_length + 1);
    std::string dirname(path);
    free(path);
    return std::make_pair(dirname, basename);
  }
  else
  {
    std::string empty;
    return std::make_pair(empty, empty);
  }
}
