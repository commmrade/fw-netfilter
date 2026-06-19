cmake_minimum_required(VERSION 3.10.0)
project(proj VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED true)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MNL REQUIRED libmnl)

include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
)
FetchContent_MakeAvailable(nlohmann_json)

add_executable(proj main.cpp)

target_include_directories(proj PRIVATE ${MNL_INCLUDE_DIRS})
target_link_libraries(proj PRIVATE ${MNL_LIBRARIES} nlohmann_json::nlohmann_json)
target_compile_options(proj PRIVATE ${MNL_CFLAGS_OTHER})
