find_package(OpenSSL 3 REQUIRED)
find_package(nlohmann_json 3.11 CONFIG REQUIRED)
if(PBS_PS5)
 find_path(ACTIVITY_SODIUM_INCLUDE sodium.h REQUIRED)
 find_library(ACTIVITY_SODIUM sodium REQUIRED)
else()
 find_package(Threads REQUIRED)
endif()

set(assets "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${assets}")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
 web/activity.html web/activity.js web/qrcodegen.js vendor/ca-bundle.pem)
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/embed_activity.py"
 "${assets}" COMMAND_ERROR_IS_FATAL ANY)
add_executable(ps5-game-activity src/activity_main.cpp src/activity_session.cpp
 src/account_store.cpp src/account_vault.cpp src/platform.cpp src/net.cpp
 src/game_activity.cpp src/game_artwork.cpp src/activity_settings.cpp src/login_verification.cpp)
target_include_directories(ps5-game-activity PRIVATE src "${assets}")
target_link_libraries(ps5-game-activity PRIVATE OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)
if(PBS_PS5)
 set_target_properties(ps5-game-activity PROPERTIES SUFFIX ".elf")
 target_compile_definitions(ps5-game-activity PRIVATE PBS_PS5=1)
 target_include_directories(ps5-game-activity PRIVATE "${ACTIVITY_SODIUM_INCLUDE}")
 target_link_libraries(ps5-game-activity PRIVATE "${ACTIVITY_SODIUM}" pthread SceRandom SceSystemService)
else()
 target_link_libraries(ps5-game-activity PRIVATE Threads::Threads)
endif()
