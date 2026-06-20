# minimum required CMAKE version
CMAKE_MINIMUM_REQUIRED(VERSION 3.10 FATAL_ERROR)
project(MightyPPL)

include(CTest)

option(MIGHTYPPL_ENABLE_AFLNET_BIZONE_SMOKE "Enable the AFLNet live bridge smoke test" OFF)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# compiler must be 17
set(CMAKE_CXX_STANDARD 17)

# required if linking to static library
add_definitions(-DANTLR4CPP_STATIC)

# using /MD flag for antlr4_runtime (for Visual C++ compilers only)
set(ANTLR4_WITH_STATIC_CRT OFF)

# Specify the version of the antlr4 library needed for this project.
# By default the latest version of antlr4 will be used.  You can specify a
# specific, stable version by setting a repository tag value or a link
# to a zip file containing the libary source.
# set(ANTLR4_TAG 4.13.1)
# set(ANTLR4_ZIP_REPOSITORY https://github.com/antlr/antlr4/archive/refs/tags/4.13.1.zip)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# add external build for antlrcpp
include(ExternalAntlr4Cpp)
# add antrl4cpp artifacts to project environment
include_directories(${ANTLR4_INCLUDE_DIRS})

# set variable pointing to the antlr tool that supports C++
# this can be overridden with -DANTLR_EXECUTABLE=/path/to/antlr-*-complete.jar
set(ANTLR_EXECUTABLE "" CACHE FILEPATH "Path to the ANTLR complete jar")
if(NOT ANTLR_EXECUTABLE AND DEFINED ENV{ANTLR_EXECUTABLE} AND EXISTS "$ENV{ANTLR_EXECUTABLE}")
  set(ANTLR_EXECUTABLE "$ENV{ANTLR_EXECUTABLE}" CACHE FILEPATH "Path to the ANTLR complete jar" FORCE)
endif()

if(NOT ANTLR_EXECUTABLE)
  find_file(ANTLR_EXECUTABLE
    NAMES
      antlr-4.13.1-complete.jar
      antlr-4.13.0-complete.jar
      antlr4.jar
      antlr4-4.7.2.jar
    PATHS
      "${CMAKE_CURRENT_SOURCE_DIR}"
      "$ENV{HOME}"
      "/usr/share/java"
      "/usr/local/share/java"
    DOC "Path to the ANTLR complete jar")
endif()

if(NOT ANTLR_EXECUTABLE)
  message(FATAL_ERROR
    "ANTLR jar not found. Set ANTLR_EXECUTABLE to the path of antlr-*-complete.jar, "
    "for example: cmake -DANTLR_EXECUTABLE=$HOME/antlr-4.13.1-complete.jar ..")
endif()

# add macros to generate ANTLR Cpp code from grammar
find_package(ANTLR REQUIRED)

# Call macro to add lexer and grammar to your build dependencies.
antlr_target(MitlGrammar Mitl.g4 VISITOR
            PACKAGE mightypplcpp)
         #antlr_target(SampleGrammarParser TParser.g4 PARSER
         #             PACKAGE antlrcpptest
         #             DEPENDS_ANTLR SampleGrammarLexer
         #             COMPILE_FLAGS -lib ${ANTLR_SampleGrammarLexer_OUTPUT_DIR})

# include generated files in project environment
include_directories(${ANTLR_MitlGrammar_OUTPUT_DIR})
#include_directories(${ANTLR_SampleGrammarParser_OUTPUT_DIR})

set(EXTERNAL_INSTALL_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/external")
set(LOCAL_MONITAAL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../MoniTAal")
set(LOCAL_MONITAAL_BUILD "${LOCAL_MONITAAL_ROOT}/build")
set(MIGHTYPPL_MONITAAL_LIBRARIES MoniTAal pugixml pardibaal)

add_subdirectory (${EXTERNAL_INSTALL_LOCATION}/buddy buddy)

#file(MAKE_DIRECTORY ${EXTERNAL_INSTALL_LOCATION}/monitaal)

ExternalProject_add(monitaal
    GIT_REPOSITORY https://github.com/DEIS-Tools/MoniTAal.git
    GIT_TAG 4bbf3cc
    PATCH_COMMAND sed -i
        -e "s|git@github.com:zeux/pugixml.git|https://github.com/zeux/pugixml.git|g"
        -e "s|git@github.com:DEIS-Tools/PARDIBAAL.git|https://github.com/DEIS-Tools/PARDIBAAL.git|g"
        -e "/add_dependencies(MoniTAal pardibaal)/a add_dependencies(MoniTAal pugixml)"
        <SOURCE_DIR>/CMakeLists.txt
        <SOURCE_DIR>/src/monitaal/CMakeLists.txt
    CMAKE_ARGS (
        -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}/monitaal -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})
)

include_directories(${EXTERNAL_INSTALL_LOCATION}/monitaal/include/monitaal)
link_directories(${EXTERNAL_INSTALL_LOCATION}/monitaal/lib)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/build/monitaal-prefix/src/monitaal-build/external/include)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/build/monitaal-prefix/src/monitaal-build/external/lib)

if(EXISTS "${LOCAL_MONITAAL_ROOT}/src/monitaal/Monitor.h" AND
   EXISTS "${LOCAL_MONITAAL_BUILD}/src/monitaal/libMoniTAal.a")
  message(STATUS "Preferring local MoniTAal workspace build for headers and libraries")
  include_directories(BEFORE
    ${LOCAL_MONITAAL_ROOT}/src/monitaal
    ${LOCAL_MONITAAL_BUILD}/external/include)
  link_directories(
    ${LOCAL_MONITAAL_BUILD}/src/monitaal
    ${LOCAL_MONITAAL_BUILD}/external/lib)
  set(MIGHTYPPL_MONITAAL_LIBRARIES
    ${LOCAL_MONITAAL_BUILD}/src/monitaal/libMoniTAal.a
    ${LOCAL_MONITAAL_BUILD}/external/lib/libpugixml.a
    ${LOCAL_MONITAAL_BUILD}/external/lib/libpardibaal.a)
endif()


#add_subdirectory(${EXTERNAL_INSTALL_LOCATION}/monitaal monitaal)

#target_include_directories(MoniTAal INTERFACE ${EXTERNAL_INSTALL_LOCATION}/monitaal)


set(MIGHTYPPL_CORE_SOURCES
    MitlFormulaVisitor.cpp
    MitlTypingVisitor.cpp
    MitlCheckNNFVisitor.cpp
    MitlToNNFVisitor.cpp
    MitlAtomNumberingVisitor.cpp
    MitlCollectTemporalVisitor.cpp
    MitlGetBDDVisitor.cpp
    BddFixpoint.cpp
    BddRuntimeMonitor.cpp
    TAwithBDDEdges.cpp
    Finally.cpp
    Once.cpp
    Globally.cpp
    Historically.cpp
    Until.cpp
    Since.cpp
    Release.cpp
    Trigger.cpp
    PnueliFn.cpp
    PnueliOn.cpp
    PnueliGn.cpp
    PnueliHn.cpp
    CountFn.cpp
    CountOn.cpp
    CountGn.cpp
    CountHn.cpp
    MightyPPL.cpp
    MightyPPLState.cpp
    MightyPPLMonitor.cpp
    ${ANTLR_MitlGrammar_CXX_OUTPUTS})

add_library(mightyppl_core STATIC ${MIGHTYPPL_CORE_SOURCES})
add_dependencies(mightyppl_core monitaal)
target_link_libraries(mightyppl_core PUBLIC antlr4_static buddy ${MIGHTYPPL_MONITAAL_LIBRARIES})

add_executable(mitppl main.cpp)
target_link_libraries(mitppl PRIVATE mightyppl_core)

add_executable(mitppl-monitor mitppl-monitor.cpp)
target_link_libraries(mitppl-monitor PRIVATE mightyppl_core)

add_executable(mitppl-monitor-bench mitppl-monitor-bench.cpp)
target_link_libraries(mitppl-monitor-bench PRIVATE mightyppl_core)


if (CMAKE_HOST_UNIX)
  # Make sure to link against threads (pthreads) library in order to be able to
  # make use of std::call_once in the code without producing runtime errors
  # (see also https://github.com/antlr/antlr4/issues/3708 and/or https://stackoverflow.com/q/51584960).
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)

  if (TARGET mitppl)
    target_link_libraries(mitppl PRIVATE Threads::Threads)
    message(STATUS "mitppl Linked with Threads!")
  endif()

  if (TARGET mitppl-monitor)
    target_link_libraries(mitppl-monitor PRIVATE Threads::Threads)
    message(STATUS "mitppl-monitor Linked with Threads!")
  endif()

  if (TARGET mitppl-monitor-bench)
    target_link_libraries(mitppl-monitor-bench PRIVATE Threads::Threads)
    message(STATUS "mitppl-monitor-bench Linked with Threads!")
  endif()

endif()

if (BUILD_TESTING)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)

  add_test(
    NAME mightyppl_monitor_feedback_smoke
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_monitor_feedback_smoke.py
            --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
            --rvem-tool ${CMAKE_CURRENT_SOURCE_DIR}/scripts/rvem_tools.py
            --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
  )

  add_test(
    NAME mightyppl_property_card_demo
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/property_card_tools.py
            check-monitor
            ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/demo_property_cards.json
            --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
  )

  add_test(
    NAME mightyppl_property_card_initial_bundle
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/property_card_tools.py
            check-monitor
            ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/main_study_property_cards_initial.json
            --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
  )

  add_test(
    NAME mightyppl_property_card_review_smoke
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_property_card_review_smoke.py
            --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
  )

  add_test(
    NAME mightyppl_monitaal_benchmark_correctness
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_monitaal_benchmark_correctness.py
            --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
            --gear-limit 500
  )

  add_test(
    NAME mightyppl_profuzzbench_overlay_smoke
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_profuzzbench_overlay_smoke.py
            --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
  )

  add_test(
    NAME mightyppl_profuzzbench_stage_audit_smoke
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_profuzzbench_stage_audit_smoke.py
            --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
  )

  if (MIGHTYPPL_ENABLE_AFLNET_BIZONE_SMOKE)
    add_test(
      NAME mightyppl_aflnet_bizone_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockftp/mock_ftp_server.c
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
    )

    add_test(
      NAME mightyppl_aflnet_bizone_ftp_response_semantic_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockftp/mock_ftp_server.c
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --force-hints keepalive
              --force-retry-chain 0
              --expect-request-class noop
              --expect-event-token conn_close
              --expect-event-token rsp_close
              --expect-event-token rsp_220
              --expect-event-token rsp_331
              --expect-event-token rsp_200
              --expect-event-token noop_rsp
              --expect-feedback-response-class 220
              --expect-feedback-response-class 200
              --expect-feedback-close-or-reset 1
    )

    add_test(
      NAME mightyppl_aflnet_bizone_ftp_timeout_semantic_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockftp/mock_ftp_server.c
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --seed-dir aflnet/tutorials/mockftp/in-ftp-timeout
              --force-hints=
              --force-retry-chain 0
              --allow-no-active-timing-plan
              --expect-request-class noresp
              --expect-event-token conn_timeout
              --expect-event-token rsp_timeout
              --expect-feedback-response-class timeout
              --expect-feedback-close-or-reset 1
    )

    add_test(
      NAME mightyppl_aflnet_bizone_ftp_reset_semantic_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockftp/mock_ftp_server.c
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --seed-dir aflnet/tutorials/mockftp/in-ftp-reset
              --force-hints=
              --force-retry-chain 0
              --allow-no-active-timing-plan
              --expect-request-class rst
              --expect-event-token conn_reset
              --expect-event-token rsp_reset
              --expect-feedback-response-class reset
              --expect-feedback-close-or-reset 1
    )

    add_test(
      NAME mightyppl_aflnet_bizone_ablation_matrix_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_ablation_matrix_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockftp/mock_ftp_server.c
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
    )

    add_test(
      NAME mightyppl_aflnet_bizone_queue_history_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockftp/mock_ftp_server.c
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --persist-exec-history
              --duration-sec 20
              --expect-exec-history-queue-origin
    )

    add_test(
      NAME mightyppl_aflnet_bizone_rtsp_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockrtsp/mock_rtsp_server.c
              --protocol RTSP
              --seed-dir aflnet/tutorials/mockrtsp/in-rtsp-smoke
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id rtsp.session_activity_before_default_timeout
              --force-hints keepalive
              --force-retry-chain 0
              --expect-keepalive-synthesized
              --expect-keepalive-profile rtsp-options-contextual
              --expect-keepalive-contextual
              --expect-keepalive-preferred-class options
              --expect-request-class options
              --expect-event-substring session_open
              --expect-event-substring session_activity
              --expect-feedback-request-class session_activity
              --expect-feedback-response-class session_open
    )

    add_test(
      NAME mightyppl_aflnet_bizone_rtsp_adaptive_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockrtsp/mock_rtsp_server.c
              --protocol RTSP
              --seed-dir aflnet/tutorials/mockrtsp/in-rtsp-smoke
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id rtsp.session_activity_before_default_timeout
              --force-hints=
              --force-retry-chain 0
              --disable-test-hint-overrides
              --replay-passes 2
              --expect-adaptive-feedback-loop
              --expect-keepalive-profile rtsp-options-contextual
              --expect-keepalive-contextual
              --expect-keepalive-preferred-class options
              --expect-request-class options
              --expect-feedback-request-class session_activity
              --expect-feedback-response-class session_open
    )

    add_test(
      NAME mightyppl_aflnet_bizone_sip_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mocksip/mock_sip_server.c
              --protocol SIP
              --seed-dir aflnet/tutorials/mocksip/in-sip
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --force-hints keepalive
              --force-retry-chain 0
              --expect-keepalive-synthesized
              --expect-keepalive-profile sip-options-contextual
              --expect-keepalive-contextual
              --expect-keepalive-preferred-class options
              --expect-request-class options
    )

    add_test(
      NAME mightyppl_aflnet_bizone_sip_retry_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mocksip/mock_sip_server.c
              --protocol SIP
              --seed-dir aflnet/tutorials/mocksip/in-sip
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id sip.invite.no_retransmit_before_timer_a
              --exec-timeout-ms 4000
              --server-wait-ms 30
              --poll-wait-ms 30
              --force-hints retry
              --force-retry-chain 1
              --force-gap-ms 1000
              --expect-retry-profile sip-invite-retransmission
              --expect-retry-preferred-class invite
              --expect-retry-contextual
              --expect-request-class invite
              --expect-event-token invite
              --expect-event-token rtx
              --expect-event-token rtx1
              --expect-event-token invite_rsp
              --expect-event-substring sip_tx_
              --expect-feedback-request-class invite
              --expect-feedback-request-class rtx1
              --expect-feedback-response-class 100
    )

    add_test(
      NAME mightyppl_aflnet_bizone_sip_backoff_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mocksip/mock_sip_server.c
              --protocol SIP
              --seed-dir aflnet/tutorials/mocksip/in-sip
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id sip.invite.no_second_retransmit_before_doubled_timer_a
              --exec-timeout-ms 8000
              --server-wait-ms 30
              --poll-wait-ms 30
              --force-hints retry
              --force-retry-chain 2
              --force-gap-ms 500
              --expect-retry-profile sip-invite-retransmission
              --expect-retry-preferred-class invite
              --expect-retry-contextual
              --expect-retry-insertion-count 2
              --expect-pre-send-delays 500,1000
              --expect-cross-request-resend 0
              --expect-boundary-bisection 1
              --expect-request-class invite
              --expect-event-token invite
              --expect-event-token rtx
              --expect-event-token rtx1
              --expect-event-token rtx2
              --expect-event-substring sip_tx_
              --expect-feedback-request-class invite
              --expect-feedback-request-class rtx1
              --expect-feedback-request-class rtx2
              --expect-feedback-response-class 100
    )

    add_test(
      NAME mightyppl_aflnet_bizone_sip_adaptive_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mocksip/mock_sip_server.c
              --protocol SIP
              --seed-dir aflnet/tutorials/mocksip/in-sip
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id sip.invite.no_retransmit_before_timer_a
              --exec-timeout-ms 4000
              --server-wait-ms 30
              --poll-wait-ms 30
              --disable-test-hint-overrides
              --force-retry-chain 0
              --replay-passes 2
              --server-env BIZONE_SIP_INVITE_RESPONSE_MODE=trying-only
              --expect-adaptive-feedback-loop
              --expect-retry-profile sip-invite-retransmission
              --expect-retry-preferred-class invite
              --expect-retry-contextual
              --expect-request-class invite
              --expect-event-token invite
              --expect-event-token rtx
              --expect-event-token rtx1
              --expect-event-token invite_rsp
              --expect-event-substring sip_tx_
              --expect-feedback-request-class invite
              --expect-feedback-request-class rtx1
              --expect-feedback-response-class 100
    )

    add_test(
      NAME mightyppl_aflnet_bizone_dtls_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockdtls/mock_dtls12_server.c
              --protocol DTLS12
              --network-scheme udp
              --seed-dir aflnet/tutorials/mockdtls/in-dtls
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --poll-wait-ms 30
              --force-hints keepalive
              --force-retry-chain 0
              --expect-keepalive-profile dtls12-clienthello-contextual
              --expect-keepalive-contextual
              --expect-keepalive-preferred-class clienthello
              --expect-request-class clienthello
              --expect-event-token ch
              --expect-feedback-request-class ch
    )

    add_test(
      NAME mightyppl_aflnet_bizone_dtls_retry_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockdtls/mock_dtls12_server.c
              --protocol DTLS12
              --network-scheme udp
              --seed-dir aflnet/tutorials/mockdtls/in-dtls
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id dtls.clienthello.no_retransmit_before_initial_rto
              --exec-timeout-ms 4000
              --poll-wait-ms 30
              --force-hints retry
              --force-retry-chain 1
              --force-gap-ms 1000
              --expect-retry-profile dtls12-clienthello-retransmission
              --expect-retry-preferred-class clienthello
              --expect-retry-contextual
              --expect-request-class clienthello
              --expect-event-token ch
              --expect-event-token rtx
              --expect-event-token rtx1
              --expect-feedback-request-class ch
              --expect-feedback-request-class rtx1
    )

    add_test(
      NAME mightyppl_aflnet_bizone_dtls_backoff_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockdtls/mock_dtls12_server.c
              --protocol DTLS12
              --network-scheme udp
              --seed-dir aflnet/tutorials/mockdtls/in-dtls
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id dtls.clienthello.no_second_retransmit_before_doubled_rto
              --exec-timeout-ms 8000
              --poll-wait-ms 30
              --force-hints retry
              --force-retry-chain 0
              --force-gap-ms 1000
              --expect-retry-insertion-count 3
              --expect-pre-send-delays 1000,2000,4000
              --expect-cross-request-resend 0
              --expect-boundary-bisection 1
              --expect-retry-profile dtls12-clienthello-retransmission
              --expect-retry-preferred-class clienthello
              --expect-retry-contextual
              --expect-request-class clienthello
              --expect-event-token ch
              --expect-event-token rtx
              --expect-event-token rtx1
              --expect-feedback-request-class ch
              --expect-feedback-request-class rtx1
    )

    add_test(
      NAME mightyppl_aflnet_bizone_dtls_adaptive_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockdtls/mock_dtls12_server.c
              --protocol DTLS12
              --network-scheme udp
              --seed-dir aflnet/tutorials/mockdtls/in-dtls
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id dtls.clienthello.no_retransmit_before_initial_rto
              --exec-timeout-ms 4000
              --poll-wait-ms 30
              --disable-test-hint-overrides
              --replay-passes 2
              --expect-adaptive-feedback-loop
              --expect-hybrid-keepalive-retry
              --expect-retry-profile dtls12-clienthello-retransmission
              --expect-retry-preferred-class clienthello
              --expect-retry-contextual
              --expect-keepalive-profile dtls12-clienthello-contextual
              --expect-keepalive-contextual
              --expect-keepalive-preferred-class clienthello
              --expect-request-class clienthello
              --expect-event-token ch
              --expect-event-token rtx
              --expect-event-token rtx1
              --expect-feedback-request-class ch
              --expect-feedback-request-class rtx1
    )

    add_test(
      NAME mightyppl_aflnet_bizone_dicom_keepalive_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockdicom/mock_dicom_server.c
              --protocol DICOM
              --seed-dir aflnet/tutorials/mockdicom/in-dicom-smoke
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id dicom.acse_response_within_default_timeout
              --force-hints keepalive
              --force-retry-chain 0
              --expect-keepalive-profile dicom-pdata_tf-contextual
              --expect-keepalive-contextual
              --expect-keepalive-preferred-class pdata_tf
              --expect-request-class pdata_tf
    )

    add_test(
      NAME mightyppl_aflnet_bizone_dicom_adaptive_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockdicom/mock_dicom_server.c
              --protocol DICOM
              --seed-dir aflnet/tutorials/mockdicom/in-dicom-smoke
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id dicom.acse_response_within_default_timeout
              --disable-test-hint-overrides
              --force-retry-chain 0
              --replay-passes 2
              --expect-adaptive-feedback-loop
              --expect-keepalive-profile dicom-pdata_tf-contextual
              --expect-keepalive-contextual
              --expect-keepalive-preferred-class pdata_tf
              --expect-request-class pdata_tf
              --expect-feedback-request-class pdata_tf
              --expect-feedback-response-class acse_rsp
    )

    add_test(
      NAME mightyppl_aflnet_bizone_dicom_retry_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockdicom/mock_dicom_server.c
              --protocol DICOM
              --seed-dir aflnet/tutorials/mockdicom/in-dicom-smoke
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --force-hints retry
              --force-retry-chain 1
              --force-gap-ms 1000
              --expect-retry-profile dicom-associate_rq-retransmission
              --expect-retry-preferred-class associate_rq
              --expect-retry-contextual
              --expect-request-class associate_rq
              --expect-event-substring assoc_req
              --expect-event-substring acse_rsp
              --expect-feedback-request-class assoc_req
              --expect-feedback-response-class acse_rsp
    )

    add_test(
      NAME mightyppl_aflnet_bizone_ssh_keepalive_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockssh/mock_ssh_server.c
              --protocol SSH
              --seed-dir profuzzbench/subjects/SSH/OpenSSH/in-ssh
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id ssh.login_grace_disconnect_or_auth
              --force-hints keepalive
              --force-retry-chain 0
              --expect-keepalive-profile ssh-kexinit-contextual
              --expect-keepalive-contextual
              --expect-request-class kexinit
              --expect-event-substring conn_open
              --expect-event-substring auth_done
              --expect-feedback-request-class conn_open
              --expect-feedback-response-class auth_done
    )

    add_test(
      NAME mightyppl_aflnet_bizone_ssh_retry_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockssh/mock_ssh_server.c
              --protocol SSH
              --seed-dir profuzzbench/subjects/SSH/OpenSSH/in-ssh
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --duration-sec 10
              --force-hints retry
              --force-retry-chain 1
              --force-gap-ms 1000
              --expect-retry-profile ssh-kexinit-retransmission
              --expect-retry-preferred-class kexinit
              --expect-retry-contextual
              --expect-request-class kexinit
    )

    add_test(
      NAME mightyppl_aflnet_bizone_ssh_adaptive_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockssh/mock_ssh_server.c
              --protocol SSH
              --seed-dir profuzzbench/subjects/SSH/OpenSSH/in-ssh
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id ssh.login_grace_disconnect_or_auth
              --disable-test-hint-overrides
              --force-retry-chain 0
              --replay-passes 2
              --expect-adaptive-feedback-loop
              --expect-keepalive-profile ssh-global_request-contextual
              --expect-keepalive-contextual
              --expect-keepalive-preferred-class global_request
              --expect-request-class global_request
              --expect-event-substring phase_authenticated
              --expect-event-substring auth_done
              --expect-feedback-response-class auth_done
              --expect-feedback-request-class global_request
              --expect-feedback-request-class-keepalive global_request 1
              --expect-first-pass-final-session-phase completed
              --expect-first-pass-final-response-class auth_done
              --expect-first-pass-final-keepalive-hint 0
              --expect-first-pass-final-candidate-absent global_request
              --expect-first-pass-final-candidate-absent ignore
              --expect-first-pass-final-candidate-absent channel_open
              --expect-feedback-request-class-keepalive disconnect 0
              --expect-feedback-response-phase-keepalive auth_done completed 0
              --expect-feedback-response-phase-candidate-absent auth_done completed global_request
              --expect-feedback-response-phase-candidate-absent auth_done completed ignore
              --expect-feedback-response-phase-candidate-absent auth_done completed channel_open
    )

    add_test(
      NAME mightyppl_aflnet_bizone_ssh_synth_keepalive_adaptive_smoke
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_aflnet_bizone_smoke.py
              --monitor ${CMAKE_CURRENT_BINARY_DIR}/mitppl-monitor
              --afl-fuzz ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-fuzz
              --afl-clang-fast ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/afl-clang-fast
              --server-source ${CMAKE_CURRENT_SOURCE_DIR}/../aflnet/tutorials/mockssh/mock_ssh_server.c
              --protocol SSH
              --seed-dir profuzzbench/subjects/SSH/OpenSSH/in-ssh
              --workspace ${CMAKE_CURRENT_SOURCE_DIR}/..
              --property-card-id ssh.login_grace_disconnect_or_auth
              --disable-test-hint-overrides
              --ssh-truncate-after-request-class service_request
              --force-retry-chain 0
              --replay-passes 2
              --expect-adaptive-feedback-loop
              --expect-keepalive-synthesized
              --expect-keepalive-profile ssh-ignore-contextual
              --expect-keepalive-contextual
              --expect-keepalive-preferred-class ignore
              --expect-request-class ignore
              --expect-event-substring phase_authenticated
              --expect-event-substring auth_done
              --expect-feedback-response-class auth_done
              --expect-feedback-request-class ignore
              --expect-feedback-request-class-keepalive ignore 1
              --expect-feedback-response-phase-keepalive auth_done authenticated 1
              --expect-feedback-response-phase-candidate-absent auth_done authenticated disconnect
    )
  endif()
endif()
