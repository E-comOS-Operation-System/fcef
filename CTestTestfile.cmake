# CMake generated Testfile for 
# Source directory: /workspaces/fcef
# Build directory: /workspaces/fcef
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test_basic "/workspaces/fcef/bin/test_basic")
set_tests_properties(test_basic PROPERTIES  _BACKTRACE_TRIPLES "/workspaces/fcef/CMakeLists.txt;62;add_test;/workspaces/fcef/CMakeLists.txt;0;")
add_test(test_end_to_end "/workspaces/fcef/bin/test_end_to_end")
set_tests_properties(test_end_to_end PROPERTIES  _BACKTRACE_TRIPLES "/workspaces/fcef/CMakeLists.txt;63;add_test;/workspaces/fcef/CMakeLists.txt;0;")
add_test(test_os_loader "/workspaces/fcef/bin/test_os_loader")
set_tests_properties(test_os_loader PROPERTIES  _BACKTRACE_TRIPLES "/workspaces/fcef/CMakeLists.txt;64;add_test;/workspaces/fcef/CMakeLists.txt;0;")
