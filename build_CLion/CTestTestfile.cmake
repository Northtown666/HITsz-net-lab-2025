# CMake generated Testfile for 
# Source directory: E:/net-lab
# Build directory: E:/net-lab/build_CLion
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(eth_in "E:/net-lab/build_CLion/eth_in.exe" "E:/net-lab/testing/data/eth_in")
set_tests_properties(eth_in PROPERTIES  _BACKTRACE_TRIPLES "E:/net-lab/CMakeLists.txt;161;add_test;E:/net-lab/CMakeLists.txt;0;")
add_test(eth_out "E:/net-lab/build_CLion/eth_out.exe" "E:/net-lab/testing/data/eth_out")
set_tests_properties(eth_out PROPERTIES  _BACKTRACE_TRIPLES "E:/net-lab/CMakeLists.txt;166;add_test;E:/net-lab/CMakeLists.txt;0;")
add_test(arp_test "E:/net-lab/build_CLion/arp_test.exe" "E:/net-lab/testing/data/arp_test")
set_tests_properties(arp_test PROPERTIES  _BACKTRACE_TRIPLES "E:/net-lab/CMakeLists.txt;171;add_test;E:/net-lab/CMakeLists.txt;0;")
add_test(ip_test "E:/net-lab/build_CLion/ip_test.exe" "E:/net-lab/testing/data/ip_test")
set_tests_properties(ip_test PROPERTIES  _BACKTRACE_TRIPLES "E:/net-lab/CMakeLists.txt;176;add_test;E:/net-lab/CMakeLists.txt;0;")
add_test(ip_frag_test "E:/net-lab/build_CLion/ip_frag_test.exe" "E:/net-lab/testing/data/ip_frag_test")
set_tests_properties(ip_frag_test PROPERTIES  _BACKTRACE_TRIPLES "E:/net-lab/CMakeLists.txt;181;add_test;E:/net-lab/CMakeLists.txt;0;")
add_test(icmp_test "E:/net-lab/build_CLion/icmp_test.exe" "E:/net-lab/testing/data/icmp_test")
set_tests_properties(icmp_test PROPERTIES  _BACKTRACE_TRIPLES "E:/net-lab/CMakeLists.txt;186;add_test;E:/net-lab/CMakeLists.txt;0;")
add_test(udp_test "E:/net-lab/build_CLion/udp_test.exe" "E:/net-lab/testing/data/udp_test")
set_tests_properties(udp_test PROPERTIES  _BACKTRACE_TRIPLES "E:/net-lab/CMakeLists.txt;191;add_test;E:/net-lab/CMakeLists.txt;0;")
add_test(tcp_test "E:/net-lab/build_CLion/tcp_test.exe" "E:/net-lab/testing/data/tcp_test")
set_tests_properties(tcp_test PROPERTIES  _BACKTRACE_TRIPLES "E:/net-lab/CMakeLists.txt;196;add_test;E:/net-lab/CMakeLists.txt;0;")
