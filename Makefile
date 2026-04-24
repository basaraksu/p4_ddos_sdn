BMV2_SWITCH_EXE = simple_switch_grpc
TOPO = pod-topo/topology.json
#TOPO = topologies/small_city.json
#TOPO = topologies/medium_city.json
#TOPO = topologies/large_city.json

# # Makefile'a dosyanın nerede olduğunu açıkça gösteriyoruz
# P4_SRC = ddos_detection.p4
# # Derleme hedefi
# P4C_ARGS = -o build/ddos_detection.json

include ../../utils/Makefile