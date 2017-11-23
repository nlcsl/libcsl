INC_DIR += $(REP_DIR)/include/libcsl

SRC_CC =  $(notdir $(wildcard $(REP_DIR)/src/csl/*/*.cc))

LIBS = jitterentropy net base
CC_OPT += -std=c++11 
#-Wno-deprecated -Wno-deprecated-declarations
SHARED_LIB =  YES

vpath %.cc $(REP_DIR)/src/csl/util/
vpath %.cc $(REP_DIR)/src/csl/net/
vpath %.cc $(REP_DIR)/src/csl/crypto/

