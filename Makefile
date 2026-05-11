CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pthread
# add libnftables в LDFLAGS
LDFLAGS = -lldns -lnftables 
VERSION = 1.1.3
CXXFLAGS += -DVERSION=\"$(VERSION)\"

# Dirs
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Files
SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SOURCES))
TARGET = $(BIN_DIR)/dnsmap

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	# CAP_NET_ADMIN required to work with the nftables API without root
	setcap 'cap_net_bind_service,cap_net_admin+ep' /usr/local/bin/dnsmap
