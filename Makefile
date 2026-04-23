# Compiler settings
# Checking for ldns using pkg-config
ifeq ($(shell pkg-config --exists ldns || echo no), no)
    $(error "The ldns library was not found. Please install libldns-dev (Debian/Ubuntu) or ldns-devel (Fedora/CentOS).")
endif

# Automatically receiving flags
LDNS_CFLAGS = $(shell pkg-config --cflags ldns)
LDNS_LIBS = $(shell pkg-config --libs ldns)

# Adding flags to core variables
CXXFLAGS += $(LDNS_CFLAGS)
LDFLAGS += $(LDNS_LIBS)
CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra
LDFLAGS = -lldns

# Dirs
SRC_DIR = src
OBJ_DIR = obj

# Files
SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SOURCES))
TARGET = dnsmap

# Firewall type (iptables by default)
BACKEND ?= iptables
ifeq ($(BACKEND), nftables)
    CXXFLAGS += -DUSE_NFTABLES
endif

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	setcap 'cap_net_bind_service,cap_net_admin+ep' /usr/local/bin/$(TARGET)
