#pragma once
#include <ldns/ldns.h>
#include "ip_manager.hpp"

void process_packet(uint8_t*& out_buf, size_t& out_len, uint8_t* in_buf, size_t in_len, IPManager& manager, bool debug_mode);
