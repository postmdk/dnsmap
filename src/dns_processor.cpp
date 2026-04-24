#include "dns_processor.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <syslog.h>

using namespace std;

void process_packet(uint8_t*& out_buf, size_t& out_len, uint8_t* in_buf, size_t in_len, IPManager& manager, bool debug) {
    ldns_pkt *pkt;
    if (ldns_wire2pkt(&pkt, in_buf, in_len) != LDNS_STATUS_OK) return;

    ldns_rr_list *questions = ldns_pkt_question(pkt);
    if (questions && ldns_rr_list_rr_count(questions) > 0) {
        ldns_rr *q = ldns_rr_list_rr(questions, 0);
        ldns_rr_type type = ldns_rr_get_type(q);

        // Blocking protocols that interfere with IPv4 mapping
        if (type == LDNS_RR_TYPE_AAAA || type == LDNS_RR_TYPE_HTTPS) {
            if (debug) {
                syslog(LOG_DEBUG, "[ DEBUG ]: Blocking IPv6/HTTPS query type: %d", type);
            }
            ldns_pkt_set_qr(pkt, true);
            ldns_pkt_set_ancount(pkt, 0);
            ldns_pkt2wire(&out_buf, pkt, &out_len);
            ldns_pkt_free(pkt);
            return;
        }
        if (type == LDNS_RR_TYPE_A) {
            char* qname = ldns_rdf2str(ldns_rr_owner(q));
            ldns_rr_list *answers = ldns_pkt_answer(pkt);

            for (size_t i = 0; i < ldns_rr_list_rr_count(answers); i++) {
                ldns_rr *rr = ldns_rr_list_rr(answers, i);
                if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_A) {
                    ldns_rdf *data = ldns_rr_a_address(rr);
                    uint32_t real_ip = ntohl(*(uint32_t*)ldns_rdf_data(data));
                    uint32_t fake_ip = manager.get_or_create(real_ip);

                    if (fake_ip) {
                        struct in_addr f_addr;
                        f_addr.s_addr = htonl(fake_ip);
                        if (debug) {
                            syslog(LOG_DEBUG, "[  MAP  ]: %s -> %s", qname, inet_ntoa(f_addr));
                        }

                        uint32_t fake_net = htonl(fake_ip);
                        ldns_rdf *new_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_A, 4, &fake_net);

                        ldns_rdf_deep_free(ldns_rr_set_rdf(rr, new_rdf, 0));
                        ldns_rr_set_ttl(rr, 300);
                    }
                }
            }
            free(qname);
        }
    }

    ldns_pkt2wire(&out_buf, pkt, &out_len);
    ldns_pkt_free(pkt);
}