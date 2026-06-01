
import random
import copy
from protocol.dns import (DNSMessage, build_compression_loop_packet, build_label_flood_packet,
                          build_response_packet, build_edns_exploit_packet,
                          build_dnssec_record_packet, build_tcp_dns_segment,
                          build_txt_rdata_bomb, build_tcp_dns_two_message,
                          build_inspector_stress_packet,
                          build_dns_dynamic_update, build_multi_query_storm)
from protocol.exploit_packets import (build_ip_defrag_exploit,
                                      build_back_orifice_exploit,
                                      build_dce_smb_exploit)

class FuzzLibrary:
    UINT16 = [0x0000, 0xFFFF, 0x7FFF, 0x8000, 0xFFFE]
    UINT32 = [0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, -1]
    NIBBLE = [0, 15, 14, 8]
    BOOLEAN = [0, 1]
    Z_FLAG = [1, 2, 4, 7]
    DOMAINS = [ "a" * 63 + ".com", "A" * 255, "%n%s%x", "admin.local\x00.com", ""]

class SmartDNSMutator:
    def __init__(self, seed_message: DNSMessage):
        self.message = copy.deepcopy(seed_message)

    def fuzz_field(self, obj, field_name, fuzz_pool):
        if hasattr(obj, field_name):
            setattr(obj, field_name, random.choice(fuzz_pool))

    def mutate(self) -> DNSMessage:
        target_section = random.choice(["header_counts", "header_flags", "question", "answer"])

        if target_section == "header_counts":
            target_field = random.choice(["qdcount", "ancount", "nscount", "arcount"])
            self.fuzz_field(self.message.header, target_field, FuzzLibrary.UINT16)

        elif target_section == "header_flags":
            target_field = random.choice(["qr", "opcode", "aa", "tc", "rd", "ra", "z", "rcode"])
            if target_field in ["qr", "aa", "tc", "rd", "ra"]:
                self.fuzz_field(self.message.header, target_field, FuzzLibrary.BOOLEAN)
            elif target_field in ["opcode", "rcode"]:
                self.fuzz_field(self.message.header, target_field, FuzzLibrary.NIBBLE)
            elif target_field == "z":
                self.fuzz_field(self.message.header, target_field, FuzzLibrary.Z_FLAG)

        elif target_section == "question" and self.message.questions:
            target_q = random.choice(self.message.questions)
            if random.choice([True, False]):
                self.fuzz_field(target_q, "qname", FuzzLibrary.DOMAINS)
            else:
                self.fuzz_field(target_q, "qtype", FuzzLibrary.UINT16)

        elif target_section == "answer" and self.message.answers:
            target_a = random.choice(self.message.answers)
            if random.choice([True, False]):
                self.fuzz_field(target_a, "ttl", FuzzLibrary.UINT32)
            else:
                self.fuzz_field(target_a, "rdlength", FuzzLibrary.UINT16)
        if target_section not in ["header_counts", "answer"]:
            self.message.header.qdcount = len(self.message.questions)
            self.message.header.ancount = len(self.message.answers)

        return self.message

class ByteMutator:
    @staticmethod
    def bit_flip(payload: bytes) -> bytes:
        if not payload: return payload
        byte_array = bytearray(payload)
        byte_idx = random.randint(0, len(byte_array) - 1)
        bit_idx = random.randint(0, 7)
        byte_array[byte_idx] ^= (1 << bit_idx)
        return bytes(byte_array)


class CompressionLoopMutator:
    LOOP_TYPES = ["deep_chain", "wide_fan", "qdcount_bomb"]

    @staticmethod
    def mutate() -> bytes:
        return build_compression_loop_packet(loop_type=random.choice(CompressionLoopMutator.LOOP_TYPES))


class LabelComplexityMutator:
    STRATEGIES = ["max_labels", "max_len_labels", "recursive_compression"]

    @staticmethod
    def mutate() -> bytes:
        return build_label_flood_packet(strategy=random.choice(LabelComplexityMutator.STRATEGIES))


class ResponseMutator:
    ANOMALIES = [
        "rdlength_mismatch", "cname_bad_pointer", "count_mismatch",
        "mx_bad_pointer", "txt_overflow", "nested_cname_chain", "answer_bomb",
        "obsolete_rr_flood", "authority_additional_bomb", "section_counter_confusion",
        "soa_name_bomb", "ns_name_bomb", "standard_rr_rdata",
    ]

    @staticmethod
    def mutate() -> bytes:
        return build_response_packet(anomaly=random.choice(ResponseMutator.ANOMALIES))


class EDNSExploitMutator:
    ANOMALIES = [
        "option_overflow", "cookie_corrupt",
        "chain_options", "multiple_opt", "payload_size_lie",
    ]

    @staticmethod
    def mutate() -> bytes:
        return build_edns_exploit_packet(anomaly=random.choice(EDNSExploitMutator.ANOMALIES))


class DNSSECRecordMutator:
    ANOMALIES = [
        "rrsig_oob_name", "nsec3_hash_overflow", "dnskey_flag_exploit",
        "nsec_bitmap_overflow", "rrsig_multi_record", "ds_digest_overflow",
    ]

    @staticmethod
    def mutate() -> bytes:
        return build_dnssec_record_packet(anomaly=random.choice(DNSSECRecordMutator.ANOMALIES))


class TCPDNSSegmentMutator:
    ANOMALIES = [
        "length_lie", "length_zero", "length_partial_header",
        "interleaved_messages", "negative_length_boundary", "corrupt_mid_session",
    ]

    @staticmethod
    def mutate() -> bytes:
        return build_tcp_dns_segment(anomaly=random.choice(TCPDNSSegmentMutator.ANOMALIES))


class TxtRdataBombMutator:
    ANOMALIES = ["event_queue_flood", "deep_txt_chain", "multi_answer_txt"]

    @staticmethod
    def mutate() -> bytes:
        return build_txt_rdata_bomb(anomaly=random.choice(TxtRdataBombMutator.ANOMALIES))


class TcpTwoMessageMutator:
    ANOMALIES = ["second_oob_ptr", "second_malformed", "second_truncated"]

    @staticmethod
    def mutate() -> bytes:
        return build_tcp_dns_two_message(anomaly=random.choice(TcpTwoMessageMutator.ANOMALIES))


class InspectorStressMutator:
    ANOMALIES = [
        "truncated_rr_chain", "rdlength_cascade", "name_hash_flood",
        "stateful_tid_storm", "partial_header_truncation",
        "zero_key_rdata", "rapid_init_burst",
    ]

    @staticmethod
    def mutate():
        """Returns (udp_payload, tcp_payload) — exactly one is non-None."""
        return build_inspector_stress_packet(
            anomaly=random.choice(InspectorStressMutator.ANOMALIES))


class IPDefragMutator:
    ANOMALIES = [
        "overlap_overflow", "triple_overlap", "max_offset_fragment",
        "tiny_last_overlap", "duplicate_offset",
    ]

    @staticmethod
    def mutate():
        """Returns list of (payload, frag_offset, mf, ip_id, proto) tuples."""
        return build_ip_defrag_exploit(
            anomaly=random.choice(IPDefragMutator.ANOMALIES))


class BackOrificeMutator:
    ANOMALIES = [
        "truncated_length", "zero_length_payload", "max_length_short_data",
        "lookup_collision", "prng_state_poison", "encrypted_truncated",
    ]

    @staticmethod
    def mutate() -> bytes:
        return build_back_orifice_exploit(
            anomaly=random.choice(BackOrificeMutator.ANOMALIES))


class DCESmbMutator:
    ANOMALIES = [
        "doff_backward", "doff_max", "transaction_null",
        "session_setup_short", "co_pdu_invalid_type",
    ]

    @staticmethod
    def mutate() -> bytes:
        return build_dce_smb_exploit(
            anomaly=random.choice(DCESmbMutator.ANOMALIES))


class DNSDynamicUpdateMutator:
    ANOMALIES = [
        "zone_bomb", "prereq_type_confusion", "update_delete_all",
        "mixed_sections_overflow", "tsig_forged",
    ]

    @staticmethod
    def mutate() -> bytes:
        return build_dns_dynamic_update(
            anomaly=random.choice(DNSDynamicUpdateMutator.ANOMALIES))


class MultiQueryStormMutator:
    ANOMALIES = [
        "type_confusion", "class_chaos", "qdcount_type_mismatch",
        "null_name_queries", "mixed_ptr_inline",
    ]

    @staticmethod
    def mutate() -> bytes:
        return build_multi_query_storm(
            anomaly=random.choice(MultiQueryStormMutator.ANOMALIES))