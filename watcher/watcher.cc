// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Windows.h needs to be the first include to prevent failures in subsequent headers.
#include <windows.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <iostream>
#include <string>
#include <condition_variable>
#include <mutex>
#include <unordered_map>

#include "watcher.h"

#include "net/if_ether.h"
#include "net/ip.h"
#include "net/udp.h"


#pragma comment(lib, "ebpfapi.lib")

#define htonl(x) _byteswap_ulong(x)
#define htons(x) _byteswap_ushort(x)
#define ntohl(x) _byteswap_ulong(x)
#define ntohs(x) _byteswap_ushort(x)


extern "C"
{
    int
    conn_track_history_callback(void *ctx, void *data, size_t size);
}


typedef UDP_HEADER udphdr;

// Define unique_ptr to call bpf_object__close on destruction
struct bpf_object_deleter
{
    void
    operator()(struct bpf_object* obj) const
    {
        if (obj) {
            bpf_object__close(obj);
        }
    }
};

typedef std::unique_ptr<struct bpf_object, bpf_object_deleter> bpf_object_ptr;

int print_name(unsigned char* data_start, int initial_offset, size_t size) {
    size_t i = initial_offset;
    for (; i < size; i++) {
        unsigned char label_len = data_start[i];

        if (label_len == 0xC0) {
            // This is a pointer
            int offset = ((label_len & 0x3F) << 8) | data_start[i + 1];
            print_name(data_start, offset, size);
            return i + 2;
        }

        if (label_len == 0) {
            i++;
            break;
        }
        i++;
        for (int j = 0; j < label_len; j++) {
            printf("%c", data_start[i + j]);
        }
        printf(".");
        i += label_len - 1;
    }
    return i;
}

int handle_event(void *ctx, void *input_data, size_t size) {
    // Process the DNS packet here

    unsigned char *data = (unsigned char *)input_data;

    // Packet contains a IP header, UDP header and DNS payload
    unsigned short question_count;
    unsigned short answer_count;
    unsigned short authority_count;
    unsigned short additional_count;

    iphdr *ip = (iphdr *)(data + sizeof(ethhdr));
    udphdr *udp = (udphdr *)(data + sizeof(ethhdr) + sizeof(iphdr));

    printf("Source IP: %d.%d.%d.%d\n", (ip->saddr >> 0) & 0xFF, (ip->saddr >> 8) & 0xFF, (ip->saddr >> 16) & 0xFF, (ip->saddr >> 24) & 0xFF);

    // The DNS payload starts after the UDP header
    unsigned char *dns_payload = (unsigned char *)(data + sizeof(ethhdr) + sizeof(iphdr) + sizeof(udphdr));

    // The first two bytes of the DNS payload are the transaction ID
    printf("Transaction ID: %02x%02x\n", dns_payload[0], dns_payload[1]);

    // The next two bytes are the flags
    printf("Flags: %02x%02x\n", dns_payload[2], dns_payload[3]);

    question_count = ntohs(*(uint16_t *)(dns_payload + 4));
    answer_count = ntohs(*(uint16_t *)(dns_payload + 6));
    authority_count = ntohs(*(uint16_t *)(dns_payload + 8));
    additional_count = ntohs(*(uint16_t *)(dns_payload + 10));

    // The next two bytes are the number of questions
    printf("Questions: %d\n", question_count);

    // The next two bytes are the number of answers
    printf("Answers: %d\n", answer_count);

    // The next two bytes are the number of authority records
    printf("Authority records: %d\n", authority_count);

    // The next two bytes are the number of additional records
    printf("Additional records: %d\n", additional_count);

    // Question section defined as:
    // QNAME: a domain name represented as a sequence of labels, where each label consists of a length byte followed by that number of bytes
    // QTYPE: a 16-bit value that specifies the type of the query
    // QCLASS: a 16-bit value that specifies the class of the query

    size_t i = 12;
    for (size_t questions = 0; questions < question_count; questions++) {
        printf("Question %zu:\n", questions + 1);
        // Print the domain name in the question section
        i = print_name(dns_payload, i, size - i);
        printf("\n");

        // Print the QTYPE
        printf("QTYPE: %02x%02x\n", dns_payload[i], dns_payload[i + 1]);
        i += 2;

        // Print the QCLASS
        printf("QCLASS: %02x%02x\n", dns_payload[i], dns_payload[i + 1]);
        i += 2;
    }

    // Answer section defined as:
    // NAME: a domain name to which the resource record pertains
    // TYPE: a 16-bit value that specifies the type of the resource record
    // CLASS: a 16-bit value that specifies the class of the resource record
    // TTL: a 32-bit unsigned integer that specifies the time interval that the resource record may be cached
    // RDLENGTH: a 16-bit unsigned integer that specifies the length in octets of the RDATA field
    // RDATA: a variable length string of octets that describes the resource

    for (size_t answer = 0; answer < answer_count; answer++) {
        printf("Answer %zu:\n", answer + 1);
        // Print the domain name in the answer section
        i = print_name(dns_payload, i, size - i);
        printf("\n");

        uint16_t type = ntohs(*(uint16_t *)(dns_payload + i));
        i += 2;
        uint16_t rr_class = ntohs(*(uint16_t *)(dns_payload + i));
        i += 2;
        uint32_t ttl = ntohl(*(uint32_t *)(dns_payload + i));
        i += 4;
        uint16_t rdlength = ntohs(*(uint16_t *)(dns_payload + i));
        i += 2;

        // Print the TYPE
        printf("TYPE: %u\n", type);

        // Print the CLASS
        printf("CLASS: %u\n", rr_class);

        // Print the TTL
        printf("TTL: %u\n", ttl);

        // Print the RDLENGTH
        printf("RDLENGTH: %u\n", rdlength);

        // Print the RDATA
        for (size_t j = 0; j < rdlength; j++) {
            printf("%02x", (unsigned char)dns_payload[i + j]);
        }
        printf("\n");
    }

    return 0;
}

bool _shutdown = false;
std::condition_variable _wait_for_shutdown;
std::mutex _wait_for_shutdown_mutex;

int control_handler(unsigned long control_type)
{
    if (control_type != CTRL_C_EVENT)
    {
        return false;
    }
    std::unique_lock lock(_wait_for_shutdown_mutex);
    _shutdown = true;
    _wait_for_shutdown.notify_all();
    return true;
}

int main(int argc, char **argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    if (!SetConsoleCtrlHandler(control_handler, true))
    {
        std::cerr << "SetConsoleCtrlHandler: " << GetLastError() << std::endl;
        return 1;
    }

    std::cerr << "Press Ctrl-C to shutdown" << std::endl;

    // Load dns_watcher.sys BPF program.
    struct bpf_object *object = bpf_object__open("dns_watcher.sys");
    if (!object)
    {
        std::cerr << "bpf_object__open for dns_watcher.sys failed: " << errno << std::endl;
        return 1;
    }

    if (bpf_object__load(object) < 0)
    {
        std::cerr << "bpf_object__load for dns_watcher.sys failed: " << errno << std::endl;
        return 1;
    }

    // Attach program to cgroup/connect4 attach point.
    auto program_v4 = bpf_object__find_program_by_name(object, "capture_dns");
    if (!program_v4)
    {
        std::cerr << "bpf_object__find_program_by_name for \"capture_dns\" failed: " << errno << std::endl;
        return 1;
    }

    uint32_t if_index = atoi(argv[1]);

    if (bpf_xdp_attach(if_index, bpf_program__fd(program_v4), 0, nullptr) < 0)
    {
        std::cerr << "bpf_xdp_attach for \"capture_dns\" failed: " << errno << std::endl;
        return 1;
    }

    // Attach to ring buffer.
    bpf_map *map = bpf_object__find_map_by_name(object, "dns_ringbuf");
    if (!map)
    {
        std::cerr << "Unable to locate dns_ringbuf map: " << errno << std::endl;
        return 1;
    }
    auto ring = ring_buffer__new(bpf_map__fd(map), handle_event, nullptr, nullptr);
    if (!ring)
    {
        std::cerr << "Unable to create ring buffer: " << errno << std::endl;
        return 1;
    }

    // Wait for Ctrl-C.
    {
        std::unique_lock lock(_wait_for_shutdown_mutex);
        _wait_for_shutdown.wait(lock, []()
                                { return _shutdown; });
    }


    // Close ring buffer.
    ring_buffer__free(ring);

    // Free the BPF object.
    bpf_object__close(object);
    return 0;
}
