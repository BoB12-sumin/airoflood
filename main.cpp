#include <pcap.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ifaddrs.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <array>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <utility>
#include <cstring>
#include <map>
#include <iomanip>

using namespace std;

struct dot11
{
    u_int8_t it_version; /* set to 0 */
    u_int8_t it_pad;
    u_int16_t it_len;     /* entire length */
    u_int32_t it_present; /* fields present */
} __attribute__((__packed__));

void print_dot11(struct dot11 *my_struct)
{
    printf("it_version: %u\n", my_struct->it_version);
    printf("it_pad: %u\n", my_struct->it_pad);
    printf("it_len: %u\n", my_struct->it_len);
    printf("it_present: %u\n", my_struct->it_present);
}

void usage()
{
    printf("syntax: airo-mon <interface> \n");
    printf("sample: airo-mon wlan0\n");
}

bool check_beacon_frame(const uint8_t *frame_ptr, size_t length)
{
    if (length < 2)
    {
        return false;
    }

    const uint16_t *type_sub_type_field = reinterpret_cast<const uint16_t *>(frame_ptr);
    uint16_t type_sub_type = ntohs(*type_sub_type_field); // 네트워크 바이트 순서를 호스트 바이트 순서로 변환

    // Beacon frame의 타입 및 서브타입 값은 0x8000
    return type_sub_type == 0x8000;
}

void adjust_offset_for_boundary(size_t &offset, size_t field_size)
{
    if (field_size % 2 == 0)
    {
        offset = (offset + 1) & ~1; // 2바이트 경계에 맞추기
    }
}

vector<string> read_essids_from_file(const string &filename)
{
    ifstream file(filename);
    vector<string> essids;
    string line;

    while (getline(file, line))
    {
        if (!line.empty())
        {
            essids.push_back(line);
        }
    }

    return essids;
}

void beacon_process(struct dot11 *header, struct pcap_pkthdr *pcap_header, const string &fake_essid)
{

    // Check version
    if (header->it_version != 0)
    {
        printf("packet's version must be 0 \n");
        return;
    }

    int radiolength = header->it_len;
    size_t offset = sizeof(dot11);

    size_t length = pcap_header->caplen;

    if (length < offset + 16)
    {
        printf("Packet too short for BSSID\n");
        return;
    }

    const size_t ieee80211_header_length = 24;

    // 비콘 프레임 페이로드 시작점
    uint8_t *frame_payload_ptr = reinterpret_cast<uint8_t *>(header) + radiolength + ieee80211_header_length;
    uint8_t *tagged_ptr = frame_payload_ptr;

    uint8_t *essid_ptr = reinterpret_cast<uint8_t *>(tagged_ptr) + 12;
    uint8_t essid_pkt = *essid_ptr;

    uint8_t *essid_len_ptr = reinterpret_cast<uint8_t *>(essid_ptr) + 1;
    const uint8_t real_essid_len = *essid_len_ptr;
    const uint8_t fake_essid_len = fake_essid.length();

    uint8_t *essid_content_ptr = reinterpret_cast<uint8_t *>(essid_ptr) + 2;
    const uint8_t essid_content = *essid_content_ptr;

    size_t remain_data_len = length - (essid_content_ptr - reinterpret_cast<uint8_t *>(header)) - real_essid_len; // 전체 패킷 - essid content 시작지점까지의 length - real essid length -> essid 가 끝나고 이후의 데이터 길이

    if (real_essid_len != fake_essid_len)
    {
        // 데이터 이동
        memmove(essid_content_ptr + fake_essid_len, essid_content_ptr + real_essid_len, remain_data_len);
        int length_difference = fake_essid_len - real_essid_len;
        length += length_difference;
        pcap_header->caplen += length_difference;
        pcap_header->len += length_difference;
    }

    // ESSID 업데이트
    *essid_len_ptr = fake_essid_len;
    memcpy(essid_content_ptr, fake_essid.c_str(), fake_essid_len);

    string essid;
    for (int i = 0; i < fake_essid_len; ++i)
    {
        essid += static_cast<char>(essid_content_ptr[i]);
    }

    printf("fake essid: %s\n", essid.c_str());
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    string essid_file = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // pcap_t *handle = pcap_open_offline("./pcapdir/beacon-a2000ua-testap5g.pcap", errbuf);
    // pcap_t *handle = pcap_open_offline("./pcapdir/dot11-sample.pcap", errbuf);

    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    string fakestr1 = "hello, I'm bob";
    // string fakestr2 = "bob";

    struct pcap_pkthdr *
        header;
    const uint8_t *packet;
    u_char *reply1 = nullptr;

    while (true)
    {
        int ret = pcap_next_ex(handle, &header, &packet);
        if (ret == 0)
        {
            printf("Timeout, no packet received\n");
            continue;
        }
        if (ret == -1 || ret == -2)
        {
            // Error or EOF, break the loop
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
            break;
        }

        struct dot11 *radiotap_hdr = (struct dot11 *)packet;
        const size_t ieee80211_header_length = 24;

        if (check_beacon_frame(reinterpret_cast<const uint8_t *>(radiotap_hdr) + (radiotap_hdr->it_len), header->caplen - (radiotap_hdr->it_len)))
        {
            beacon_process(radiotap_hdr, header, fakestr1);
        }
        else
        {
            continue;
        }

        if (pcap_sendpacket(handle, packet, header->caplen) != 0)
        {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        }
    }

    return 0;
}