#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    //Step1 检查数据包长度：
    if (buf->len < sizeof(ip_hdr_t)){//数据包长度小于最小首部长度，丢弃
        return;
    }
    ip_hdr_t* hdr = (ip_hdr_t*)buf->data;

    //Step2 进行报头检测：
    if (hdr->version != IP_VERSION_4 ||//版本号不为IPv4
        swap16(hdr->total_len16) > buf->len ||//总长度字段大于收到的数据包长度
        hdr->hdr_len < sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE){//IP报头长度小于最小首部长度
        return;
    }

    //Step3 校验头部校验和：
    //先把 IP 头部的头部校验和字段用其他变量保存起来，接着将该头部校验和字段置为 0
    //是否需要大小端转换？—— 不需要，计算与验算均按网络字节顺序（见ip_fragment_out）
    uint16_t hdr_checksum = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;

    //调用 checksum16 函数来计算头部校验和与 IP 头部原本的首部校验和字段进行对比
    //若不一致,丢弃
    if (hdr_checksum != checksum16((uint16_t *)hdr, hdr->hdr_len * IP_HDR_LEN_PER_BYTE)){
        return;
    }
    //若一致，则再将该头部校验和字段恢复成原来的值
    hdr->hdr_checksum16 = hdr_checksum;

    //Step4 对比目的 IP 地址：
    //若不是发送给本机的，将其丢弃
    if (memcmp(hdr->dst_ip,net_if_ip,NET_IP_LEN) != 0){
        return;
    }

    //Step5 去除填充字段：
    //若数据包长度大于总长度字段,说明有填充字段
    if (swap16(hdr->total_len16) < buf->len){
        buf_remove_padding(buf,buf->len - swap16(hdr->total_len16));
    }

    //Step6 去掉 IP 报头：
    buf_remove_header(buf, hdr->hdr_len * IP_HDR_LEN_PER_BYTE);

    //Step7 向上层传递数据包：
    //调用 net_in() 函数向上层传递数据包。
    if (net_in(buf, hdr->protocol,hdr->src_ip) != 0){
        //传递失败，返回-1
        //重新加入 IP 报头
        buf_add_header(buf,hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
        //调用 icmp_unreachable() 函数返回 ICMP 协议不可达信息
        icmp_unreachable(buf,hdr->src_ip,ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    //Step1 增加头部缓存空间：
    buf_add_header(buf, sizeof(ip_hdr_t));

    //Step2 填写头部字段：
    ip_hdr_t* hdr = (ip_hdr_t*)buf->data;

    hdr->version     = IP_VERSION_4;
    hdr->hdr_len     = sizeof(ip_hdr_t)/IP_HDR_LEN_PER_BYTE;
    hdr->tos         = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->id16        = swap16(id);

    if (mf) hdr->flags_fragment16 = swap16(IP_MORE_FRAGMENT | offset);
    else    hdr->flags_fragment16 = swap16(offset);

    hdr->ttl = IP_DEFALUT_TTL;
    hdr->protocol = protocol;
    hdr->hdr_checksum16 = 0;

    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);

    //Step3 计算并填写校验和：
    hdr->hdr_checksum16 = checksum16((uint16_t*)hdr, sizeof(ip_hdr_t));

    //Step4 发送数据：
    //调用 arp_out() 函数将封装后的 IP 头部和数据发送出去。
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    //数据报标识
    static uint16_t ip_id = 0;
    //数据报最大包长
    static uint16_t data_max_len = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);

    //Step1 检查数据报包长：
    if (buf->len <= data_max_len){
        //若数据报包长<=以太网MTU-报头长度，无需分段，则直接发送
        ip_fragment_out(buf,ip,protocol,ip_id++,0,0);
        return;
    }

    // Step2 分片处理：
    // 若数据报包长超过 IP 协议最大负载包长，则需要进行分片发送。具体操作如下：
    buf_t _ip_buf;
    buf_t* ip_buf = &_ip_buf;

    //分片发送数据报
    uint16_t current_offset = 0;
    while (buf->len > data_max_len){
        // 首先调用 buf_init() 初始化一个 ip_buf。
        buf_init(ip_buf,data_max_len);
        //将数据报截断，每个截断后的包长等于 IP 协议最大负载包长（1500 字节 - IP 首部长度）
        memcpy(ip_buf->data,buf->data,data_max_len);
        buf_remove_header(buf,data_max_len);
        //调用 ip_fragment_out() 函数发送出去
        ip_fragment_out(ip_buf,ip,protocol,ip_id,current_offset/IP_HDR_OFFSET_PER_BYTE,1);
        current_offset += data_max_len;
    }

    //发送最后一个分片
    //注意最后数据报标识需要+1
    buf_init(ip_buf, buf->len);
    memcpy(ip_buf->data, buf->data, buf->len);
    buf_remove_header(buf, buf->len);
    ip_fragment_out(ip_buf, ip, protocol, ip_id++, current_offset/IP_HDR_OFFSET_PER_BYTE, 0);
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}