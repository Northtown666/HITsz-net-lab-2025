#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // TO-DO
    //Step1. 初始化缓冲区：
    buf_init(&txbuf, sizeof(arp_pkt_t));
    //Step2. 填写ARP报头:
    arp_pkt_t* hdr = (arp_pkt_t*)txbuf.data;
    hdr->hw_type16 = swap16(ARP_HW_ETHER);
    hdr->pro_type16 = swap16(NET_PROTOCOL_IP);
    hdr->hw_len = NET_MAC_LEN;
    hdr->pro_len = NET_IP_LEN;
    memcpy(hdr->sender_mac,net_if_mac, NET_MAC_LEN);
    memcpy(hdr->sender_ip,net_if_ip,NET_IP_LEN);
    memcpy(hdr->target_ip,target_ip,NET_IP_LEN);
    //Step3. 设置操作类型(同时要注意进行大小端转换)：
    hdr->opcode16 = swap16(ARP_REQUEST);
    //Step4. 发送 ARP 报文：
    ethernet_out(&txbuf,ether_broadcast_mac,NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    //Step1. 初始化缓冲区：
    buf_init(&txbuf, sizeof(arp_pkt_t));
    //Step2. 填写 ARP 报头首部：
    arp_pkt_t* hdr = (arp_pkt_t*)txbuf.data;
    hdr->hw_type16 = swap16(ARP_HW_ETHER);
    hdr->pro_type16 = swap16(NET_PROTOCOL_IP);
    hdr->hw_len = NET_MAC_LEN;
    hdr->pro_len = NET_IP_LEN;
    memcpy(hdr->sender_mac,net_if_mac, NET_MAC_LEN);
    memcpy(hdr->sender_ip,net_if_ip,NET_IP_LEN);
    memcpy(hdr->target_mac,target_mac,NET_MAC_LEN);
    memcpy(hdr->target_ip,target_ip,NET_IP_LEN);
    //Step3. 设置操作类型(同时要注意进行大小端转换)：
    hdr->opcode16 = swap16(ARP_REPLY);
    //Step4. 发送 ARP 报文：
    ethernet_out(&txbuf,target_mac,NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    //Step1. 检查数据长度：
    if (buf->len < sizeof(arp_pkt_t)){
        return;
    }
    //Step2. 报头检查：
    arp_pkt_t* hdr = (arp_pkt_t*)buf->data;
    if (
        hdr->hw_type16 != swap16(ARP_HW_ETHER) ||
        hdr->pro_type16 != swap16(NET_PROTOCOL_IP) ||
        hdr->hw_len != NET_MAC_LEN ||
        hdr->pro_len != NET_IP_LEN ||
        (hdr->opcode16 != swap16(ARP_REQUEST) &&
         hdr->opcode16 != swap16(ARP_REPLY))
    )   return;
    //Step3. 更新 ARP 表项：
    map_set(&arp_table,hdr->sender_ip,hdr->sender_mac);
    //Step4. 查看缓存情况：
    buf_t * arp_buf_pkt = (buf_t*)map_get(&arp_buf,hdr->sender_ip);

    if (arp_buf_pkt!=NULL){//有缓存的情况
        //调用ethernet_out发送缓存中的数据包
        ethernet_out(arp_buf_pkt,hdr->sender_mac,NET_PROTOCOL_IP);
        map_delete(&arp_buf,hdr->sender_ip);
    }

    //没有缓存的情况下，检查是否是请求自己MAC地址的ARP请求报文
    if(hdr->opcode16 == swap16(ARP_REQUEST) &&
        memcmp(hdr->target_ip,net_if_ip,NET_IP_LEN)==0){
        //如果是请求自己的MAC地址的，调用arp_resp进行回应
        arp_resp(hdr->sender_ip,hdr->sender_mac);
    }
}


/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    //Step1. 查找 ARP 表：
    uint8_t* target_mac = map_get(&arp_table,ip);
    //Step2. 找到对应 MAC 地址：
    if (target_mac){
        //将数据包直接发送给以太网层
        ethernet_out(buf,target_mac,NET_PROTOCOL_IP);
        return;
    }
    //Step3. 未找到对应 MAC 地址：
    if (map_get(&arp_buf,ip)==NULL){//如果arp_buf里没有包
        //将这个包缓存到 arp_buf 中
        map_set(&arp_buf,ip,buf);
        //发送一个请求目标IP地址对应的MAC地址的ARP请求报文
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}