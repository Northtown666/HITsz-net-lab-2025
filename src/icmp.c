#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    //Step1 初始化并封装数据：
    //调用 buf_init() 函数来初始化 txbuf
    buf_init(&txbuf,req_buf->len);
    //拷贝来自接收的回显请求报文中的数据
    memcpy(txbuf.data, req_buf->data, req_buf->len);

    icmp_hdr_t *req_hdr = (icmp_hdr_t *)req_buf->data;
    icmp_hdr_t *hdr = (icmp_hdr_t*)txbuf.data;

    //封装 ICMP 报头
    hdr->type = ICMP_TYPE_ECHO_REPLY;
    hdr->code = 0;//本实验不支持0对应的代码
    hdr->checksum16 = 0;
    hdr->id16 = req_hdr->id16;
    hdr->seq16 = req_hdr->seq16;

    //Step2 填写校验和：
    //ICMP报头的校验和涵盖了整个报文，因此直接使用txbuf的参数而不是hdr
    hdr->checksum16 = checksum16((uint16_t*)txbuf.data, txbuf.len);

    //Step3 发送数据报：
    //调用 ip_out() 函数将封装好且填写了校验和的 ICMP 数据报发送出去。
    ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    //Step1 报头检测：
    if (buf->len < sizeof(icmp_hdr_t)){
        return;
    }

    //Step2 查看 ICMP 类型：重点关注是否为回显请求类型。
    icmp_hdr_t* hdr = (icmp_hdr_t*)buf->data;

    //Step3 回送回显应答：调用 icmp_resp() 函数回送一个回显应答（ping 应答）。
    if (hdr->type == ICMP_TYPE_ECHO_REQUEST &&
        hdr->code == 0){//本实验不支持0对应的代码
        icmp_resp(buf,src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    //Step1 初始化并填写ICMP数据部分：
    //调用 buf_init() 函数来初始化 txbuf
    //txbuf首先填写数据部分：IP 数据报首部和 IP 数据报的前 8 个字节的数据字段。
    buf_init(&txbuf, sizeof(ip_hdr_t) + 8);
    memcpy(txbuf.data,recv_buf->data,sizeof(ip_hdr_t) + 8);

    //Step2 填写报头：
    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    icmp_hdr_t *hdr = (icmp_hdr_t*)txbuf.data;
    hdr->type = ICMP_TYPE_UNREACH;
    hdr->code = code;
    hdr->checksum16 = 0;
    hdr->id16 = 0;
    hdr->seq16 = 0;

    //Step3 计算校验和
    //同icmp_resp()
    hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    //Step4 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);

}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}