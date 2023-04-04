//
// Created by rinlang on 4/1/23.
//
//多线程处理数据包

#include "headers/multithread.h"
#include "format.h"
#include "data_unit.h"
#include <QDebug>

multithread::multithread() {
    this->is_done = true;
}

void multithread::run() {
    while (true){
        if(is_done){
            break;
        }else{
            int res = pcap_next_ex(this->device, &this->pkt_header, &this->pkt_data);//获取下一个包
            if(res == 0){//未抓到包
                continue;
            }else{
                this->local_time_sec =  this->pkt_header->ts.tv_sec;
                localtime_r(&(this->local_time_sec), &(this->local_time));
                strftime(this->time_string, sizeof(this->time_string), "%H:%M:%S", &(this->local_time));
                QString info = "";
                int type = epHandle(this->pkt_data, info);
                if(type){
                    DataUnit data;
                    data.setInfo(info);
                    data.setDataLength(this->pkt_header->len);
                    data.setTimeStamp(this->time_string);
                    data.setDataType(type);
                    data.setPktContent(pkt_data, pkt_header->len);
                    emit send(data);
                }
                // 处理数据包格式
            }
        }
    }
}

bool multithread::setPointer(pcap_t *pointer) {
    this->device = pointer;
    if(pointer)
        return true;
    else
        return false;
}

void multithread::setFlag() {
    this->is_done = false;
}

void multithread::resetFlag() {
    this->is_done = true;
}

int multithread::epHandle(const u_char *pkt_content, QString &info) {//以太网协议处理方法
    EP_HEADER* ep_header = (EP_HEADER*) pkt_content;
    u_short content_type = ntohs(ep_header->type);//转换网络字节序和主机字节序
    switch(content_type){
        case 0x0800:{//ip数据包
            int ipPackage = 0;
            int res = ipHandle(pkt_content, ipPackage);
            switch (res) {
                case 1: {//icmp
                    info = icmpHandle(pkt_content);
                    return 2;
                }
                case 6: {//tcp
                    return tcpHandle(pkt_content, info, ipPackage);
                }
                case 17:{//udp
                    return udpHandle(pkt_content, info);
                }
                default:
                    break;
            }
        }
        case 0x806:{//ARP
            info = arpHandle(pkt_content);
            return 1;
        }
        default:
            break;
    }
    return 0;
}

int multithread::ipHandle(const u_char *pkt_content, int &ipPackage) {
    IP_V4_HEADER* header;
    header = (IP_V4_HEADER*)(pkt_content + 14/*跳过以太头*/);
    int protocol = header->protocol;
    ipPackage = (ntohs(header->total_length) - ((header->version_and_header_length) & 0x0F) * 4);
    return protocol;
}

int multithread::tcpHandle(const u_char *pkt_content, QString &info, int ipPackage) {
    TCP_HEADER* header;
    header = (TCP_HEADER*)(pkt_content + 14 + 20/*跳过以太、ip头*/);
    u_short  src = ntohs(header->src_port);
    u_short des = ntohs(header->des_port);

    QString proSend = "";
    QString proRecv = "";

    int type = 3;//TCP
    int header_length = (header->header_length >> 4) * 4;
    int tcp_payload = ipPackage - header_length;

    if(src == 443 || des == 443) {
        if (src == 443)
            proSend = "(HTTPS)";
        else
            proRecv = "(HTTPS)";
        u_char * ssl = (u_char*)(pkt_content + 14 + 20 + header_length);
        u_char  isTls = *ssl;
        u_short *pointer = (u_short*) ssl;
        u_short version = ntohs(*pointer);
        if(isTls >= 20 && isTls <=23 && version >=0x0301 && version <= 0x0304){
            type = 6;
            switch(isTls){
                case 20:{
                    info = "Change Cipher Spec";
                    break;
                }
                case 21:{
                    info = "Alert";
                    break;
                }
                case 22:{
                    info = " Handshake";
                    ssl += 4;
                    u_char type = (*ssl);
                    switch (type) {
                        case 1:{
                            info += " Client Hello";
                            break;
                        }
                        case 2:{
                            info += "Server Hello";
                            break;
                        }
                        default:
                            break;
                    }
                }
                case 23:{
                    info  = "Application Data";
                    break;
                }
                default:
                    break;
            }
        }else{
            type = 7;
        }

        if(type == 7)
            info = "Continuation Data ";
    }
    info += QString::number(src) + proSend + "->" + QString::number(des) + proRecv;


    QString flag = "";
    if(header->flags & 0x08)  flag += "PSH,";
    if(header->flags & 0x10)  flag += "ACK,";
    if(header->flags & 0x02)  flag +="SYN,";
    if(header->flags & 0x20)  flag +="URG,";
    if(header->flags & 0x01)  flag +="FIN,";
    if(header->flags & 0x04)  flag +="RST,";
    if(flag != ""){
        flag = flag.left(flag.length() - 1);
        info += "[" + flag + "]";
    }

    u_int sequence = ntohl(header->sequence_num);
    u_int ack = ntohl(header->ack_num);
    u_short window = ntohs(header->window_size);

    info += " Seq=" + QString::number(sequence) + " ACK=" + QString::number(ack) + " win=" + QString::number(window) + " len=" + QString::number(tcp_payload);
    return type;
}

int multithread::udpHandle(const u_char *pkt_content, QString &info) {
    UDP_HEADER * header = (UDP_HEADER*)(pkt_content + 14 + 20);
    u_short des = ntohs(header->des_port);
    u_short src = ntohs(header->src_port);
    if(des == 53 || src == 53){
        info  = dnsHandle(pkt_content);
        return 5;
    }else{
        QString res = QString::number(src) + "->" + QString::number(des);
        u_short data_len = ntohs(header->datagram_length);
        res = "len = " + QString::number(data_len);
        info = res;
        return 4;
    }


}

QString multithread::arpHandle(const u_char *pkt_content) {
    ARP_HEADER * header = (ARP_HEADER*)(pkt_content + 14);
    
    u_short op = ntohs(header->op_type);
    QString res = "";
    u_char *des_ip = header->des_ip;
    QString des_ip_string = QString::number(*des_ip) + "." +  QString::number(*(des_ip+1)) + "." + QString::number(*(des_ip+2)) + "." + QString::number(*(des_ip+3));
    
    u_char *src_ip = header->src_ip;
    QString src_ip_string = QString::number(*src_ip) + "." +  QString::number(*(src_ip+1)) + "." + QString::number(*(src_ip+2)) + "." + QString::number(*(src_ip+3));
    
    u_char *src_mac = header->src_mac;
    QString src_mac_string = byteToString(src_mac, 1) + ":"
            + byteToString(src_mac+1, 1) + ":"
            + byteToString(src_mac+2, 1) + ":"
            + byteToString(src_mac+3, 1) + ":"
            + byteToString(src_mac+4, 1) + ":"
            + byteToString(src_mac+5, 1)  ;
    switch (op) {
        case 1:
            res = "who has " + des_ip_string + "? Tell" + src_ip_string;//询问
            break;
        case 2:
            res = src_ip_string + " is at " + src_mac_string;//响应
            break;
        default:
            break;
    }
    return res;
}

QString multithread::byteToString(u_char *str, int size) {
    QString res = "";
    for(int i = 0;i < size; i++){
        char high = str[i] >> 4;//获取字节高位
        if(high >= 0x0A){
            high += 0X41 -0X0A;
        }else{
            high += 0x30;
        }
        char low = str[i] & 0xF;
        if(low >= 0x0A){
            low += 0x41 -0x0A;
        }else{
            low += 0x30;
        }
        res.append(high);
        res.append(low);
    }
    return res;
}

QString multithread::dnsHandle(const u_char *pkt_content) {
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    u_short identification = ntohs(dns->identification);
    u_short type = ntohs(dns->flags);
    QString info = "";
    if((type & 0xf800) == 0x0000){
        info = "Standard query ";
    }
    else if((type & 0xf800) == 0x8000){
        info = "Standard query response ";
    }
    QString name = "";
    char*domain = (char*)(pkt_content + 14 + 20 + 8 + 12);
    while(*domain != 0x00){
        if(domain && (*domain) <= 64){
            int length = *domain;
            domain++;
            for(int k = 0;k < length;k++){
                name += (*domain);
                domain++;
            }
            name += ".";
        }else break;
    }
    // DNS_QUESITON *qus = (DNS_QUESITON*)(pkt_content + 14 + 20 + 8 + 12 + stringLength);
    // qDebug()<<ntohs(qus->query_type);
    // qDebug()<<ntohs(qus->query_class);
    name = name.left(name.length()-1);
    return info + "0x" + QString::number(identification,16) + " " + name;
}

QString multithread::icmpHandle(const u_char *pkt_content) {
    ICMP_HEADER *header = (ICMP_HEADER*)(pkt_content + 14 + 20);
    u_char type = header->type;
    u_char code = header->code;
    QString res = "";
    switch (type) {
        case 0:{
            if(!code){
                res = "Echo response(ping)";
            }
            break;
        }
        case 8:{
            if(!code){
                res = "Echo request(ping)";
            }
            break;
        }
        default:
            break;
    }
    return res;
            
}





