//
// Created by rinlang on 4/1/23.
//

#ifndef WIREWHALE_MULTITHREAD_H
#define WIREWHALE_MULTITHREAD_H
#include <QThread>
#include <pcap.h>
#include "data_unit.h"


class multithread:public QThread {
    Q_OBJECT
private:
    pcap_t *device;
    struct  pcap_pkthdr *pkt_header;//数据包头指针
    const u_char  *pkt_data;//数据包内容指针
    time_t local_time_sec;//秒time
    struct tm local_time;//time的拆分形式结构体
    char time_string[16];
    bool is_done;

public:
    multithread();
    bool  setPointer(pcap_t *pointer);
    void setFlag();
    void resetFlag();
    void run() override;
    int epHandle(const u_char * pkt_content, QString& info);
    int ipHandle(const u_char* pkt_content, int& ipPackage);
    int tcpHandle(const u_char* pkt_content, QString& info, int ipPackage);
    int udpHandle(const u_char* pkt_content, QString& info);
    QString arpHandle(const u_char* pkt_content);
    QString dnsHandle(const u_char* pkt_content);
    QString icmpHandle(const u_char * pkt_content);

protected:
    static QString byteToString(u_char* str, int size);

    signals:
    void send(DataUnit data);//发送信号

};


#endif //WIREWHALE_MULTITHREAD_H
