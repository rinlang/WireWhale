//
// Created by rinlang on 3/31/23.
//

#ifndef WIREWHALE_MAIN_WINDOW_H
#define WIREWHALE_MAIN_WINDOW_H

#include <QMainWindow>
#include <pcap.h>
#include <QVector>
#include "data_unit.h"
#include "delegate.h"


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
Q_OBJECT

private:
    Ui::MainWindow *ui;
    pcap_if_t  *all_devices_list;//所有设备列表
    pcap_if_t *device_node;//单个设备列表节点
    pcap_t *device;//指向单个设备的指针描述符，使用该描述符进行抓包操作
    QVector<DataUnit>pData;
    int count;//数据包个数
    char errbuf[PCAP_ERRBUF_SIZE];//pcap错误信息buf
    delegate* readOnlyDelegate;
    int numberRow;

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;
    void showNetworkAdapter();
    int capture();
private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);
public slots:
    void HandleMessage(DataUnit data);//接收子线程信号


};


#endif //WIREWHALE_MAIN_WINDOW_H
