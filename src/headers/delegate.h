//
// Created by rinlang on 4/2/23.
//

#ifndef WIREWHALE_DELEGATE_H
#define WIREWHALE_DELEGATE_H

#include<QWidget>
#include<QItemDelegate>
#include<QStyleOptionViewItem>

class delegate: public QItemDelegate {
public:
    delegate(QWidget *parent = NULL):QItemDelegate(parent)
            {}

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override //final
    {
        Q_UNUSED(parent)
        Q_UNUSED(option)
        Q_UNUSED(index)
        return nullptr;
    }
};


#endif //WIREWHALE_DELEGATE_H
