#include <QCoreApplication>
#include <QDebug>
#include <cryptographic.h>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    
    QString pass = "password";
    Cryptographic crypto(pass);
    qDebug() << "IV";
    qDebug() << "iv length: " << crypto.iv().length();
    qDebug() << crypto.iv().toHex();
    qDebug() << "KEY";
    qDebug() << "key length: " << crypto.key().length();
    qDebug() << crypto.key().toHex();
    qDebug() << "---------------------------";
    QString plain = "Hello world! This is a not so funny but useful text!";
    //QString plain = "Hello world!";
    QByteArray p = plain.toLocal8Bit();
    qDebug() << "Plain data";
    qDebug() << p.toHex();
    qDebug() << "---------------------------";
    qDebug() << "Cipher data";
    QByteArray encrypted = crypto.encryptByteArray(p);
    qDebug() << "---------------------------";
    qDebug() << encrypted.toHex();
    qDebug() << "---------------------------";
    qDebug() << "Encrypted plain data";
    qDebug() << crypto.decryptByteArray(encrypted).toHex();
    
    return a.exec();
}
