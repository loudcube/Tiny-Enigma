 /*************************************************************
 * An OpenSSL based cryptographic class that encrypts and
 * decrypts data using AES-256.
 *
 * The key can be set directly or derived from a password
 * using deriveKey(QString &). The IV can be generated using
 * generateIV().
 *
 * Due to AES-256 being used the key length is 256 bit and the
 * iv length is 128 bit. Given key and iv are expected to have 
 * exactly these proportions! Lengths longer or shorter than 
 * expected WILL result in a seqmentation fault.
 * 
 * Till now deriveKey(QString&) does not use any salt.
 * 
 * Further information:
 *  https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_
 *      and_Decryption
 *  https://wiki.openssl.org/index.php/Manual:EVP_EncryptInit(3)
 *  https://wiki.openssl.org/index.php/Random_Numbers
 *************************************************************/

#ifndef CRYPTOGRAPHIC_H
#define CRYPTOGRAPHIC_H

#define KEY_LENGTH 32
#define IV_LENGTH 16
#define BLOCK_SIZE IV_LENGTH

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <QString>
#include <QDebug>
#include <QByteArray>

class Cryptographic : public QObject
{
    Q_OBJECT
public:
    // create instance with raw key
    explicit Cryptographic(unsigned char *key, unsigned char *iv, QObject *parent = 0);
    // create instance using password --> iv is generated internally
    explicit Cryptographic(QString &password, QObject *parent = 0);
    // destruct instance
    ~Cryptographic();
    
    // get methods
    QByteArray key();
    QByteArray iv();
    
    // encrypt data
    QByteArray encryptByteArray(QByteArray &plain);
    // decrypt data
    QByteArray decryptByteArray(QByteArray &cipher);

signals:

public slots:

private:
    unsigned char *m_key = nullptr;
    unsigned char *m_iv = nullptr;

    // initialize OpenSSL library
    void initOpenSsl();
    // generate iv
    QByteArray generateIV();
    // derive key from password
    QByteArray deriveKey(QString &password);
};

#endif // CRYPTOGRAPHIC_H
