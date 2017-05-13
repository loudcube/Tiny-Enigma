 /*************************************************************
 * An OpenSSL based TinyEnigma class that encrypts and
 * decrypts data using AES-256.
 *
 * The key can be set directly or derived from a password
 * using deriveKey(QString &). The IV is automatically 
 * generated using generateIV() when a TinyEnigma object is 
 * initialized using a password with
 * TinyEnigma(QString &password, QObject *parent = 0).
 *
 * Due to AES-256 being used the key length is 256 bit and the
 * iv length is 128 bit. Given key and iv are expected to have 
 * exactly these proportions! Lengths longer or shorter than 
 * expected WILL result in a seqmentation fault.
 * 
 * Further information:
 *  https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_
 *      and_Decryption
 *  https://wiki.openssl.org/index.php/Manual:EVP_EncryptInit(3)
 *  https://wiki.openssl.org/index.php/Random_Numbers
 *************************************************************/

#ifndef TINY_ENIGMA_H
#define TINY_ENIGMA_H

#define KEY_LENGTH 32
#define IV_LENGTH 16
#define BLOCK_SIZE IV_LENGTH
#define BUFFER_SIZE 1024

#include "tiny-enigma_global.h"
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <QString>
#include <QDebug>
#include <QByteArray>
#include <QFile>
#include <QDataStream>

class TINY_ENIGMA_SHARED_EXPORT TinyEnigma : public QObject
{
    Q_OBJECT
public:
    // create instance with raw key
    explicit TinyEnigma(unsigned char *key, unsigned char *iv, QObject *parent = 0);
    // create instance using password --> iv is generated internally
    explicit TinyEnigma(QString &password, QObject *parent = 0);
    // destruct instance
    ~TinyEnigma();
    
    // get methods
    QByteArray key();
    QByteArray salt();
    QByteArray iv();
    
    // encrypt a whole file
    void encryptFile(QIODevice &plain_file, QIODevice &cipher_file);
    void decryptFile(QIODevice &cipher_file, QIODevice &plain_file);

signals:

public slots:

private:
    unsigned char *m_key = nullptr;
    QByteArray m_salt;
    unsigned char *m_iv = nullptr;
    EVP_CIPHER_CTX *m_ctx = nullptr;

    // initialize OpenSSL library
    void initOpenSsl();
    // initialize cipher context
    void initCtx();
    // generate iv
    QByteArray generateIV();
    // generate salt, uses generateIV()
    QByteArray generateSalt();
    // derive key from password
    QByteArray deriveKey(QString &password);
};

#endif // TINY_ENIGMA_H
