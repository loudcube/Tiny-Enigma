#include "cryptographic.h"

Cryptographic::Cryptographic(unsigned char *key, unsigned char *iv, QObject *parent) 
    : QObject(parent), m_key(key), m_iv(iv)
{
    initOpenSsl();
}

Cryptographic::Cryptographic(QString &password, QObject *parent) 
    : QObject(parent)
{
    initOpenSsl();
    m_key = reinterpret_cast<unsigned char*>(deriveKey(password).data());
    m_iv = reinterpret_cast<unsigned char*>(generateIV().data());
}

Cryptographic::~Cryptographic()
{
    free(m_key);
    free(m_iv);
}

QByteArray Cryptographic::key()
{
    QByteArray key = QByteArray::fromRawData(reinterpret_cast<const char*>(m_key), KEY_LENGTH);
    return key;
}

QByteArray Cryptographic::iv()
{
    QByteArray iv = QByteArray::fromRawData(reinterpret_cast<const char*>(m_iv), IV_LENGTH);
    return iv;
}

QByteArray Cryptographic::encryptByteArray(QByteArray &plain)
{
    // retrieve pointer to data of QByteArray --> needs reinterpret cast
    // actually this causes a dep copy, mabey use QByteArray::constData()
    unsigned char *plain_data = reinterpret_cast<unsigned char*>(plain.data());
    int plain_len = plain.size();
    // cipher data --> to be filled by EVP_EncryptUpdate()
    unsigned char *cipher_data = reinterpret_cast<unsigned char*>(malloc(sizeof(unsigned char*) * (plain_len + BLOCK_SIZE - 1)));
    int tmp_len = 0;
    int cipher_len = 0;
    
    // final QByteArray
    QByteArray cipher;
    
    // encrypt here
    EVP_CIPHER_CTX *ctx = nullptr;
    // check for errors
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        qDebug() << "unable to create cipher context encrypt(ByteArray&)";
        throw QString("unable to create cipher context encrypt(ByteArray&)");
    }
    else
    {
        qDebug() << "initialized ctx";
    }
    
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, m_key, m_iv) != 1)
    {
        qDebug() << "unable to initialize encryption encrypt(ByteArray&)";
        throw QString("unable to initialize encryption encrypt(ByteArray&)");
    }
    else
    {
        qDebug() << "initialized encryption";
    }
    
    qDebug() << "plain_len = " << plain_len;
    
    if(EVP_EncryptUpdate(ctx, cipher_data, &tmp_len, plain_data, plain_len) != 1)
    {
        qDebug() << "unable to initialize encryption encrypt(ByteArray&)";
        throw QString("unable to initialize encryption encrypt(ByteArray&)");
    }
    else
    {
        qDebug() << "updated cipher data";
        cipher_len += tmp_len;
        
        qDebug() << "update tmp_len: " << tmp_len;
    }
    
    if(EVP_EncryptFinal_ex(ctx, cipher_data + tmp_len, &tmp_len) != 1)
    {
        qDebug() << "unable to finalize encryption encrypt(ByteArray&)";
        throw QString("unable to finalize encryption encrypt(ByteArray&)");
    }
    else
    {
        qDebug() << "finalized encryption";
        cipher_len += tmp_len;
        
        cipher.append(reinterpret_cast<char*>(cipher_data), cipher_len);
    }
    
    qDebug() << "cipher_len = " << cipher_len;
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return cipher;
}

QByteArray Cryptographic::decryptByteArray(QByteArray &cipher)
{
    // retrieve pointer to data of QByteArray --> needs reinterpret cast
    unsigned char *cipher_data = reinterpret_cast<unsigned char*>(cipher.data());
    int cipher_len = cipher.size();
    // cipher data --> to be filled by EVP_DecryptUpdate()
    unsigned char *plain_data = reinterpret_cast<unsigned char*>(malloc(sizeof(unsigned char*) * (cipher_len + BLOCK_SIZE)));
    int tmp_len = 0;
    int plain_len = 0;
    
    // final QByteArray
    QByteArray plain;
    
    // encrypt here
    EVP_CIPHER_CTX *ctx = nullptr;
    // check for errors
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        qDebug() << "unable to create cipher context decrypt(ByteArray&)";
        throw QString("unable to create cipher context decrypt(ByteArray&)");
    }
    else
    {
        qDebug() << "initialized ctx";
    }
    
    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, m_key, m_iv) != 1)
    {
        qDebug() << "unable to initialize decryption decrypt(ByteArray&)";
        throw QString("unable to initialize decryption decrypt(ByteArray&)");
    }
    else
    {
        qDebug() << "initialized decryption";
    }
    
    qDebug() << "cipher_len = " << cipher_len;
    
    if(EVP_DecryptUpdate(ctx, plain_data, &tmp_len, cipher_data, cipher_len) != 1)
    {
        qDebug() << "unable to initialize decryption decrypt(ByteArray&)";
        throw QString("unable to initialize decryption decrypt(ByteArray&)");
    }
    else
    {
        qDebug() << "updated plain data";
        plain_len += tmp_len;
        
        qDebug() << "update tmp_len: " << tmp_len;
    }
    
    if(EVP_DecryptFinal_ex(ctx, plain_data + tmp_len, &tmp_len) != 1)
    {
        qDebug() << "unable to finalize encryption encrypt(ByteArray&)";
        ERR_print_errors_fp(stderr);
        throw QString("unable to finalize encryption encrypt(ByteArray&)");
    }
    else
    {
        qDebug() << "finalized decryption";
        plain_len += tmp_len;
        
        plain.append(reinterpret_cast<char*>(plain_data), plain_len);
    }
    
    qDebug() << "plain_len = " << plain_len;
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return plain;
}

// always call this before the first operation using OpenSSL!!!
void Cryptographic::initOpenSsl()
{
    // initialize library
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_ciphers();
    OPENSSL_config(NULL);
    
    // seed random number generator
    RAND_poll();
}

QByteArray Cryptographic::deriveKey(QString &password)
{
    // transform password into c string i.e. const char*
    const char *password_cstr = password.toStdString().c_str();
    // allocate key memory
    unsigned char *key = (unsigned char*) malloc(KEY_LENGTH * sizeof(unsigned char));
    // check for success
    if(!key)
    {
        qDebug() << "unable to allocate key memory: deriveKey(QString&)";
        throw QString("unable to allocate key memory: deriveKey(QString&)");
    }
    
    if(!PKCS5_PBKDF2_HMAC_SHA1(password_cstr, strlen(password_cstr), NULL, 0, 1000, KEY_LENGTH, key))
    {
        qDebug() << "error at: deriveKey(QString&)";
        throw QString("error at: deriveKey(QString&)");
    }
    else
    {
        QByteArray key_container;
        key_container.setRawData(reinterpret_cast<const char*>(key), KEY_LENGTH);
        return key_container;
    }
    
}

QByteArray Cryptographic::generateIV()
{
    // allocate iv memory
    unsigned char *iv = (unsigned char*) malloc(IV_LENGTH * sizeof(unsigned char));
    RAND_bytes(iv, IV_LENGTH);
    QByteArray iv_container;
    iv_container.setRawData(reinterpret_cast<const char*>(iv), IV_LENGTH);
    return iv_container;
}
