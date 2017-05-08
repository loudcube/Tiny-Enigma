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
    
    EVP_cleanup();
    ERR_free_strings();
}

QByteArray Cryptographic::key()
{
    QByteArray key;
    key.append(reinterpret_cast<const char*>(m_key), KEY_LENGTH);
    return key;
}

QByteArray Cryptographic::iv()
{
    QByteArray iv;
    iv.append(reinterpret_cast<const char*>(m_iv), IV_LENGTH);
    return iv;
}

void Cryptographic::encryptFile(QIODevice &plain_file, QIODevice &cipher_file)
{
    // open QIODevices
    plain_file.open(QIODevice::ReadOnly);
    cipher_file.open(QIODevice::WriteOnly);
    
    // data streams
    QDataStream plain_stream(&plain_file);
    QDataStream cipher_stream(&cipher_file);
    
    // buffers
    unsigned char *plain_buffer = reinterpret_cast<unsigned char*>(malloc(sizeof(unsigned char*) * BUFFER_SIZE));
    unsigned char *cipher_buffer = reinterpret_cast<unsigned char*>(malloc(sizeof(unsigned char*) * 
                                                                           (BUFFER_SIZE + BLOCK_SIZE - 1)));
    
    int tmp_len = 0; // the number of bytes written by OpenSSL
    int read_bytes = 0; // the number of bytes read from the QIODevice
    
    try
    {
        initCtx();
    }
    catch(QString str)
    {
        throw str;
    }
    
    if(EVP_EncryptInit_ex(m_ctx, EVP_aes_256_cbc(), NULL, m_key, m_iv) != 1)
    {
        qDebug() << "unable to initialize encryption encryptFile(QIODevice&, QIODevice&)";
        throw QString("unable to initialize encryption encryptFile(QIODevice&, QIODevice&)");
    }
    
    while(!plain_stream.atEnd())
    {       
        read_bytes = plain_stream.readRawData(reinterpret_cast<char*>(plain_buffer), BUFFER_SIZE);
        
        if(EVP_EncryptUpdate(m_ctx, cipher_buffer, &tmp_len, plain_buffer, read_bytes) != 1)
        {
            qDebug() << "unable to update encryption encrypt(ByteArray&)";
            throw QString("unable to update encryption encrypt(ByteArray&)");
        }
        
        cipher_stream.writeRawData(reinterpret_cast<const char*>(cipher_buffer), tmp_len);
    }
    
    if(EVP_EncryptFinal_ex(m_ctx, cipher_buffer, &tmp_len) != 1)
    {
        qDebug() << "unable to finalize encryption encrypt(ByteArray&)";
        throw QString("unable to finalize encryption encrypt(ByteArray&)");
    }
    else
    {
        cipher_stream.writeRawData(reinterpret_cast<const char*>(cipher_buffer), tmp_len);
    }
    
    EVP_CIPHER_CTX_cleanup(m_ctx);
    free(plain_buffer);
    free(cipher_buffer);
}

void Cryptographic::decryptFile(QIODevice &cipher_file, QIODevice &plain_file)
{
    // open QIODevices
    plain_file.open(QIODevice::WriteOnly);
    cipher_file.open(QIODevice::ReadOnly);
    
    // data streams
    QDataStream plain_stream(&plain_file);
    QDataStream cipher_stream(&cipher_file);
    
    // buffers
    unsigned char *plain_buffer = reinterpret_cast<unsigned char*>(malloc(sizeof(unsigned char*) * (BUFFER_SIZE + BLOCK_SIZE)));
    unsigned char *cipher_buffer = reinterpret_cast<unsigned char*>(malloc(sizeof(unsigned char*) * BUFFER_SIZE));
    
    int tmp_len = 0; // the number of bytes written by OpenSSL
    int read_bytes = 0; // the number of bytes read from the QIODevice
    
    try
    {
        initCtx();
    }
    catch(QString str)
    {
        throw str;
    }
    
    if(EVP_DecryptInit_ex(m_ctx, EVP_aes_256_cbc(), NULL, m_key, m_iv) != 1)
    {
        qDebug() << "unable to initialize encryption encryptFile(QIODevice&, QIODevice&)";
        throw QString("unable to initialize encryption encryptFile(QIODevice&, QIODevice&)");
    }
    
    while(!cipher_stream.atEnd())
    {       
        read_bytes = cipher_stream.readRawData(reinterpret_cast<char*>(cipher_buffer), BUFFER_SIZE);
        
        if(EVP_DecryptUpdate(m_ctx, plain_buffer, &tmp_len, cipher_buffer, read_bytes) != 1)
        {
            qDebug() << "unable to update encryption encrypt(ByteArray&)";
            throw QString("unable to update encryption encrypt(ByteArray&)");
        }
        
        plain_stream.writeRawData(reinterpret_cast<const char*>(plain_buffer), tmp_len);
    }
    
    if(EVP_DecryptFinal_ex(m_ctx, plain_buffer, &tmp_len) != 1)
    {
        qDebug() << "unable to finalize encryption encrypt(ByteArray&)";
        throw QString("unable to finalize encryption encrypt(ByteArray&)");
    }
    else
    {
        plain_stream.writeRawData(reinterpret_cast<const char*>(plain_buffer), tmp_len);
    }
    
    EVP_CIPHER_CTX_cleanup(m_ctx);
    free(plain_buffer);
    free(cipher_buffer);
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

void Cryptographic::initCtx()
{
    if(!(m_ctx = EVP_CIPHER_CTX_new()))
    {
        qDebug() << "unable to create cipher context encrypt(ByteArray&)";
        throw QString("unable to create cipher context encrypt(ByteArray&)");
    }
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
