# Tiny-Enigma
Tiny-Enigma is a simple to use and lightweight cryptographic library using OpenSSL. It is designed to integrate into the Qt framework. Due to that it is impossible to be used without.<br/>

## Documentation
To use the library one must only create an object of Tiny-Enigma and use its members.

### Public types
```c++
enum class Error { CipherContextError, KeyDerivationError, AllocationError,
                   InitializationError, UpdateError, FinalizeError, OpenFileError };
```

These are the all exceptions possibly thrown by this class. One should catch an exception of type `TinyEnigma::Error` like following.

```c++
try
{
  enigma.encryptFile(QIODevice &plain_file, QIODevice &cipher_file);
}
catch(TinyEnigma::Error::AllocationError e)
{
  qDebug() << Q_FUNC_INFO << " allocation error";
}
catch(TinyEnigma::Error::KeyDerivationError e)
{
  qDebug() << Q_FUNC_INFO << " unable to derive key";
}
```

Another way is the following.

```c++
try
{
  enigma.encryptFile(QIODevice &plain_file, QIODevice &cipher_file);
}
catch(TinyEnigma::Error e)
{
  switch (e) {
    case TinyEnigma::Error::AllocationError:
      qDebug() << Q_FUNC_INFO << " allocation error";
    default:
      qDebug() << Q_FUNC_INFO << " an unexpected exception occurred";
  }
}
```

### Public members
```c++
explicit TinyEnigma(unsigned char *key, unsigned char *iv, QObject *parent = 0);
explicit TinyEnigma(QString &password, QObject *parent = 0);
explicit TinyEnigma(const TinyEnigma&) = delete;
~TinyEnigma();

TinyEnigma &operator =(const TinyEnigma&) = delete;

QByteArray key();
QByteArray salt();
QByteArray iv();

void encryptFile(QIODevice &plain_file, QIODevice &cipher_file);
void decryptFile(QIODevice &cipher_file, QIODevice &plain_file);
```

__Note:__ The __copy constructor is disabled__ by design as it does not make any sense to copy an instance of Tiny-Enigma.

```c++
explicit TinyEnigma(unsigned char *key, unsigned char *iv, QObject *parent = 0);
```

Tiny-Enigma __takes__ ownership of `*key` and `*iv`!

```c++
explicit TinyEnigma(QString &password, QObject *parent = 0);
```

It is recommended to use the latter constructor as it is a lot safer than the one using raw key and iv. That way it is ensured that the right key and iv lengths are chosen. They can always be returned by members. However, this constructor __mights throw an exception__ of type `Tiny-Enigma::Error`. Even though it is unlikely that this will happen, one should catch the exception. Otherwise the application will be terminated.

```c++
QByteArray key();
QByteArray salt();
QByteArray iv();
```

For now Tiny-Enigma only supports encryption and decryption of a QIODevice.

```c++
void encryptFile(QIODevice &plain_file, QIODevice &cipher_file);
```

`plain_file` the QIODevice to be encrypted; `cipher_file` the one where the encrypted data shall be written to

__Note:__ might throw an exception

```c++
void decryptFile(QIODevice &cipher_file, QIODevice &plain_file);
```

`cipher_file` the QIODevice being decrypted; `cipher_file` the one where the decrypted data shall be written to

__Note:__ might throw an exception

However, one can always convert any type into a QByteArray and use QBuffer as a QIODevice for it. That way one can use Tiny-Enigma on any type.

## Motivation
My original motivation for creating this project was the need of a simple cryptographic library that integrates well with Qt. Because nothing available fitted my needs - not simple enough - I decided to create it on my own.

The goal was to keep it as simple as possible but still general enough to work on any data that might be in need to be encrypted. Therefore, Tiny-Enigma works on QIODevices. Literally anything can be used as a QIODevice through QBuffer.
