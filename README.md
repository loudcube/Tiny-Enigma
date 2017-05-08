# Tiny-Enigma
Tiny-Enigma is simple to use and lightweight cryptographic library. It is designed to integrate into the Qt framework. Therefore it is impossible to be used without.<br/>
## Documentation
To use the library one must only create an object of Tiny-Enigma and use its members.
<pre>explicit TinyEnigma(unsigned char *key, unsigned char *iv, QObject *parent = 0);
explicit TinyEnigma(QString &password, QObject *parent = 0);</code></pre>
It is recommended to use the latter constructor as it is a lot safer than the one using raw key and iv. That way it is ensured that the right key and iv lengths are chosen. They can always be returned by members.
<pre>QByteArray key();
QByteArray iv();</code></pre>
For now Tiny-Enigma only supports encryption and decryption of a QIODevice.
<pre>void encryptFile(QIODevice &plain_file, QIODevice &cipher_file);
void decryptFile(QIODevice &cipher_file, QIODevice &plain_file);</code></pre>
However, one can always convert any type into a QByteArray and use QBuffer as a QIODevice for it. That way one can use Tiny-Enigma on any type.
