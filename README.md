# crypsi-mysql-udf

C Crypsi (https://github.com/telkomdev/c-crypsi) MySQL UDF (User Defined Function)

## Motivation/ Why ?
Why not `standard mysql crypto function` https://dev.mysql.com/doc/refman/8.0/en/encryption-functions.html ?. At the time this plugin was created, `standard mysql crypto function` did not support `AES GCM` and `HMAC (hash-based message authentication code)` yet. So this plugin is made to fulfill `AES GCM` and `HMAC (hash-based message authentication code)` encryption needs.

## Dependencies
- https://github.com/telkomdev/c-crypsi
- Openssl 1.1.1

### `crypsi-mysql-udf` is compatible with each other with the following libraries. 
- C/C++ https://github.com/telkomdev/c-crypsi
- Golang https://github.com/telkomdev/go-crypsi
- Python https://github.com/telkomdev/pycrypsi
- C# (.NET) https://github.com/telkomdev/NetCrypsi
- Java/JVM https://github.com/telkomdev/jcrypsi
- NodeJs https://github.com/telkomdev/crypsi
- Javascript (React and Browser) https://github.com/telkomdev/crypsi.js
- PostgreSQL https://github.com/telkomdev/pgcrypsi

Compatible which means you can directly use existing functions to encrypt and decrypt data. For example, the functions in the Crypsi package for NodeJs below are compatible with the functions in `crypsi-mysql-udf`

crypsi-mysql-udf
```sql
mysql> select mcrypsi_aes_128_gcm_encrypt('abc$#128djdyAgbj', 'this is dark') as res;
+----------------------------------------------------------------------------------+
| res                                                                              |
+----------------------------------------------------------------------------------+
| c5cbfb20cbd635fed539adedb588d64b05458aef3898e1be5225dab28ca96607f721601641cd996d |
+----------------------------------------------------------------------------------+
1 row in set (0.01 sec)
```

Decrypt the above encrypted data with the crypsi package for Nodejs
```javascript
const { aesEncryption } = require('crypsi');

const decryptedData = aesEncryption.decryptWithAes128Gcm('abc$#128djdyAgbj', 'c5cbfb20cbd635fed539adedb588d64b05458aef3898e1be5225dab28ca96607f721601641cd996d');
console.log(decryptedData.toString('utf-8')); // result: this is dark
```


## Getting started

### Building

Clone
```shell
$ git clone https://github.com/telkomdev/crypsi-mysql-udf.git
```

Install MySQL Development client
```shell
$ sudo apt-get update
$ sudo apt-get install libmysqlclient-dev
```

Compile extensions, Create and Copy SHARED Library to `/usr/lib/mysql/plugin/`
```shell
$ cc -fPIC -c crypsi_mysqludf.c -I /usr/include/mysql
$ cc -shared -o crypsi_mysqludf.so crypsi_mysqludf.o
$ sudo cp crypsi_mysqludf.so  /usr/lib/mysql/plugin/
```

#### Notes
To find out what `plugin_dir` is referring to, run the following command:
```shell
mysql> show variables like 'plugin_dir';
+---------------+------------------------+
| Variable_name | Value                  |
+---------------+------------------------+
| plugin_dir    | /usr/lib/mysql/plugin/ |
+---------------+------------------------+
1 row in set (0.00 sec)
```

#### Error: Error Code: 1127. Can't find symbol 'xxxx' in library
try to restart MySQL Server
```shell
$ sudo systemctl restart mysql
```

### Install to Database

Login as superuser
```shell
$ sudo mysql
```

Show installed functions
```shell
$ select * from mysql.func;
```

Drop the functions if exists
```sql
DROP FUNCTION mcrypsi_aes_128_gcm_encrypt;
DROP FUNCTION mcrypsi_aes_192_gcm_encrypt;
DROP FUNCTION mcrypsi_aes_256_gcm_encrypt;

DROP FUNCTION mcrypsi_aes_128_gcm_decrypt;
DROP FUNCTION mcrypsi_aes_192_gcm_decrypt;
DROP FUNCTION mcrypsi_aes_256_gcm_decrypt;

DROP FUNCTION mcrypsi_hmac_md5;
DROP FUNCTION mcrypsi_hmac_sha1;
DROP FUNCTION mcrypsi_hmac_sha256;
DROP FUNCTION mcrypsi_hmac_sha384;
DROP FUNCTION mcrypsi_hmac_sha512;
```

Create functions
```sql
CREATE FUNCTION mcrypsi_aes_128_gcm_encrypt RETURNS STRING SONAME 'crypsi_mysqludf.so';
CREATE FUNCTION mcrypsi_aes_192_gcm_encrypt RETURNS STRING SONAME 'crypsi_mysqludf.so';
CREATE FUNCTION mcrypsi_aes_256_gcm_encrypt RETURNS STRING SONAME 'crypsi_mysqludf.so';

CREATE FUNCTION mcrypsi_aes_128_gcm_decrypt RETURNS STRING SONAME 'crypsi_mysqludf.so';
CREATE FUNCTION mcrypsi_aes_192_gcm_decrypt RETURNS STRING SONAME 'crypsi_mysqludf.so';
CREATE FUNCTION mcrypsi_aes_256_gcm_decrypt RETURNS STRING SONAME 'crypsi_mysqludf.so';

CREATE FUNCTION mcrypsi_hmac_md5 RETURNS STRING SONAME 'crypsi_mysqludf.so';
CREATE FUNCTION mcrypsi_hmac_sha1 RETURNS STRING SONAME 'crypsi_mysqludf.so';
CREATE FUNCTION mcrypsi_hmac_sha256 RETURNS STRING SONAME 'crypsi_mysqludf.so';
CREATE FUNCTION mcrypsi_hmac_sha384 RETURNS STRING SONAME 'crypsi_mysqludf.so';
CREATE FUNCTION mcrypsi_hmac_sha512 RETURNS STRING SONAME 'crypsi_mysqludf.so';
```

### AES GCM encrypt function
- mcrypsi_aes_128_gcm_encrypt (AES 128 bit encryption function)
- mcrypsi_aes_192_gcm_encrypt (AES 192 bit encryption function)
- mcrypsi_aes_256_gcm_encrypt (AES 256 bit encryption function)

### AES GCM decrypt function
- mcrypsi_aes_128_gcm_decrypt (AES 128 bit decryption function)
- mcrypsi_aes_192_gcm_decrypt (AES 192 bit decryption function)
- mcrypsi_aes_256_gcm_decrypt (AES 256 bit decryption function)

### Expected key length
- AES 128: key length should be 16 bytes/char
- AES 192: key length should be 24 bytes/char
- AES 256: key length should be 32 bytes/char

### HMAC (hash-based message authentication code)

The length of the HMAC key must be at least 32 characters
- mcrypsi_hmac_md5
- mcrypsi_hmac_sha1
- mcrypsi_hmac_sha256
- mcrypsi_hmac_sha384
- mcrypsi_hmac_sha512

### Run test
```shell
$ sudo mysql
mysql> source /home/vagrant/crypsi-mysql-udf/test.sql
```

### Test the extensions

Encrypt
```shell
mysql> select mcrypsi_aes_128_gcm_encrypt('abc$#128djdyAgbj', 'this is dark') as res;
+----------------------------------------------------------------------------------+
| res                                                                              |
+----------------------------------------------------------------------------------+
| 2d66dcffd5056b67b1cbf276359bd33a3e982047ace8a6c7f6fa1deccee26f1cfd4cc1c8c6d7b15b |
+----------------------------------------------------------------------------------+
1 row in set (0.01 sec)
```

Decrypt
```shell
mysql> select mcrypsi_aes_128_gcm_decrypt('abc$#128djdyAgbj', '2d66dcffd5056b67b1cbf276359bd33a3e982047ace8a6c7f6fa1deccee26f1cfd4cc1c8c6d7b15b') as res;
+--------------+
| res          |
+--------------+
| this is dark |
+--------------+
1 row in set (0.01 sec)
```

HMAC (hash-based message authentication code)
```shell
mysql> select mcrypsi_hmac_sha512('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
+----------------------------------------------------------------------------------------------------------------------------------+
| res                                                                                                                              |
+----------------------------------------------------------------------------------------------------------------------------------+
| 825b6b87adf4ab749b769425d583dc42cbae2f44381fbf0182b46cab6c6ddf157ea98f58bc735e532d0591e2a99d903811f94ade78159ec678efebc473d088a8 |
+----------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.00 sec)
```
