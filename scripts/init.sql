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