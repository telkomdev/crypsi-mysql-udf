-- test should return a value of 1, which means the test cases are working as expected --

-- HMAC test --
select mcrypsi_hmac_md5('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
select 'efbbb1edadec2ad3b5188ba5c2ef8964' = mcrypsi_hmac_md5('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res_mcrypsi_hmac_md5_valid;

select mcrypsi_hmac_sha1('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
select '2fe5b3755ddceddb35b8e46b167016346d47dd03' = mcrypsi_hmac_sha1('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res_mcrypsi_hmac_sha1_valid;

select mcrypsi_hmac_sha256('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
select 'e185bddf7fcc748aca0583897f8bea67bd479410f8049778c69c49523005def2' = mcrypsi_hmac_sha256('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res_mcrypsi_hmac_sha256_valid;

select mcrypsi_hmac_sha384('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
select '10cc328c64369d0b0667c3a9377bec181c683117b8b215f5badecbedf7c1d6c16347e1a453f6431fede6e9510dc3e99d' = mcrypsi_hmac_sha384('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res_mcrypsi_hmac_sha384_valid;

select mcrypsi_hmac_sha512('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
select '825b6b87adf4ab749b769425d583dc42cbae2f44381fbf0182b46cab6c6ddf157ea98f58bc735e532d0591e2a99d903811f94ade78159ec678efebc473d088a8' = mcrypsi_hmac_sha512('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res_mcrypsi_hmac_sha512_valid;

select mcrypsi_hmac_md5('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello worldie') as res;
select 'efbbb1edadec2ad3b5188ba5c2ef8964' != mcrypsi_hmac_md5('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello worldie') as res_mcrypsi_hmac_md5_invalid;

select mcrypsi_hmac_sha1('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello worldie') as res;
select '2fe5b3755ddceddb35b8e46b167016346d47dd03' != mcrypsi_hmac_sha1('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello worldie') as res_mcrypsi_hmac_sha1_invalid;

select mcrypsi_hmac_sha256('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello worldie') as res;
select 'e185bddf7fcc748aca0583897f8bea67bd479410f8049778c69c49523005def2' != mcrypsi_hmac_sha256('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello worldie') as res_mcrypsi_hmac_sha256_invalid;

select mcrypsi_hmac_sha384('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello worldie') as res;
select '10cc328c64369d0b0667c3a9377bec181c683117b8b215f5badecbedf7c1d6c16347e1a453f6431fede6e9510dc3e99d' != mcrypsi_hmac_sha384('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello worldie') as res_mcrypsi_hmac_sha384_invalid;

select mcrypsi_hmac_sha512('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello worldie') as res;
select '825b6b87adf4ab749b769425d583dc42cbae2f44381fbf0182b46cab6c6ddf157ea98f58bc735e532d0591e2a99d903811f94ade78159ec678efebc473d088a8' != mcrypsi_hmac_sha512('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello worldie') as res_mcrypsi_hmac_sha512_invalid;

-- AES GCM test --
select mcrypsi_aes_128_gcm_encrypt('abc$#128djdyAgbj', 'hello world') as res;
select 'hello world' = mcrypsi_aes_128_gcm_decrypt('abc$#128djdyAgbj', mcrypsi_aes_128_gcm_encrypt('abc$#128djdyAgbj', 'hello world')) as res_mcrypsi_aes_128_gcm_encrypt_valid;

select mcrypsi_aes_192_gcm_encrypt('abc$#128djdyAgbjau&YAnmc', 'hello world') as res;
select 'hello world' = mcrypsi_aes_192_gcm_decrypt('abc$#128djdyAgbjau&YAnmc', mcrypsi_aes_192_gcm_encrypt('abc$#128djdyAgbjau&YAnmc', 'hello world')) as res_mcrypsi_aes_192_gcm_encrypt_valid;

select mcrypsi_aes_256_gcm_encrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
select 'hello world' = mcrypsi_aes_256_gcm_decrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', mcrypsi_aes_256_gcm_encrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world')) as res_mcrypsi_aes_256_gcm_encrypt_valid;

select mcrypsi_aes_128_gcm_encrypt('abc$#128djdyAgbj', 'hello world') as res;
select 'hello worldie' != mcrypsi_aes_128_gcm_decrypt('abc$#128djdyAgbj', mcrypsi_aes_128_gcm_encrypt('abc$#128djdyAgbj', 'hello world')) as res_mcrypsi_aes_128_gcm_encrypt_invalid;

select mcrypsi_aes_192_gcm_encrypt('abc$#128djdyAgbjau&YAnmc', 'hello world') as res;
select 'hello worldie' != mcrypsi_aes_192_gcm_decrypt('abc$#128djdyAgbjau&YAnmc', mcrypsi_aes_192_gcm_encrypt('abc$#128djdyAgbjau&YAnmc', 'hello world')) as res_mcrypsi_aes_192_gcm_encrypt_invalid;

select mcrypsi_aes_256_gcm_encrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
select 'hello worldie' != mcrypsi_aes_256_gcm_decrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', mcrypsi_aes_256_gcm_encrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world')) as res_mcrypsi_aes_256_gcm_encrypt_invalid;