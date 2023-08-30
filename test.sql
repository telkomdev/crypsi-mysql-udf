-- test should return a value of 1, which means the test cases are working as expected --

-- HMAC test --
select 'efbbb1edadec2ad3b5188ba5c2ef8964' = mcrypsi_hmac_md5('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
select '2fe5b3755ddceddb35b8e46b167016346d47dd03' = mcrypsi_hmac_sha1('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
select 'e185bddf7fcc748aca0583897f8bea67bd479410f8049778c69c49523005def2' = mcrypsi_hmac_sha256('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
select '10cc328c64369d0b0667c3a9377bec181c683117b8b215f5badecbedf7c1d6c16347e1a453f6431fede6e9510dc3e99d' = mcrypsi_hmac_sha384('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;
select '825b6b87adf4ab749b769425d583dc42cbae2f44381fbf0182b46cab6c6ddf157ea98f58bc735e532d0591e2a99d903811f94ade78159ec678efebc473d088a8' = mcrypsi_hmac_sha512('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world') as res;

-- AES GCM test --
select 'hello world' = mcrypsi_aes_128_gcm_decrypt('abc$#128djdyAgbj', '56370ee4bf173f70da9506a3d1ab537af77c5f52c81da0a56cae22b65b341612316275bfa80c55') as res;
select 'hello world' = mcrypsi_aes_192_gcm_decrypt('abc$#128djdyAgbjau&YAnmc', '151fd1e55f8d1bbfb57ee10fb47b7a1a7b467cfb96d902e02e0c0c01551acb47a317d8663c9d6a') as res;
select 'hello world' = mcrypsi_aes_256_gcm_decrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', 'dba9faf4afc97b8cfed4408d0ab8cd1bc7274ccd4efe9f4ff177191067f5cb9592375daea2d90e') as res;