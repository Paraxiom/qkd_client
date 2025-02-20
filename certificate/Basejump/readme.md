# Basejump certificates

Here we got the list of certificates in the server where jumpbox is installed `/home/ubuntu/evq/2025-01-14/certs`. 
You have to take both the root ca and the users under each of the respective sites. You should have these certificates :

- evq-root.pem
- USER_001.pem
- USER_001-key.pem
- USER_002.pem
- USER_002-key.pem

When you do so, you then need to decrypt the keys that are password encrypted. The password is `basejump`. You should use `openssl` like so :
- `openssl pkey -in USER_001-key.pem -out decrypted_USER_001-key.pem`
- `openssl pkey -in USER_002-key.pem -out decrypted_USER_002-key.pem`

