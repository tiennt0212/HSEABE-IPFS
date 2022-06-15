import ipfshttpclient

# IPFS0 = '/ipv4/172.22.0.12/tcp/5001'
IPFS0 = '/dns/ipfs.io/tcp/5001/http'
client0 = ipfshttpclient.connect(IPFS0)


print('Add ciphertext to IPFS0')
res = client0.add('/ciphertext.txt')
return_hash = res['Hash']

print('=============================')
print('Get ciphertext from IPFS0')
print('Block {}'.format(return_hash))

client0.block.get(return_hash)