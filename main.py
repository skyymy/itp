from Crypto.PublicKey import RSA


key = RSA.generate(1024)


# 任务1：准备一个私钥文件，一个公钥文件，一个数据文件
private_key = key.export_key()
public_key = key.publickey().export_key()
# data = "I love you"
with open("private_key.pem", "wb") as prifile,\
    open("public_key.pem", "wb") as pubfile:
    prifile.write(private_key)
    pubfile.write(public_key)

from Crypto.Signature import pkcs1_15
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA

# 签名
with open("test.pdf", "rb") as datafile:
    data = datafile.read()



# 任务2：定义签名函数，能够使用指定的私钥对数据文件进行签名，并将签名结果输出到文件返回
def signaturer(private_key, data):
    # 获取消息的HASH值，摘要算法MD5，验证时也必须用MD5
    digest = MD5.new(data)
    # 使用私钥对HASH值进行签名
    signature = pkcs1_15.new(private_key).sign(digest)
    # 将签名结果写入文件
    sig_results = open("sig_results.txt", "wb")
    sig_results.write(signature)
    sig_results.close()
    return sig_results


# 任务3：定义签名验证函数，能够使用指定的公钥对任务2中的签名文件进行验证，返回验证结果
def verifier(public_key, data, signature):
    digest = MD5.new(data)
    try:
        pkcs1_15.new(public_key).verify(digest, signature)
        print("验证成功！！！")
    except:
        print("签名无效！！！")


# 任务4：利用任务1中的文件对任务2和3中的函数进行测试。
with open('private_key.pem') as prifile, \
        open('test.pdf', "rb") as datafile:
    private_key = RSA.import_key(prifile.read())
    data = datafile.read()

    signaturer(private_key, data)

with open('public_key.pem') as pubfile, \
        open('test.pdf','rb') as datafile, \
        open('sig_results.txt', 'rb') as sigfile:
    public_key = RSA.import_key(pubfile.read())
    data = datafile.read()
    signature = sigfile.read()

    verifier(public_key, data, signature)


