import requests
import uid_gen_pb2
import login_pb2
import major_res_pb2
import player_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
url_grant = "https://100067.connect.garena.com/oauth/guest/token/grant"
headers_guest ={
"User-Agent": "GarenaMSDK/4.0.19P9(RMX5070 ;Android 7.1.1;en;US;)",
"Content-Type": "application/x-www-form-urlencoded",
"Host": "100067.connect.garena.com"
}
guest_uid = "4175678888"
guest_password = "1997_by_falcon_EWF9B41T"
payload ={
"client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
"uid": f"{guest_uid}",
"password": f"{guest_password}",
"response_type": "token",
"client_id": "100067",
"client_type": "2"
}
guest_res = requests.post(url_grant, headers=headers_guest,data=payload)
data = guest_res.json()
access_token = data.get("access_token")
open_id = data.get("open_id")
platform = data.get("platform")
# print(f"access token :",access_token)
# print(f"open id :",open_id)
# print(f"platform :",platform)

# NEXT IS THE MAJOR LOGIN PAYLOAD
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

majorLogin = "https://loginbp.ggblueshark.com/MajorLogin"
major_h = {
"X-Unity-Version": "2018.4.11f1",
"ReleaseVersion": "OB50",
"Content-Type": "application/x-www-form-urlencoded",
"X-GA": "v1 1",
"Authorization": "Bearer ",
"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.1; RMX5070 Build/NMF26F)",
"Host": "loginbp.ggblueshark.com"
}

def build_login(access_token,open_id):
    msg = login_pb2.Login_Data()
    msg.open_ID = open_id
    msg.Access_token = access_token
    msg.platForm23 = "4"
    msg.platForm99 = "4"
    msg.platForm100 = "4"
    data = msg.SerializeToString()
    cifer = AES.new(key,AES.MODE_CBC, iv)
    enc_data = cifer.encrypt(pad(data,AES.block_size))
    return enc_data
# print(f"data to send:",build_login(access_token,open_id).hex())
data_tosend = build_login(access_token,open_id)
major_res = requests.post(majorLogin,headers=major_h,data=data_tosend)
# print(f"major res code",major_res.status_code)
# print(f"major res content",major_res.content.hex())
protobuf_bytes = bytes.fromhex(major_res.content.hex())
my_message = major_res_pb2.Major_response()
my_message.ParseFromString(protobuf_bytes)
print("===========================")
print(my_message.jwt)
print("===========================")
acc_jwt = my_message.jwt

# send the info request  =====
info_url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
info_h ={
    "X-Unity-Version": "2018.4.11f1",
    "ReleaseVersion": "OB50",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-GA": "v1 1",
    "Authorization": f"Bearer {acc_jwt}",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.1; RMX5070 Build/NMF26F)",
    "Host": "clientbp.ggblueshark.com"
}
def build_uid(uid):
    mx = uid_gen_pb2.uid_generate()
    mx.uid = uid
    mx.uidx = 1
    data = mx.SerializeToString()
    cifer = AES.new(key,AES.MODE_CBC, iv)
    enc_data = cifer.encrypt(pad(data,AES.block_size))
    return enc_data
my_uid = 12284377618
uid_info = requests.post(info_url,headers=info_h,data=build_uid(my_uid))

print(uid_info.status_code)
print(uid_info.content.hex())
protobuf_bytes = bytes.fromhex(uid_info.content.hex())
my_messagex = player_pb2.PlayerResponse()
my_messagex.ParseFromString(protobuf_bytes)
print(my_messagex)