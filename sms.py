#Finlandiscool1

import os
from twilio.rest import Client
'''
print(os.system("SETX {0} {1} /M".format('TWILIO_ACCOUNT_SID', '')))
print(os.system("SETX {0} {1} /M".format('TWILIO_AUTH_TOKEN', '')))
'''

service_id = 'MG000de850aea5307bc69214ccf110f7e3'
test_num = '4804179666'
account_sid = os.environ['TWILIO_ACCOUNT_SID']
auth_token = os.environ['TWILIO_AUTH_TOKEN']
client = Client(account_sid, auth_token)

def send_msg(to, msg):
    msg = client.messages.create(
        body=msg,
        from_=service_id,
        to=to
    )
    return msg.sid

print(send_msg(test_num, 'testy'))
