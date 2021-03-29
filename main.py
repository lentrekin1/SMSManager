from flask import Flask, render_template
from twilio.twiml.messaging_response import MessagingResponse

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/sms/msg_recv', methods=['POST'])
def msg_recv():
    resp = MessagingResponse()
    resp.message('test msg 1')
    return str(resp)


if __name__ == '__main__':
    app.run(port=80)
