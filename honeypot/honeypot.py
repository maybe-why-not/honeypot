#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, make_response, url_for, Markup
import requests, time, json, subprocess, pymongo, sys
from requests.packages import urllib3
urllib3.disable_warnings()
from http.server import BaseHTTPRequestHandler
BaseHTTPRequestHandler.protocol_version = "HTTP/1.1"
    
myclient = pymongo.MongoClient("mongodb://localhost:27017/")

mydb = myclient['honeypot']
if 'honeypot' not in myclient.database_names():
    mycol = mydb["data"]
    mycol.insert_one({"time":"", "ip":"", "url":"", "method":"", "header":"", "data":""})
    mycol.create_index([('ip',1),('data',1)])
    mycol.delete_one({"time":"", "ip":"", "url":"", "method":"", "header":"", "data":""})

    mycol = mydb["times"]
    mycol.insert_one({"ip":"", "time":"", "times":""})
    mycol.create_index("ip")
    mycol.delete_one({"ip":"", "time":"", "times":""})
    
with open('header','r',encoding='utf8')as f:
    header_text = f.readlines()
    response_headers = {}
    for i in header_text:
        response_headers[i.split(': ')[0]] = i.strip().split(': ')[1]

with open('html','r',encoding='utf8')as f:
    html = f.read()

app = Flask(__name__)
@app.route('/', defaults={'path': ''},methods = ['POST','GET','PUT','DELETE','OPTIONS','PATCH','HEAD','TRACE','CONNECT'], strict_slashes=False)
@app.route('/<path:path>',methods = ['POST','GET','PUT','DELETE','OPTIONS','PATCH','HEAD','TRACE','CONNECT'], strict_slashes=False)
def index(path):
    if path == 'f2f40344a167fb5ab51f9f89ba9831a1':#自己填复杂路径防爆破
        data_list = [i for i in mydb['data'].find()]
        data_list = sorted(data_list,key=lambda x: x['time'], reverse=True)
        html_text = '''<!DOCTYPE HTML>
    <html>
    <link rel="shortcut icon" href="https://pic1.zhimg.com/80/v2-f2f40344a167fb5ab51f9f89ba9831a1_im.jpg" type="image/x-icon">
    <title>liulangmao's honeypot</title>
    <body>
    '''
        length = len(data_list)
        for data in data_list:
            request_text = ''
            request_text += data['method'] +' /'+ data['url'].split('/',3)[-1] +'  HTTP/1.1<br>'
            for i in data['header'].keys():
                request_text += i +': '+ data['header'][i] +'<br>'
            request_text = request_text +'<br>'+ json.loads(data['data'])['data'].replace('\r\n','<br>')

            html_text += '''<details>
        <summary>
        <span class="font_bk">'''+str(length)+'''&nbsp;&nbsp;&nbsp;&nbsp;'''+str(time.asctime( time.localtime(data['time']) ))+'''&nbsp;&nbsp;&nbsp;&nbsp;'''+data['ip']+'''&nbsp;&nbsp;&nbsp;&nbsp;'''+data['url']+'''</span>
        </summary><div style='  width: 1500px; height: 200px; overflow: scroll; float: left;'><pre>'''+request_text+'''</pre></div></details>'''
            length -= 1

        resp = make_response(html_text)
        return resp
#####################################################################
    data = {}
    data['time'] = time.time()
    data['ip'] = request.remote_addr
    data['url'] = request.url
    data['method'] = request.method
    data['header'] = {}
    for key, value in request.headers.items():
        data['header'][key] = value
    data['data'] = json.dumps({'data':request.get_data(as_text=True)})
    length = len(json.dumps(data))

    times_list = [i for i in mydb['times'].find({'ip':data['ip']})]
    if times_list:
        times_dict = times_list[0]
        if (data['time'] - times_dict['time']) > 3600:
            mydb["times"].update_one({'ip': data['ip']},{"$set": { "time": data['time'] ,"times":1}})
            if length < 50000:
                mydb["data"].insert_one(data)
            
            resp = make_response(html)
            resp.status = str(200)
            for i in response_headers.keys():
                resp.headers[i] = response_headers[i]
        elif times_dict['times'] >= 10:
            resp = make_response('')
        else:
            mydb["times"].update_one({'ip': data['ip']},{"$set": { "times": times_dict['times']+1}})
            if length < 50000:
                mydb["data"].insert_one(data)
            
            resp = make_response(html)
            resp.status = str(200)
            for i in response_headers.keys():
                resp.headers[i] = response_headers[i]
    else:
        mydb["times"].insert_one({'ip': data['ip'], "time": data['time'] ,"times":1})
        if length < 50000:
            mydb["data"].insert_one(data)

        resp = make_response(html)
        resp.status = str(200)
        for i in response_headers.keys():
            resp.headers[i] = response_headers[i]
            
    return resp

if __name__ == "__main__":
##    app.run(threaded=True)
    app.run(host='0.0.0.0',port= 8080,processes=True)
