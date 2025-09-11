import json,time
import requests,os
import urllib3
from flask import request, Blueprint, render_template

urllib3.disable_warnings()

path = Blueprint('path', __name__)


@path.route('/', methods=['GET', "POST"])
@path.route('/index', methods=['GET', "POST"])
def index():
    return render_template("index.html")


@path.route('/post_form', methods=['POST', ])
def post_form():
    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'zh-CN,zh;q=0.9',
        'content-type': 'application/json',
        'origin': 'https://www.oscs1024.com',
        'priority': 'u=1, i',
        'referer': 'https://www.oscs1024.com/cm',
        'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
        # 'cookie': 'Hm_lvt_113185c61c5bffebb22e97ff5c955cc5=1757425706; HMACCOUNT=4E07F83E7A48FD1B; Hm_lpvt_113185c61c5bffebb22e97ff5c955cc5=1757593242',
    }
    per_page = int(request.form.get('per_page',10))
    data = {
        'page': int(request.form.get('page', 1)),
        'per_page':per_page,
    }
    vuln_no = ''
    if request.form.get('vuln_no'):
        vuln_no = request.form.get('vuln_no')
        try:
            res = requests.get('https://www.oscs1024.com/oscs/v1/vdb/vuln_info/'+vuln_no ).json()
            rows = []
            count = 0
            if 'title' in res.keys(): 
                count = 1
                rows = [res]
                for i in rows:
                    idx = rows.index(i)
                    rows[idx]['created_at'] = i['published_time']
                    rows[idx]['mps'] = i['mps_id']

        except Exception as e:
            rows = []
            count = 0
    
        respos = {
            "status": 0,
            "data": {
                'rows': rows,
                "count": count
            },
            'msg': ''
        }
    else:
        try:
            res = requests.post('https://www.oscs1024.com/oscs/v1/intelligence/list', headers=headers, json=data).json()
            rows = res['data']['data']
            for i in rows:
                # if i['public_time'][0:10] == getTimestr(int(time.time())):
                if i['public_time'][0:10] =='2025-09-04': 
                # 如果是今天发布的漏洞
                    with open('dingding_notice.log','r') as f:
                        data = json.loads(f.read())
                        # print(data)
                    if i['title'] not in data:
                        if os.path.exists('ding.json'):
                            access_token = json.loads(open('ding.json','r').read())['access_token']
                            url = 'https://oapi.dingtalk.com/robot/send?access_token='+access_token 
                            resp = requests.post(url, json={'msgtype':'text','text':{'content':'WAF  漏洞情报'+i['title']}}).json()
                            if resp['errcode']== 0:
                                data.append(i['title'])
                                with open('dingding_notice.log','w') as f:
                                    f.write(json.dumps(data,ensure_ascii=False))

                    with open('feishu_notice.log','r') as f:
                        data = json.loads(f.read())
                        # print(data)
                    if i['title'] not in data:
                        if os.path.exists('feishu.json'):
                            access_token = json.loads(open('feishu.json','r').read())['access_token']
                            url = 'https://open.feishu.cn/open-apis/bot/v2/hook/'+access_token 
                            resp = requests.post(url, json={'msgtype':'text','text':{'content':'WAF  漏洞情报'+i['title']}}).json()
                            if resp['StatusCode']== 0:
                                data.append(i['title'])
                                with open('feishu_notice.log','w') as f:
                                    f.write(json.dumps(data,ensure_ascii=False)) 

                idx = rows.index(i)
                rows[idx]['publish_time'] = i['public_time'][0:10]
        
            respos = {
                "status": 0,
                "data": {
                    'rows': rows,
                    "count": res['data']['total']
                },
                'msg': ''
            }
        except Exception as e:
            respos = {
                "status": 0,
                "data": {
                    'rows': [],
                    "count": 0
                },
                'msg': str(e)
            }
    return json.dumps(respos)

@path.route('/detail', methods=['GET' ])
def detail():
    mps = request.args.get('id')
  
    json_data = {
        'vuln_no': mps,
    }

    res = requests.post('https://www.oscs1024.com/oscs/v1/vdb/info',  json=json_data).json()

    rows = res['data'][0]

    effect = ''
    url = ''
    for i in rows['references']:
        url += i['url']+"\r\n<br/>" 
    rows['url'] =url
    for i in rows['effect']:
        effect += i['name']+'@'+str(i['affected_version'])+"\r\n<br/>"
    rows['effect'] = effect
    
    if 'CVE' in rows['cve_id'] :
        rows['cve_id'] = '<a href="%s">%s</a>'%('https://nvd.nist.gov/vuln/detail/'+rows['cve_id'],'https://nvd.nist.gov/vuln/detail/'+rows['cve_id'])


    respos = {
        "status": 0,
        "data":rows,
        'msg': ''
    }
    return json.dumps(respos)

def getTimestr(timeint):
    timeArray = time.localtime(timeint)
    return  time.strftime("%Y-%m-%d", timeArray)

@path.route('/validDing', methods=['GET' ,'POST'])
def validDing():
    access_token = request.form.get('access_token')
    if access_token:
        url = 'https://oapi.dingtalk.com/robot/send?access_token='+access_token
        res = requests.post(url, json={'msgtype':'text','text':{'content':"WAF test ok"}}).json()
        if res['errcode']== 0:
            with open('ding.json','w') as f:
                f.write(json.dumps({"access_token":access_token}))
            return json.dumps({'status':0,'msg':'测试成功'})
        else:
            return json.dumps({'status':1,'msg':'测试失败'})
        
@path.route('/getDing', methods=['GET' ,'POST'])
def getDing():
    if os.path.exists('ding.json'):
        with open('ding.json','r') as f:
            return json.dumps({"access_token":json.loads(f.read())['access_token']})
    return json.dumps({"access_token":''})

@path.route('/validFeishu', methods=['GET' ,'POST'])
def validFeishu():
    access_token = request.form.get('access_token')
    if access_token:
        url = 'https://open.feishu.cn/open-apis/bot/v2/hook/'+access_token
        res = requests.post(url, json={'msg_type':'text','content':{'text':"WAF test ok"}}).json()
        print(res)
        if res['StatusCode']== 0:
            with open('feishu.json','w') as f:
                f.write(json.dumps({"access_token":access_token}))
            return json.dumps({'status':0,'msg':'测试成功'})
        else:
            return json.dumps({'status':1,'msg':'测试失败'})
        
@path.route('/getFeishu', methods=['GET' ,'POST'])
def getFeishu():
    if os.path.exists('feishu.json'):
        with open('feishu.json','r') as f:
            return json.dumps({"access_token":json.loads(f.read())['access_token']})
    return json.dumps({"access_token":''})