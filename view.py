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
        res = requests.post('https://www.oscs1024.com/oscs/v1/intelligence/list',  json=data).json()
        rows = res['data']['data']
        for i in rows:
            if i['public_time'][0:10] == getTimestr(int(time.time())):
            # 如果是今天发布的漏洞
                with open('dingding_notice.log','r') as f:
                    data = json.loads(f.read())
                    print(data)
                if i['title'] not in data:
                    if os.path.exists('ding.json'):
                        access_token = json.loads(open('ding.json','r').read())['access_token']
                        url = 'https://oapi.dingtalk.com/robot/send?access_token='+access_token 
                        resp = requests.post(url, json={'msgtype':'text','text':{'content':'WAF  漏洞情报'+i['title']}}).json()
                        if resp['errcode']== 0:
                            data.append(i['title'])
                            with open('dingding_notice.log','w') as f:
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