import json,time
import requests
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
    # print(request.form.get('vuln_no'))
    if request.form.get('vuln_no'):
        vuln_no = request.form.get('vuln_no')
        # data['vuln_no'] = vuln_no
        # res = requests.post('https://www.oscs1024.com/oscs/v1/vdb/info',  json=data).json()
        res = requests.post('https://www.oscs1024.com/oscs/v1/vdb/vuln_info/'+vuln_no, ).json()
        # rows = res['data']
        rows = []
        count = 0
        if 'title' in res.keys(): 
            count = 1
            rows = [res]
            for i in rows:
                idx = rows.index(i)
                rows[idx]['created_at'] = i['published_time']
                rows[idx]['mps'] = i['mps_id']
    
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
            idx = rows.index(i)
            rows[idx]['created_at'] = i['created_at'].replace('T', ' ').replace('+', ' ')[0:per_page]
    
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