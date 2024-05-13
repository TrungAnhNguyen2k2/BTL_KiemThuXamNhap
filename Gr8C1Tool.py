import subprocess
import os
import time
from urllib.parse import urlparse

url = input("Enter the URL to start: ")
# url="http://testphp.vulnweb.com/"
# url="https://owncloud.pollrich.com/"
# url=""
output_dir = urlparse(url).netloc
if not os.path.exists(output_dir):
    os.makedirs(output_dir)
def arjun():
    print('[+]Arjun is running',end='\r')
    with open(output_dir +'/arjun.txt', "w") as f_arjun:
        with open("testphp.vulnweb.com"+'/katana.txt') as f:
            list_urls = f.readlines()
            for url_tmp in list_urls:
                url_tmp = url_tmp.strip()
                command_get = 'arjun -u "{}"'.format(url_tmp)
                reponse = subprocess.run(command_get, shell=True, check=True, capture_output=True, text=True).stdout
                try: 
                    s = ["GET {}".format(url_tmp)] + reponse.split('Parameters found:')[1].strip().replace(',','').split()
                    url_with_param = " ".join(s)
                    f_arjun.write(url_with_param)
                except:
                    pass
                '''-----POST-----'''
                command_post = 'arjun -u "{}" -m POST'.format(url_tmp)
                reponse = subprocess.run(command_post, shell=True, check=True, capture_output=True, text=True).stdout
                try: 
                    s = ["POST {}".format(url_tmp)] + reponse.split('Parameters found:')[1].strip().replace(',','').split()
                    url_with_param = " ".join(s)
                    f_arjun.write(url_with_param)
                except:
                    pass
    print('[v]Arjun is done                                 ')
    
def sqlmap():
    print('[+]Sqlmap is running',end='\r')
    with open(output_dir+'/arjun.txt', "r") as f:
        for line in f.readlines():
            line = line.split()
            param = '&'.join(x+'=' for x in line[2:])
            param_in_query=','.join(line[2:])
            if line[0] =='GET':
                cmd = 'sqlmap -u "{}?{}" -p "{}" -b -o --smart --batch --disable-coloring --random-agent --output-dir=tmp 2>>/dev/null && cat tmp/*/log >> {}/sql.txt && rm -rf tmp '.format(line[1],param,param_in_query,output_dir)
            if line[0] =='POST':
                cmd = 'sqlmap -u "{}" --data="{}" -p "{}" -b -o --smart --batch --disable-coloring --random-agent --output-dir=tmp 2>>/dev/null && cat tmp/*/log >> {}/sql.txt && rm -rf tmp'.format(line[1],param,param_in_query,output_dir)
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                pass
    print('[v]Sqlmap is done                 ')
def katana():
    print('[+]Crawling part via katana and unfurl',end='\r')
    cmd = "katana -u '{}' -aff -fx|unfurl --unique format %s://%d%p |grep -vE '\\.css$|\\.html$|\\.js' > {}/katana.txt ".format(url,output_dir)
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
    except:
        pass
    print('[v]Crawling is done                              ')
def nuclei():
    print('[+]Nuclei is running',end='\r')
    if not os.path.exists(output_dir+'/nuclei'):
        os.makedirs(output_dir+'/nuclei')
    severity=['low','medium','high','critical']
    for x in severity:
        cmd = 'nuclei -u {} -s {} --silent -retries 3 -o {}/nuclei/{} 2>>/dev/null'.format(url,x,output_dir,x)
        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            pass
    print('[v]Nuclei is done                                 ')
    
def acunetix():
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.session()
    burp0_url = "https://b20at009-anh-kali:3443/api/v1/me/login"
    burp0_json={"email": "chuyendihoibai@gmail.com", "password": "606c8d69f8fd526591fa8ba2e6e7af35c0d3009650430fd5a1eaf37a6ac9dabd", "remember_me": False}
    x_authen = session.post(burp0_url, json=burp0_json,verify=False).headers.get('X-Auth')
    r = session.get('https://b20at009-anh-kali:3443/api/v1/me',headers={'X-Auth': '{}'.format(x_authen)},verify=False)
    burp0_url = "https://b20at009-anh-kali:3443/api/v1/targets/add"
    burp0_json={"groups": [], "targets": [{"address": url, "description": ""}]}
    r = session.post(burp0_url, headers={'X-Auth': '{}'.format(x_authen)}, json=burp0_json).json()['targets'][0]['target_id']
    burp0_url = "https://b20at009-anh-kali:3443/api/v1/scans"
    burp0_json={"incremental": False, "profile_id": "11111111-1111-1111-1111-111111111111", "schedule": {"disable": False, "start_date": None, "time_sensitive": False}, "target_id": r}
    response = session.post(burp0_url, headers={'X-Auth': '{}'.format(x_authen)}, json=burp0_json)
    if response.status_code == 201:
        ScanID= response.headers.get("Location").split("/")[-1]
    else:
        print("Failed to create scan. HTTP Status Code:", session.status_code)
        exit(1)    
    while True:
        scan_target = "https://b20at009-anh-kali:3443/api/v1/scans/" + ScanID
        scan_status = session.get(scan_target, headers={"Accept": "application/json","X-Auth": '{}'.format(x_authen)},verify=False)
        if scan_status.status_code == 200:
            MyScanStatus = scan_status.json()["current_session"]["status"]

            if MyScanStatus == "processing":
                print("[+]Acunetix is scanning. Please wait!", end ="\r")
            elif MyScanStatus == "scheduled":
                print("Scan Status: Scheduled - please waiting")
            elif MyScanStatus == "completed":
                print("[v]Acunetix is done!                    ")
                file_name = output_dir+'/acunetix.txt'
                with open (file_name,"w") as f:
                    f.write("Please login and access to this link below to see the full report:\n")
                    f.write("https://b20at009-anh-kali:3443/#/scans/"+ScanID+"/info")
                break
            else:
                print("Invalid Scan Status: Aborting")
                exit(1)
            
        else:
            print("Failed to fetch scan status. HTTP Status Code:", scan_status.status_code)
            exit(1)
        time.sleep(30)
if __name__=="__main__":
    katana()
    nuclei()
    arjun()
    sqlmap()
    acunetix()
    print(f"Your scanning is all completed! The result info will be save in folder: {output_dir}")
