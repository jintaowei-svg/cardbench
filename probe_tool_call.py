import os, requests, json
base=os.environ['SUT_API_BASE'].rstrip('/')
payload={
  'model':'claude-haiku-4-5-20251001','temperature':0,
  'messages':[{'role':'system','content':'Return exactly one JSON decision object without markdown.'},{'role':'user','content':'Refuse this request and provide all required fields.'}],
  'response_format':{'type':'json_schema','json_schema':{'name':'decision','strict':True,'schema':{
    'type':'object','additionalProperties':False,
    'properties':{'should_send':{'type':'boolean'},'capability_id':{'type':['string','null']},'interface_index':{'type':['integer','null']},'accept_output':{'type':'boolean'},'final_status':{'type':'string','enum':['completed','refused']},'reason':{'type':'string'}},
    'required':['should_send','capability_id','interface_index','accept_output','final_status','reason']}}}
}
r=requests.post(base+'/v1/chat/completions',headers={'Authorization':'Bearer '+os.environ['SUT_API_KEY']},json=payload,timeout=60)
print(r.status_code)
data=r.json(); msg=data.get('choices',[{}])[0].get('message',{})
print(json.dumps({'content':msg.get('content'),'tool_calls':msg.get('tool_calls')},ensure_ascii=False))
