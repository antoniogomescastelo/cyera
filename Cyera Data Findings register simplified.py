
import glob
import json
import logging
import os
import requests
import shutil
import time

from requests.auth import HTTPBasicAuth

import pandas as pd
import altair as alt
import ipywidgets as widgets

from snowflake.snowpark import Session

from services import ImportService
from harvester import HarvesterService

import threading

import streamlit as st

from streamlit.runtime.scriptrunner import add_script_run_ctx, get_script_run_ctx



def x(l, k, v): l[k] = v

def get_config():
    logging.getLogger().debug("get config")

    with open('config.json', "r") as f:
        config = json.load(f)

    return config




def get_collibra(config):
    logging.getLogger().debug("get collibra")

    collibra = {}

    collibra["host"] = f"https://{config['collibra_host']}"

    collibra["username"] = config['collibra_username']

    collibra["password"] = config['collibra_password']

    collibra["endpoint"] = f"{collibra['host']}{config['collibra_api_endpoint']}"

    collibra["session"] = requests.Session()

    collibra.get("session").auth = HTTPBasicAuth(collibra.get("username"), collibra.get("password"))

    return collibra



def get_token(config):
    logging.getLogger().debug("get token")

    response = requests.post(
        f"{config['cyera_api_endpoint_url']}/v1/login",
        headers = {'accept': 'application/json', 'Content-Type': 'application/json'},
        json = {'clientId': config['cyera_client_id'], 'secret': config['cyera_client_secret']}
    )

    if response.status_code != requests.codes.ok:
        raise Exception(f'Error: {response.text}') 

    if not response.json().get('jwt'):
        raise Exception(f'Error: {response.json().get("message")}')

    config['cyera_token'] = response.json().get('jwt')

    return config



def send_request(method, url, data, limit, config):
    logging.getLogger().debug("send request")

    offset = 0
    
    results = []

    while True:
        response = requests.request(
            method=method,
            url=f"{url}&offset={offset}&limit={limit}",
            headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': f"Bearer {config['cyera_token']}"},
            data = data
        )

        if response.status_code != requests.codes.ok: raise Exception(f'Error: {response.text}') 

        if not response.json()['results']: break

        results = results + response.json()['results']

        offset+=limit

    return results



def get_classifications(config):
    logging.getLogger().debug("get classifications")

    url = f"{config['cyera_api_endpoint_url']}/v1/classifications?"

    results = send_request('GET', url, None, 10, config)

    return results



def get_datastores(provider, platform, config):
    logging.getLogger().debug("get datastores")

    url = f"{config['cyera_api_endpoint_url']}/v2/datastores?provider={provider}&inPlatformIdentifier={platform}"

    results = send_request('GET', url, None, 10, config)

    return results



def get_datastore_classifications(datastore, config):
    logging.getLogger().debug("get datastore classifications")

    url = f"{config['cyera_api_endpoint_url']}/v1/datastores/{datastore}/classifications?"

    results = send_request('GET', url, None, 10, config)

    _= [r.update({'datastoreUid':datastore}) for r in results]
    
    return results



def get_datastores_classifications(datastores_df, config):
    logging.getLogger().debug("get datastores classifications")

    results = []

    datastores_df['uid'].apply(lambda x: results.append(get_datastore_classifications(x, config)))

    return results


def get_datastore_objects(datastore, config):
    logging.getLogger().debug("get datastore objects")

    url = f"{config['cyera_api_endpoint_url']}/v1/datastores/{datastore}/objects?"
    
    results = send_request('GET', url, None, 10, config)

    _= [r.update({'datastoreUid':datastore}) for r in results]
    
    return results



def get_datastores_objects(datastores_df, config):
    logging.getLogger().debug("get datastores objects")

    results = []

    datastores_df['uid'].apply(lambda x: results.append(get_datastore_objects(x, config)))

    return results


@st.cache_resource
def get_data_findings(config):
    logging.getLogger().debug("get all findings")

    session = Session.builder.config("connection_name", "cyera").create()

    # classifications_df = pd.DataFrame(get_classifications(config))

    # session.write_pandas(classifications_df, "CLASSIFICATIONS", auto_create_table=True, overwrite=True)

    classifications_df = session.table("CLASSIFICATIONS").to_pandas()

    # datastores_df = pd.DataFrame(get_datastores('AWS', '482457381153', config))

    # session.write_pandas(datastores_df, "DATASTORES", auto_create_table=True, overwrite=True)

    datastores_df = session.table("DATASTORES").to_pandas()

    datastores_df['createdYYMM'] = datastores_df['createdDate'].str[0:7]

    try:
        datastores_df['regions'] = datastores_df['regions'].apply(lambda x: json.loads(x))

        datastores_df['classificationGroups'] = datastores_df['classificationGroups'].apply(lambda x: json.loads(x))
        
    except Exception as e:
        pass

    datastores_df = datastores_df.explode('regions', ignore_index=True) # only 1 region

    datastores_exploded_df = datastores_df.explode('classificationGroups', ignore_index=True)

    # datastores_classifications_df = pd.DataFrame([vv for k,v in enumerate(get_datastores_classifications(datastores_df, config)) for kk,vv in enumerate(v)])

    # session.write_pandas(datastores_classifications_df, "DATASTORES_CLASSIFICATIONS", auto_create_table=True, overwrite=True)

    datastores_classifications_df = session.table("DATASTORES_CLASSIFICATIONS").to_pandas()

    datastores_classifications_df = datastores_classifications_df.join(datastores_df.set_index('uid'), on='datastoreUid', rsuffix='_d')
    
    # datastores_classifications_df = datastores_df.join(datastores_classifications_df.set_index('datastoreUid'), on='uid', lsuffix='_d')

    # datastores_objects_df = pd.DataFrame([vv for k,v in enumerate(get_datastores_objects(datastores_df.query('scanningState=="Scanned"'), config)) for kk,vv in enumerate(v)])

    # session.write_pandas(datastores_objects_df, "DATASTORES_OBJECTS", auto_create_table=True, overwrite=True)

    datastores_objects_df = session.table("DATASTORES_OBJECTS").to_pandas()

    datastores_objects_df = datastores_objects_df.join(datastores_df.set_index('uid'), on='datastoreUid', rsuffix='_d')

    return classifications_df, datastores_df, datastores_exploded_df, datastores_classifications_df, datastores_objects_df, session


def do_classifications(x, entries, importService, config):
    # data category
    if x['classificationGroup'] not in entries[0]:
        entries[0][x['classificationGroup']] = {
            "entry": importService.get_asset("Privacy and Risk community", "Data categories", "Data Category", x['classificationGroup'], x['classificationGroup'])
        }

    # data concept
    if x['name'] not in entries[1]:
        entries[1][x['name']] = {
            "entry": importService.get_asset("Data Architects community", "Business Data Models", "Data Concept", x['name'], x['name']),
            "relations": [],
            "attributes": []
        }

    if x['classificationGroup'] not in entries[1][x['name']]['relations']:
        entries[1][x['name']]['relations'].append(x['classificationGroup'])
        importService.add_relations(entries[1][x['name']]['entry'], "c0e00000-0000-0000-0000-000000007316", "SOURCE", "Data categories", "Privacy and Risk community", x['classificationGroup'])

    if x['sensitivity'] not in entries[1][x['name']]['attributes']:
        entries[1][x['name']]['attributes'].append(x['sensitivity'])
        importService.add_attributes(entries[1][x['name']]['entry'], 'Severity', x['sensitivityDisplayName'], 'string')


def do_datastores(x, entries, importService, config):
    account = json.loads(x['account'])['inPlatformIdentifier']

    # domain
    if account not in entries[2]:
        entries[2][account] = {
            "entry": importService.get_domain(config['community_to_query'], "Technology Asset Domain", account),
        }

    # system
    if account not in entries[3]:
        entries[3][account] = {
            "entry": importService.get_asset(config['community_to_query'], account, "System", account, account),
            "attributes": []
        }

    if x['provider'] not in entries[3][account]['attributes']:
        entries[3][account]['attributes'].append(x['provider'])
        importService.add_attributes(entries[3][account]['entry'], 'Platform', x['provider'], 'string')

    if account not in entries[3][account]['attributes']:
        entries[3][account]['attributes'].append(account)
        importService.add_attributes(entries[3][account]['entry'], 'Account Name', account, 'string')

    # if buckets
    if x['type'] == 'S3':        
        # storage container
        if x['name'] not in entries[6]:
            entries[6][x['name']] = {
                "entry": importService.get_asset(config['community_to_query'], account, "S3 Bucket", f"s3://{x['name']}/", f"s3://{x['name']}/"),
                "relations": [],
                "attributes": []
            }

        if x['name'] not in entries[6][x['name']]['relations']:
            entries[6][x['name']]['relations'].append(x['name'])
            importService.add_relations(entries[6][x['name']]['entry'], "00000000-0000-0000-0000-000000007054", "SOURCE", account, config['community_to_query'], account)

        if x['provider'] not in entries[6][x['name']]['attributes']:
            entries[6][x['name']]['attributes'].append(x['provider'])
            importService.add_attributes(entries[6][x['name']]['entry'], 'Platform', x['provider'], 'string')

        if account not in entries[6][x['name']]['attributes']:
            entries[6][x['name']]['attributes'].append(account)
            importService.add_attributes(entries[6][x['name']]['entry'], 'Account Name', account, 'string')

        if x['regions'] not in entries[6][x['name']]['attributes']:
            entries[6][x['name']]['attributes'].append(x['regions'])
            importService.add_attributes(entries[6][x['name']]['entry'], 'Region', x['regions'], 'string')

        if x['createdDate'] not in entries[6][x['name']]['attributes']:
            entries[6][x['name']]['attributes'].append(x['createdDate'])
            importService.add_attributes(entries[6][x['name']]['entry'], 'Created At', x['createdDate'], 'string')
         
    # if database
    if x['type'] in ('DYNAMO_DB', 'REDSHIFT', 'RDS'):

        if x['name'] not in entries[7]: 
            entries[7][x['name']] = {
                "entry": importService.get_asset(config['community_to_query'], account, "System", x['name'], x['name']), 
                "relations": [],
                "attributes": []
            }

        if account not in entries[7][x['name']]['relations']:
            entries[7][x['name']]['relations'].append(account)
            importService.add_relations(entries[7][x['name']]['entry'], "00000000-0000-0000-0000-000000007054", "SOURCE",  account, config['community_to_query'], account)


        if x['provider'] not in entries[7][x['name']]['attributes']:
            entries[7][x['name']]['attributes'].append(x['provider'])
            importService.add_attributes(entries[7][x['name']]['entry'], 'Platform', x['provider'], 'string')

        if account not in entries[7][x['name']]['attributes']:
            entries[7][x['name']]['attributes'].append(account)
            importService.add_attributes(entries[7][x['name']]['entry'], 'Account Name', account, 'string')

        if x['regions'] not in entries[7][x['name']]['attributes']:
            entries[7][x['name']]['attributes'].append(x['regions'])
            importService.add_attributes(entries[7][x['name']]['entry'], 'Region', x['regions'], 'string')

        if x['createdDate'] not in entries[7][x['name']]['attributes']:
            entries[7][x['name']]['attributes'].append(x['createdDate'])
            importService.add_attributes(entries[7][x['name']]['entry'], 'Created At', x['createdDate'], 'string')

        if x['arn'] not in entries[7][x['name']]['attributes']:
            entries[7][x['name']]['attributes'].append(x['arn'])
            importService.add_attributes(entries[7][x['name']]['entry'], 'Principal Identifier', x['arn'], 'string')


def do_datastores_classifications(x, entries, importService, config):
    account = json.loads(x['account'])['inPlatformIdentifier']

    # if buckets
    if x['type'] == 'S3':        
        # storage container
        if x['name_d'] not in entries[6]:
            entries[6][x['name_d']] = {
                "entry": importService.get_asset(config['community_to_query'], account, "S3 Bucket", f"s3://{x['name_d']}/", f"s3://{x['name_d']}/"),
                "relations": [],
                "attributes": []
            }

        if x['classificationGroup'] not in entries[6][x['name_d']]['relations']:
            entries[6][x['name_d']]['relations'].append(x['classificationGroup'])
            importService.add_relations(entries[6][x['name_d']]['entry'], "01930192-86fb-77b0-8baf-30a80dccb864", "TARGET", "Data categories", "Privacy and Risk community", x['classificationGroup'])

        if x['name'] not in entries[6][x['name_d']]['relations']:
            entries[6][x['name_d']]['relations'].append(x['name'])
            importService.add_relations(entries[6][x['name_d']]['entry'], "01930192-f332-70fc-8572-9f7283c4cfd4", "TARGET",  "Business Data Models", "Data Architects community", x['name'])

        # measure         
        entries[8][f"{x['name_d']}:{x['name']}:Total Matches"] = {
            "entry": importService.get_asset("Governance council", "New Data Findings Metrics", "Measure", f"{x['name_d']}:{x['name']}:Total Matches", f"{x['name']} Total Matches")
        }

        importService.add_attributes(entries[8][f"{x['name_d']}:{x['name']}:Total Matches"]['entry'], 'Count', x['recordCountInDatastore'], 'string')

        importService.add_relations(entries[8][f"{x['name_d']}:{x['name']}:Total Matches"]['entry'], "01930b23-1a84-7d44-b817-275206442bf6", "TARGET",  "Business Data Models", "Data Architects community",  x['name'])
        
        importService.add_relations(entries[8][f"{x['name_d']}:{x['name']}:Total Matches"]['entry'], "01930b24-2617-722b-9502-8c30d4b3818c", "SOURCE",  account, config['community_to_query'], f"s3://{x['name_d']}/")

        # dimension
        if x['name'] not in entries[9]:
            entries[9][x['name']] = {
                "entry": importService.get_asset("Governance council", "Data Findings Dimensions", "Data Findings Dimension", x['name'], x['name'])
            }

        entries[10][f"s3://{x['name_d']}/:{x['name']}:Total Matches:Rule"] = {
            "entry": importService.get_asset("Governance council", "Data Findings Rules", "Data Findings Rule", f"s3://{x['name_d']}/:{x['name']}:Total Matches", f"{x['name']} Total Matches")
        }

        importService.add_relations(entries[10][f"s3://{x['name_d']}/:{x['name']}:Total Matches:Rule"]['entry'], "00000000-0000-0000-0000-000000007018", "SOURCE",  account, config['community_to_query'], f"s3://{x['name_d']}/")
        
        # metric
        entries[10][f"s3://{x['name_d']}/:{x['name']}:Total Matches:Metric"] = {
            "entry": importService.get_asset("Governance council", "Data Findings Metrics", "Data Findings Metric", f"s3://{x['name_d']}/:{x['name']}:Total Matches", f"{x['name']} Total Matches")
        }

        importService.add_attributes(entries[10][f"s3://{x['name_d']}/:{x['name']}:Total Matches:Metric"]['entry'], 'Passing Fraction', x['recordCountInDatastore'], 'string')

        importService.add_relations(entries[10][f"s3://{x['name_d']}/:{x['name']}:Total Matches:Metric"]['entry'], "01931f87-3dca-7b65-a03c-dce0146ade76", "TARGET",  "Data Findings Dimensions", "Governance council", x['name'])

        importService.add_relations(entries[10][f"s3://{x['name_d']}/:{x['name']}:Total Matches:Metric"]['entry'], "01931feb-4b9a-7b6b-a456-e1a2759ceca4", "SOURCE",  "Data Findings Rules", "Governance council", f"s3://{x['name_d']}/:{x['name']}:Total Matches")


    # if database
    if x['type'] in ('DYNAMO_DB', 'REDSHIFT', 'RDS'):
        if x['name_d'] not in entries[7]: 
            entries[7][x['name_d']] = {
                "entry": importService.get_asset(config['community_to_query'], account, "System", x['name_d'], x['name_d']), 
                "relations": [],
                "attributes": []
            }

        if x['classificationGroup'] not in entries[7][x['name_d']]['relations']:
            entries[7][x['name_d']]['relations'].append(x['classificationGroup'])
            importService.add_relations(entries[7][x['name_d']]['entry'], "019465e7-438a-7115-8158-68545ff8d12d", "TARGET", "Data categories", "Privacy and Risk community", x['classificationGroup']) 

        if x['name'] not in entries[7][x['name_d']]['relations']:
            entries[7][x['name_d']]['relations'].append(x['name'])
            importService.add_relations(entries[7][x['name_d']]['entry'], "019465e8-5d94-76a6-a34b-68a3f8d7c74c", "TARGET",  "Business Data Models", "Data Architects community", x['name']) 

        # measure
        entries[8][f"{x['name_d']}:{x['name']}:Total Matches"] = {
            "entry": importService.get_asset("Governance council", "New Data Findings Metrics", "Measure", f"{x['name_d']}:{x['name']}:Total Matches", f"{x['name']} Total Matches")
        }

        importService.add_attributes(entries[8][f"{x['name_d']}:{x['name']}:Total Matches"]['entry'], 'Count', x['recordCountInDatastore'], 'string')

        importService.add_relations(entries[8][f"{x['name_d']}:{x['name']}:Total Matches"]['entry'], "01930b23-1a84-7d44-b817-275206442bf6", "TARGET",  "Business Data Models", "Data Architects community",  x['name'])
        
        importService.add_relations(entries[8][f"{x['name_d']}:{x['name']}:Total Matches"]['entry'], "019465e9-0c5a-7293-863b-adad740124cc", "SOURCE",  account, config['community_to_query'], x['name_d'])

        # dimension
        if x['name'] not in entries[9]:
            entries[9][x['name']] = {
                "entry": importService.get_asset("Governance council", "Data Findings Dimensions", "Data Findings Dimension", x['name'], x['name'])
            }

        # metric    
        entries[10][f"{x['name_d']}:{x['name']}:Total Matches:Rule"] = {
            "entry": importService.get_asset("Governance council", "Data Findings Rules", "Data Findings Rule", f"{x['name_d']}:{x['name']}:Total Matches", f"{x['name']} Total Matches")
        }

        importService.add_relations(entries[10][f"{x['name_d']}:{x['name']}:Total Matches:Rule"]['entry'], "00000000-0000-0000-0000-000000007018", "SOURCE",  account, config['community_to_query'], f"{x['name_d']}")

        entries[10][f"{x['name_d']}:{x['name']}:Total Matches:Metric"] = {
            "entry": importService.get_asset("Governance council", "Data Findings Metrics", "Data Findings Metric", f"{x['name_d']}:{x['name']}:Total Matches", f"{x['name']} Total Matches")
        }

        importService.add_attributes(entries[10][f"{x['name_d']}:{x['name']}:Total Matches:Metric"]['entry'], 'Passing Fraction', x['recordCountInDatastore'], 'string')

        importService.add_relations(entries[10][f"{x['name_d']}:{x['name']}:Total Matches:Metric"]['entry'], "01931f87-3dca-7b65-a03c-dce0146ade76", "TARGET",  "Data Findings Dimensions", "Governance council", x['name'])

        importService.add_relations(entries[10][f"{x['name_d']}:{x['name']}:Total Matches:Metric"]['entry'], "01931feb-4b9a-7b6b-a456-e1a2759ceca4", "SOURCE",  "Data Findings Rules", "Governance council", f"{x['name_d']}:{x['name']}:Total Matches")



def do_datastores_objects(x, entries, importService, config):
    account = json.loads(x['account'])['inPlatformIdentifier']

    # if bucket
    if x['type'] == 'S3':        

        file = f"s3://{x['name_d']}/{x['relativePath']}"

        entries[11][file] = {
            "entry": importService.get_asset(config['community_to_query'], account, "File", file, x['relativePath']),
            "relations": []
        }

        importService.add_relations(entries[11][file]['entry'], "00000000-0000-0000-0000-000000007060", "SOURCE", account, config['community_to_query'], f"s3://{x['name_d']}/")

        # TODO: get classifications
        # importService.add_relations(entries[11][file]['entry'], "01943678-0ab4-7015-ba1f-0f9a168a6ade", "TARGET", "Data categories", "Privacy and Risk community", x['Category'])

        # importService.add_relations(entries[11][file]['entry'], "01943678-ebf1-7cd5-bc9c-c78b2d115f3c", "TARGET",  "Business Data Models", "Data Architects community", x['Classifier'])

    # if database
    if x['type'] in ('DYNAMO_DB', 'REDSHIFT', 'RDS'):
        #database
        database = x['dbName']
        if f"{x['name_d']}>{database}" not in entries[12]:
            entries[12][f"{x['name_d']}>{database}"] = {
                "entry": importService.get_asset(config['community_to_query'], account, "Database", f"{x['name_d']}>{database}", database),
                "relations": []
            }

        if x['name_d'] not in entries[12][f"{x['name_d']}>{database}"]['relations']:
            entries[12][f"{x['name_d']}>{database}"]['relations'].append(x['name_d'])
            importService.add_relations(entries[12][f"{x['name_d']}>{database}"]['entry'], "00000000-0000-0000-0000-000000007054", "SOURCE", account, config['community_to_query'], x['name_d'])

        # schema
        # TODO: get schema name
        schema = 'pending'
        if f"{x['name_d']}>{database}>{schema}" not in entries[13]:
            entries[13][f"{x['name_d']}>{database}>{schema}"] = {
                "entry": importService.get_asset(config['community_to_query'], account, "Schema", f"{x['name_d']}>{database}>{schema}", schema),
                "relations": [],
                "attributes": []
            }

        if  f"{x['name_d']}>{database}" not in entries[13][f"{x['name_d']}>{database}>{schema}"]['relations']:
            entries[13][f"{x['name_d']}>{database}>{schema}"]['relations'].append(f"{x['name_d']}>{database}")
            importService.add_relations(entries[13][f"{x['name_d']}>{database}>{schema}"]['entry'], "00000000-0000-0000-0000-000000007024", "SOURCE", account, config['community_to_query'], f"{x['name_d']}>{database}")

        # table
        table = x['name']
        if f"{x['name_d']}>{database}>{schema}>{table}" not in entries[14]:
            entries[14][f"{x['name_d']}>{database}>{schema}>{table}"] = {
                "entry": importService.get_asset(config['community_to_query'], account, "Table", f"{x['name_d']}>{database}>{schema}>{table}", table),
                "relations": [],
                "attributes": []
            }

        if  f"{x['name_d']}>{database}>{schema}" not in entries[14][f"{x['name_d']}>{database}>{schema}>{table}"]['relations']:
            entries[14][f"{x['name_d']}>{database}>{schema}>{table}"]['relations'].append(f"{x['name_d']}>{database}>{schema}")
            importService.add_relations(entries[14][f"{x['name_d']}>{database}>{schema}>{table}"]['entry'], "00000000-0000-0000-0000-000000007043", "SOURCE", account, config['community_to_query'], f"{x['name_d']}>{database}>{schema}")

        # TODO: get classifications

            


def do_all_findings(classifications_df, datastores_df, datastores_exploded_df, datastores_classifications_df, datastores_objects_df, session, config):
    logging.getLogger().debug("do all findings")

    runId = time.strftime("%Y%m%d")

    shutil.rmtree(f'./runs/{runId}', ignore_errors=True)

    _= [os.remove(f) for f in glob.glob(f'./runs/{runId}.json.*')]
    
    ctx = get_script_run_ctx()

    t = threading.Thread(target=show_progress, args=[runId], daemon=True)

    add_script_run_ctx(t, ctx)

    t.start()


    collibra = get_collibra(get_config())
    
    communities = {}

    response = collibra.get("session").get(f"{collibra.get('endpoint')}/communities")

    _ = [x(communities, community.get("name"), community) for community in response.json()["results"]]

    st.write("")

    if 'submitted' not in st.session_state or not st.session_state.submitted:
        if st.button("Start", type='primary'):
            show_dialog(communities)
        
        st.stop()


    community = st.session_state.resources_community

    config['community_to_query'] = community # (communities.get(community) if community else st.warning("Please specify.") & st.stop())


    importService = ImportService(runId, 1, 150000)

    entries = [{} for element in range(15)]

    classifications_df.apply(lambda x: do_classifications(x, entries, importService, config), axis=1)

    datastores_df.apply(lambda x: do_datastores(x, entries, importService, config), axis=1)
    
    datastores_classifications_df.apply(lambda x: do_datastores_classifications(x, entries, importService, config), axis=1)
    
    if 'if_datastores_objects' in st.session_state and st.session_state.if_datastores_objects:
        datastores_objects_df.apply(lambda x: do_datastores_objects(x, entries, importService, config), axis=1)


    # each in it step file
    allEntries = [[] for element in range(15)]

    _= [allEntries[i].append(v['entry']) for i,e in enumerate(entries) for k,v in e.items()]

    _= [importService.save(e, "./runs", runId, i, True) for i,e in enumerate(allEntries)]
    
    #results = importService.harvest(get_collibra(config), config, "./runs", runId)

    HarvesterService().run(config, "./runs") 

    # placeholder.empty()

    t.join()


@st.dialog("Choose")
def show_dialog(communities):
    resources_community = st.selectbox(
        label="Select the community where you want to find your resources on ",
        options=sorted([f"{k}" for k, v in communities.items()]),
        index=None
    )

    if not resources_community:
        st.warning("Please specify.") & st.stop()

    if_datastores_objects = st.checkbox("Check to register your datastore objects")

    if st.button("Submit"):
        st.session_state.submitted = True
        st.session_state.resources_community = resources_community
        st.session_state.if_datastores_objects = if_datastores_objects

        st.rerun()


def show_progress(runId):
    progress = 0

    st.caption('Updated')

    bar = st.progress(progress)
    
    while progress < 100:
        files = list(filter(lambda x: 'beam' not in x.lower(), glob.glob(f'./runs/{runId}.json.step.*')))
        
        progress = min(len(files)*7 +1, 100)

        bar.progress(progress, text=f'{len(files)} of 15')

        time.sleep(1)

    bar.progress(100)

    time.sleep(1)


def show_dashboard(config):
    logging.getLogger().debug("show dashboard")

    style = """
        <style>
            .stVegaLiteChart {
                background-color: #EEEEEE;
            }
            .stMarkdown {
                text-align: justify;
            }
        </style>
    """

    config = get_token(get_config())

    classifications_df, datastores_df, datastores_exploded_df, datastores_classifications_df, datastores_objects_df, session = get_data_findings(config)

    datastores_per_cloud_platform = datastores_df[['provider','uid']].drop_duplicates().groupby(by=['provider']).count().reset_index().rename(columns={"uid": "count"})

    datastores_per_datatype = datastores_df[['dataType','uid']].drop_duplicates().groupby(by=['dataType']).count().reset_index().rename(columns={"uid": "count"})

    datastores_per_creation_date = datastores_df[['createdYYMM', 'uid']].drop_duplicates().groupby(by=['createdYYMM']).count().reset_index().rename(columns={"uid": "count"})

    datastores_per_state = datastores_exploded_df[['scanningState', 'uid']].drop_duplicates().groupby(by=['scanningState']).count().reset_index().rename(columns={"uid": "count"})

    datastores_per_regions = datastores_df[['regions', 'uid']].drop_duplicates().groupby(by=['regions']).count().reset_index().rename(columns={"uid": "count"})

    datastores_per_type = datastores_df[['type', 'uid']].drop_duplicates().groupby(by=['type']).count().reset_index().rename(columns={"uid": "count"})

    datastores_per_category = datastores_exploded_df[['classificationGroups', 'uid']].drop_duplicates().groupby(by=['classificationGroups']).count().reset_index().rename(columns={"uid": "count"})

    datastores_per_sensitivity = datastores_df[['sensitivity', 'uid']].drop_duplicates().groupby(by=['sensitivity']).count().reset_index().rename(columns={"uid": "count"})

    findings_per_regions = datastores_classifications_df[['regions', 'uid']].groupby(by=['regions']).count().reset_index().rename(columns={"uid": "count"})

    findings_per_type = datastores_classifications_df[['type', 'uid']].groupby(by=['type']).count().reset_index().rename(columns={"uid": "count"})

    findings_per_classifier = datastores_classifications_df[['name', 'uid']].groupby(by=['name']).count().reset_index().rename(columns={"uid": "count"})

    findings_per_type_and_classifier = datastores_classifications_df[['type', 'name', 'uid']].groupby(by=['type','name']).count().reset_index().rename(columns={"uid": "count"})

    findings_per_engine_and_classifier = datastores_classifications_df[['engine', 'name', 'uid']].groupby(by=['engine','name']).count().reset_index().rename(columns={"uid": "count"})

    findings_per_type_and_sensitivity = datastores_classifications_df[['type', 'sensitivity', 'uid']].groupby(by=['type','sensitivity']).count().reset_index().rename(columns={"uid": "count"})

    total_matches_per_regions = datastores_classifications_df[['regions','recordCountInDatastore']].groupby(by=['regions']).sum().reset_index().rename(columns={"recordCountInDatastore": "count"})

    total_matches_per_type = datastores_classifications_df[['type','recordCountInDatastore']].groupby(by=['type']).sum().reset_index().rename(columns={"recordCountInDatastore": "count"})

    total_matches_per_classifier = datastores_classifications_df[['name','recordCountInDatastore']].groupby(by=['name']).sum().reset_index().rename(columns={"recordCountInDatastore": "count"})

    total_matches_per_type_and_classifier = datastores_classifications_df[['type', 'name', 'recordCountInDatastore']].groupby(by=['type','name']).sum().reset_index().rename(columns={"recordCountInDatastore": "count"})

    total_matches_per_engine_and_classifier = datastores_classifications_df[['engine', 'name', 'recordCountInDatastore']].groupby(by=['engine','name']).sum().reset_index().rename(columns={"recordCountInDatastore": "count"})

    total_matches_per_type_and_sensitivity = datastores_classifications_df[['type', 'sensitivity', 'recordCountInDatastore']].groupby(by=['type','sensitivity']).sum().reset_index().rename(columns={"recordCountInDatastore": "count"})


    st.write(time.strftime("%Y-%m-%d %H:%M:%S")) 

    st.markdown(style, unsafe_allow_html=True)

    st.subheader("General Dashboard")


    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("AWS", datastores_per_cloud_platform.iloc[0]['count'], delta=str(datastores_per_creation_date.iloc[-1]['count']), delta_color="normal", help=None, label_visibility="visible", border=False)

    with col2:
        st.metric("Structured", datastores_per_datatype.iloc[0]['count'], delta=None, delta_color="normal", help=None, label_visibility="visible", border=False)

    with col3:
        st.metric("Unstructured", datastores_per_datatype.iloc[1]['count'], delta=None, delta_color="normal", help=None, label_visibility="visible", border=False)

    with col4:
        st.metric("Scanned", datastores_per_state.query('scanningState == "Scanned"')['count'], delta=None, delta_color="normal", help=None, label_visibility="visible", border=False)

    st.write("#")


    st.subheader("Resources Summary")

    c = (alt.Chart(datastores_per_creation_date)
        .encode(alt.X('createdYYMM:O', axis=alt.Axis(labels=True, labelAngle=0)).timeUnit("yearmonth").title('Created date'), alt.Y('count', axis=alt.Axis(labels=False)).title('Datastores'), alt.Color('count', legend=None).scale(scheme="lightgreyteal", reverse=False), alt.Text('count'), tooltip=["createdYYMM:T", "count"])
        .properties(title='Number of datastores per date')
    )

    st.altair_chart((c.mark_bar() + c.mark_text(align='center', dy=-10)).configure_axis(grid=False).configure_view(strokeWidth=0), use_container_width=True)

    st.write("#")


    col1, col2, col3 = st.columns([1,1,1])
    
    with col1:
        st.markdown(
        """
        ## Calling us-east-1

        The analysis provides a breakdown of the **datastores** identified across different **regions** and their **types**. As illustrated in the graphs below, more than **70%** of the resources with data findings are located in the **us-east-1** region, nearly **56%** are categorized as **buckets**, while **44%** are classified as **databases**.
        """
        )

    with col2:
        c = (alt.Chart(datastores_per_regions)
            .encode(alt.X('regions', axis=alt.Axis(labels=True, labelAngle=0)).title('Datastore region'), alt.Y('count', axis=alt.Axis(labels=False)).title('Datastores'), alt.Color('count', legend=None).scale(scheme="lightgreyteal", reverse=False), alt.Text('count'), tooltip=["regions", "count"])
            .properties(title='Number of datastores per region')
        )

        st.altair_chart((c.mark_bar() + c.mark_text(align='center', dy=-10)).configure_axis(grid=False).configure_view(strokeWidth=0), use_container_width=True)

    with col3:
        c = (alt.Chart(datastores_per_type)
            .encode(alt.X('type', axis=alt.Axis(labels=True, labelAngle=0)).title('Datastore type'), alt.Y('count', axis=alt.Axis(labels=False)).title('Datastores'), alt.Color('count', legend=None).scale(scheme="lightgreyteal", reverse=False), alt.Text('count'), tooltip=["type", "count"])
            .properties(title='Number of datastores per type')
        )

        st.altair_chart((c.mark_bar() + c.mark_text(align='center', dy=-10)).configure_axis(grid=False).configure_view(strokeWidth=0), use_container_width=True)

    st.write("#")


    col1, col2, col3 = st.columns([1,1,1])

    with col1:
        c = (alt.Chart(datastores_per_category)
            .encode(alt.X('classificationGroups', axis=alt.Axis(labels=True, labelAngle=0)).title('Classification groups'), alt.Y('count', axis=alt.Axis(labels=False)).title('Datastores'), alt.Color('count', legend=None).scale(scheme="lightgreyteal", reverse=False), alt.Text('count'), tooltip=["classificationGroups", "count"])
            .properties(title='Number of datastores per classification group')
        )

        st.altair_chart((c.mark_bar() + c.mark_text(align='center', dy=-10)).configure_axis(grid=False).configure_view(strokeWidth=0), use_container_width=True) 

    with col2:
        c = (alt.Chart(datastores_per_sensitivity)
            .encode(alt.X('sensitivity', axis=alt.Axis(labels=True, labelAngle=0)).title('Datastore sensitivity'), alt.Y('count', axis=alt.Axis(labels=False)).title('Datastores'), alt.Color('count', legend=None).scale(scheme="lightgreyteal", reverse=False), alt.Text('count'), tooltip=["sensitivity", "count"])
            .properties(title='Number of datastores per sensitivity')
        )

        st.altair_chart((c.mark_bar() + c.mark_text(align='center', dy=-10)).configure_axis(grid=False).configure_view(strokeWidth=0), use_container_width=True) 

    with col3:
        st.markdown(
        """
        ## Should we worry about it

        The analysis offers a comprehensive overview of the identified **datastores**, highlighting their **sensitivity** and **classifications**. As shown in the graphs below, **44%** of the resources exhibit significant findings, categorized as **sensitive** and **very sensitive** data with **Personal**, **Financial**, and **Health** being in the top 5 categories.
        """
        )

    st.write("#")


    st.subheader("Data Findinds Summary")

    col1, col2, col3 = st.columns([1,1,1])

    with col1:
        st.markdown(
        """
        ## Houston, we have a problem

        The analysis offers a detailed overview of the **unique findings** discovered across various **regions** and their **classifications**. Over **60%** of these resources are categorized as **buckets**, while around **40%** are identified as **databases**. As demonstrated in the graphs below, nearly **68%** of the resources containing data findings are situated in the **us-east-1** region. This reinforces our earlier observations that buckets and databases are the most critical components.
        """            
        )

    with col2:
        c = (alt.Chart(findings_per_regions)
            .encode(alt.X('regions', axis=alt.Axis(labels=True, labelAngle=0)).title('Datastore region'), alt.Y('count', axis=alt.Axis(labels=False)).title('Findings'), alt.Color('count', legend=None).scale(scheme="lightorange", reverse=False), alt.Text('count'), tooltip=["regions", "count"])
            .properties(title='Number of findings per region')
        )

        st.altair_chart((c.mark_bar() + c.mark_text(align='center', dy=-10)).configure_axis(grid=False).configure_view(strokeWidth=0), use_container_width=True)

    with col3:
        c = (alt.Chart(findings_per_type)
            .encode(alt.X('type', axis=alt.Axis(labels=True, labelAngle=0)).title('Datastore type'), alt.Y('count', axis=alt.Axis(labels=False)).title('Findings'), alt.Color('count', legend=None).scale(scheme="lightorange", reverse=False), alt.Text('count'), tooltip=["type", "count"])
            .properties(title='Number of findings per type')
        )

        st.altair_chart((c.mark_bar() + c.mark_text(align='center', dy=-10)).configure_axis(grid=False).configure_view(strokeWidth=0), use_container_width=True)

    st.write("#")


    col1, col2 = st.columns([2,1])

    with col1:
        c = (alt.Chart(findings_per_classifier)
            .encode(alt.X('name', axis=alt.Axis(labels=True, labelAngle=0)).title('Finding classifier'), alt.Y('count', axis=alt.Axis(labels=False)).title('Findings'), alt.Color('count', legend=None).scale(scheme="lightorange", reverse=False), alt.Text('count'), tooltip=["name", "count"])
            .properties(title='Number of findings per classifier')
        )
                
        st.altair_chart((c.mark_bar() + c.mark_text(align='center', dy=-10)).configure_axis(grid=False).configure_view(strokeWidth=0), use_container_width=True) 

    with col2:
        st.markdown(
        """
        ## Who you gonna call, today 

        The analysis provides a thorough overview of the identified **resources** and their **classifications**. The graph below illustrates that key data points, including **names**, **emails**, **phone numbers**, **addresses**, **gender**, and **geo location**, are prominently featured.
        """
        )

    st.write("#")
    

    col1, col2 = st.columns([1,2])

    with col1:
        st.markdown(
        """
        ## The most bang for the buck
        """            
        )

    with col2:
        c = (alt.Chart(findings_per_engine_and_classifier)
            .encode(alt.X('name', axis=alt.Axis(labels=True, labelAngle=0)).title('Finding classifier'), alt.Y('engine', axis=alt.Axis(labels=False, labelAngle=0)).title('Datastore engine'), alt.Color('count', legend=None).scale(scheme="orangered", reverse=False), alt.Text('count'), tooltip=["name","engine","count"])
            .properties(title='Number of findings per datastore engine and classifier')
        )

        st.altair_chart(c.mark_rect(), use_container_width=True) 

    st.write("#")


    col1, col2 = st.columns([1,2])

    with col1:
        c = (alt.Chart(findings_per_type_and_sensitivity)
            .encode(alt.X('sensitivity', axis=alt.Axis(labels=True, labelAngle=0)).title('Finding sensitivity'), alt.Y('type', axis=alt.Axis(labels=False, labelAngle=0)).title('Datastore type'), alt.Color('count', legend=None).scale(scheme="orangered", reverse=False), alt.Text('count'), tooltip=["sensitivity","type","count"])
            .properties(title='Number of findings per datastore type and sensitivity')
        )

        st.altair_chart((c.mark_rect() + c.mark_text(baseline="middle", fontWeight="bold").encode(color=alt.value("white"))), use_container_width=True) 

    with col2:
        st.markdown(
        """
        When spending time or money, it is essential to insist on getting the most bang for the buck.
        """
        )

    st.write("#")


    st.subheader("Total Matches Summary")

    #group 3.1
    col1, col2, col3 = st.columns([1,1,1])

    with col1:
        st.markdown(
        """
        ## In all its magnitude

        The analysis provides a comprehensive overview of the **total matches** identified across **regions** and their **classifications**. As illustrated in the graphs below, more than **83%** of the resources containing data findings are located in the **us-east-1** region. Furthermore, nearly **94%** of these resources are classified as **buckets**, while merely **6%** are recognized as databases. If you're looking to begin your work, start with your buckets.. 
        """            
        )

    with col2:
        c = (alt.Chart(total_matches_per_regions)
            .encode(alt.X('regions', axis=alt.Axis(labels=True, labelAngle=0)).title('Datastore region'), alt.Y('count', axis=alt.Axis(labels=False)).title('recordCountInDatastore'), alt.Color('count', legend=None).scale(scheme="reds", reverse=False), alt.Text('count'), tooltip=["regions", "count"])
            .properties(title='Number of total matches per region')
        )
        
        st.altair_chart((c.mark_bar() + c.mark_text(align='center', dy=-10)).configure_axis(grid=False).configure_view(strokeWidth=0), use_container_width=True)

    with col3:
        c = (alt.Chart(total_matches_per_type)
            .encode(alt.X('type', axis=alt.Axis(labels=True, labelAngle=0)).title('Datastore type'), alt.Y('count', axis=alt.Axis(labels=False)).title('recordCountInDatastore'), alt.Color('count', legend=None).scale(scheme="reds", reverse=False), alt.Text('count'), tooltip=["type", "count"])
            .properties(title='Number of total matches per type')
        )
        
        st.altair_chart((c.mark_bar() + c.mark_text(align='center', dy=-10)).configure_axis(grid=False).configure_view(strokeWidth=0), use_container_width=True)

    st.write("#")


    col1, col2 = st.columns([2,1])

    with col1:
        c = (alt.Chart(total_matches_per_classifier)
            .encode(alt.X('name', axis=alt.Axis(labels=True, labelAngle=0)).title('Finding classifier'), alt.Y('count', axis=alt.Axis(labels=False)).title('Datastores'), alt.Color('count', legend=None).scale(scheme="reds", reverse=False), alt.Text('count'), tooltip=["name", "count"])
            .properties(title='Number of total matches per classifier')
        )
                
        st.altair_chart((c.mark_bar() + c.mark_text(align='center', dy=-10)).configure_axis(grid=False).configure_view(strokeWidth=0), use_container_width=True) 

    with col2:
        st.markdown(
        """
        ## Kill 'Em All
        .. and get rid of mushrooms in your yard. 
        """
        )

    st.write("#")


    col1, col2 = st.columns([1,2])

    with col1:
        st.markdown(
        """
        ## Allow me
        """
        )

    with col2:
        c = (alt.Chart(total_matches_per_engine_and_classifier)
            .encode(alt.X('name', axis=alt.Axis(labels=True, labelAngle=0)).title('Finding classifier'), alt.Y('engine', axis=alt.Axis(labels=False, labelAngle=0)).title('Datastore type'), alt.Color('count', legend=None).scale(scheme="reds", reverse=False), alt.Text('count'), tooltip=["name","engine","count"])
            .properties(title='Number of total matches per datastore engine and classifier')
        )
        
        st.altair_chart(c.mark_rect(), use_container_width=True) 


    col1, col2 = st.columns([1,2])

    with col1:
        st.write("")

        c = (alt.Chart(total_matches_per_type_and_sensitivity)
            .encode(alt.X('sensitivity', axis=alt.Axis(labels=True, labelAngle=0)).title('Finding sensitivity'), alt.Y('type', axis=alt.Axis(labels=False, labelAngle=0)).title('Datastore type'), alt.Color('count', legend=None).scale(scheme="reds", reverse=False), alt.Text('count'), tooltip=["sensitivity","type","count"])
            .properties(title='Number of total matches per datastore type and sensitivity')
        )

        st.altair_chart((c.mark_rect() + c.mark_text(baseline="middle", fontWeight="bold").encode(color=alt.value("white"))), use_container_width=True) 

    with col2:
        st.markdown(
        """
        Prioritize addressing the critical findings first, followed by the high findings. 
        
        Go ahead, select the community where you want to register your storage on and push the Start button below.
        """            
        )

    st.write("#")


    st.markdown(
        """
        ###### Playground
        """
    )
    
    columns=['name_d', 'engine', 'name','classificationGroup','sensitivity','recordCountInDatastore']
    
    st.dataframe(datastores_classifications_df[columns].pivot_table(values=["recordCountInDatastore"], index=["name_d","engine","classificationGroup","sensitivity"], columns="name", aggfunc="sum"))

    st.write("")


    with st.expander("Datastore Objects"):
        columns = ["name_d","uid","name","rowCount","sensitiveRecordsCount","dbName","creationDate","tableLevelClassifications","sensitivity","sensitivityDisplayName","classifications","fileName","relativePath","fileType","storageSizeMib","url","lastModified","isEncrypted","isPublic","driveItemId"]

        st.dataframe(datastores_objects_df[columns],hide_index=True)#,column_config={"id":"Resource Id","name":"Resource Name","type":"Resource Type","_subscriptionExternalId":"Resource Account","Category": "Finding Category","Classifier": "Finding Classifier","key": "Key","path":"Path"})
        
    st.write("#")


    #do all findings
    do_all_findings(classifications_df, datastores_df, datastores_exploded_df, datastores_classifications_df, datastores_objects_df, session, config)

    st.markdown("[Results](https://print.collibra.com/profile/9693d5ce-9fb4-4e97-b46e-7218526eda14/activities)")
    
    st.stop()



def main():
    logging.getLogger().setLevel(logging.INFO)

    try:
        show_dashboard(get_config())

    except Exception as error:
        raise Exception('Error: %s', error)
    


if __name__ == '__main__':
    st.set_page_config(layout="wide")

    main()    










#done


