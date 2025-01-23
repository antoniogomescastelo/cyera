import glob
import json
import logging
import os
import time

from os.path import exists
  
import apache_beam as beam
from apache_beam.io import WriteToText
from apache_beam.options.pipeline_options import PipelineOptions
from apache_beam.options.pipeline_options import SetupOptions
from apache_beam.coders import Coder

import apache_beam.runners.interactive.interactive_beam as ib
from apache_beam.runners.interactive.interactive_runner import InteractiveRunner

from requests.auth import HTTPBasicAuth

import requests


#do import
class DoImport(beam.DoFn):    
    def process(self, element, config):
        logging.getLogger().info(f"DoImport: element: {element}")

        try:              
            collibra = {}

            collibra["host"] = f"https://{config['collibra_host']}"

            collibra["username"] = config['collibra_username']

            collibra["password"] = config['collibra_password']

            collibra["endpoint"] = f"{collibra['host']}{config['collibra_api_endpoint']}"

            collibra["session"] = requests.Session()

            collibra.get("session").auth = HTTPBasicAuth(collibra.get("username"), collibra.get("password"))

            #get filename
            filename = f"{element['resource_location']}/{element['step_number']}.{element['file_name']}.{element['part_number']}.json"

            payload = {'fileName': element['file_name']}

            files=[('file',(element['file_name'],open(filename,'rb'),'application/json'))]

            #post json job request
            response = collibra.get("session").post(f"{collibra.get('endpoint')}/import/json-job", data=payload, files=files)
 
            #wait until job complete
            id = response.json().get('id')

            state = response.json().get('state')
            
            while state != "COMPLETED" and state != "CANCELED" and state != "ERROR":
                time.sleep(1)

                response = collibra.get("session").get(f"{collibra.get('endpoint')}/jobs/{id}")
                
                state = response.json()['state']

            #add job info to element
            element["job"] = {"id": id, "result": response.json()['result']}
          
        except Exception as e:
            logging.getLogger().error(f"AuthenticationFailed: Failed to authenticate request through basic credentials")
            element["job"] = None
       
        yield element


#do shape
class DoShape(beam.DoFn):    
    def process(self, element):
        logging.getLogger().info(f"DoShape: element: {element}")
      
        element_reshaped = {f"{element[0]}" : element[1]}
      
        yield element_reshaped


#json coder
class JsonCoder(Coder):
    def encode(self, x):
      return json.dumps(x).encode("utf-8")

    def decode(self, x):
      return json.loads(x)


class HarvesterService():
    #do pipeline
    def doPipeline(self, config=None, file=None, data=None, step=None):
        logging.getLogger().info(f"doPipeline: file: {file} step: {step} data: {data['steps'][step]}")

        #TODO: read from config instead
        #set options
        options = PipelineOptions(['--direct_num_workers', '8', '--runner', 'DirectRunner', '--direct_running_mode', 'multi_threading'])
        
        options.view_as(SetupOptions).save_main_session = True

        #build and run pipeline
        with beam.Pipeline(options=options) as pipeline: 
            steps = (
                pipeline
                    | "get step" >> beam.Create(data["steps"][step])
                    | "run import" >> beam.ParDo(DoImport(), config)
                    | "group by step" >> beam.GroupBy(lambda s: s["step_number"])
                    | "shape element" >> beam.ParDo(DoShape())
                    | "write json" >> WriteToText(f"{file}.step.{step}", shard_name_template="", coder=JsonCoder())
                    #| "done" >> beam.Map(print) 
                )
            

    #do results
    def doResults(self, config=None, file=None, data=None, step=None):
        logging.getLogger().info(f"doResults: file: {file} step: {step}")    

        with open(f"{file}.step.{step}", "r") as f:
            try:
                o = json.load(f)
                data["steps"].update(o)
                logging.getLogger().info(f"doResults: data: {o} step: {step}")

            except Exception as e:
                pass
            
        os.remove(f"{file}.step.{step}")

        return data
    

    #do request
    def doRequest(self, config=None, file=None):
        logging.getLogger().info(f"doRequest: file: {file}")

        #lock file
        try:
            os.rename(file, f"{file}.lock")
        
        except Exception as e:
            logging.getLogger().error(f"json.decoder.JSONDecodeError:: Failed to deserialize JSON document: {file}")
            exit(-1)

        #load json file
        try:
            with open(f"{file}.lock", "r") as f:
                data = json.load(f)

        except Exception as e:
            logging.getLogger().error(f"FileNotFoundError: No such file or directory: {file}.lock")
            exit(-1)

        #iterate step data
        [self.doPipeline(config, file, data, step) for step in data["steps"]] 
         
        #get step data results
        results = {
            "runId": data["run_id"],
            "steps": {}
        }
        
        #delete step file, if found
        if exists(f'{file}.results'):
            os.remove(f'{file}.results')
        
        #append all data step results found
        [self.doResults(config, file, results, step) for step in data["steps"]] 

        #write step file
        with open(f'{file}.results', "a+") as f:
            f.write(json.dumps(results))

        #unlock
        try:
            os.rename(f"{file}.lock", f"{file}.done")
        except Exception as e:
            exit(-1)


    #run
    def run(self, config, input):
        files = glob.glob(f'{input}/*.json')

        [self.doRequest(config, file) for file in files] 
