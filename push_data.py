import os
import sys
import json
import urllib.parse
from dotenv import load_dotenv
load_dotenv(override=True)

password = urllib.parse.quote_plus(os.getenv("MONGO_PASS"))
MONGO_DB_URL = f"mongodb+srv://{os.getenv('MONGO_USER')}:{password}@{os.getenv('MONGO_CLUSTER')}/?appName=Cluster0"
print(MONGO_DB_URL)

import certifi
ca = certifi.where() # Certificate Authorities bundle

import pandas as pd
import numpy as np
import pymongo
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging

class NetworkDataExtract:
    def __init__(self):
        try:
            pass
        except Exception as e:
            raise NetworkSecurityException(e, sys)
    
    def csv_to_json_converter(self, file_path):
        try:
            data = pd.read_csv(file_path)
            data.reset_index(drop=True, inplace=True)
            records = list(json.loads(data.T.to_json()).values())
            return records
        except Exception as e:
            raise NetworkSecurityException(e, sys)
    
    def insert_data_mongodb(self, records, database, collection):
        try:
            self.database = database
            self.collection = collection
            self.records = records

            self.mongo_client = pymongo.MongoClient(MONGO_DB_URL)
            self.database = self.mongo_client[self.database]

            self.collection = self.database[self.collection]
            self.collection.insert_many(self.records)
            
            return (len(records))

        except Exception as e:
            raise NetworkSecurityException(e, sys)
    
if __name__ == "__main__":
    FILE_PATH = "Network_Data/phisingData.csv"
    DATABASE = "ANAND_DB"
    Collection = "NetworkData"
    networkobj = NetworkDataExtract()
    records = networkobj.csv_to_json_converter(FILE_PATH)
    print(records)
    no_of_records = networkobj.insert_data_mongodb(records, DATABASE, Collection)
    print(no_of_records)