from pymongo import MongoClient
from pymongo.server_api import ServerApi
import urllib.parse
from dotenv import load_dotenv
import os

load_dotenv(override=True)

password = urllib.parse.quote_plus(os.getenv("MONGO_PASS"))
uri = f"mongodb+srv://{os.getenv('MONGO_USER')}:{password}@{os.getenv('MONGO_CLUSTER')}/?appName=Cluster0"

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))

# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)