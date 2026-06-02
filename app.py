import sys
import os

import certifi
ca = certifi.where()

from dotenv import load_dotenv
load_dotenv(override=True)

import urllib.parse

password = urllib.parse.quote_plus(os.getenv("MONGO_PASS"))
mongo_db_url = f"mongodb+srv://{os.getenv('MONGO_USER')}:{password}@{os.getenv('MONGO_CLUSTER')}/?appName=Cluster0"
import pymongo
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.pipeline.training_pipeline import TrainingPipeline
from networksecurity.utils.ml_utils.model.estimator import NetworkModel

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, UploadFile, Request
from uvicorn import run as app_run
from fastapi.responses import Response
from starlette.responses import RedirectResponse
import pandas as pd

from networksecurity.utils.main_utils.utils import load_object

client = pymongo.MongoClient(mongo_db_url, tlsCAFile=ca)

from networksecurity.constants.training_pipeline import DATA_INGESTION_COLLECTION_NAME
from networksecurity.constants.training_pipeline import DATA_INGESTION_DATABASE_NAME

database = client[DATA_INGESTION_DATABASE_NAME]
collection = database[DATA_INGESTION_COLLECTION_NAME]

app = FastAPI()
orgins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=orgins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="./templates")

@app.get("/", tags=["authentication"])
async def index():
    return RedirectResponse(url="/docs")

@app.get("/train", tags=["train"])
async def train_route():
    try:
        train_pipeline = TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response(content="Training successful !!", media_type="text/plain")
    except Exception as e:
        raise NetworkSecurityException(e, sys)


@app.post("/predict")
async def predict_route(request: Request, file: UploadFile=File(...)):
    try:
        df = pd.read_csv(file.file)
        preprocessor = load_object(file_path="final_model/preprocessor.pkl")
        model = load_object(file_path="final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor, model=model)
        print(df.iloc[0])
        y_pred = network_model.predict(df)
        print(y_pred)
        df["predicted_column"] = y_pred
        print(df["predicted_column"])
        df.to_csv("prediction_output/output.csv")
        table_html = df.to_html(classes="table table-striped")

        # return templates.TemplateResponse("table.html", {"request": request, "table": table_html})
        return templates.TemplateResponse(name="table.html", context={"table": table_html}, request=request)

    except Exception as e:
        raise NetworkSecurityException(e, sys)

if __name__ == "__main__":
    app_run(app, host="0.0.0.0", port=8000)