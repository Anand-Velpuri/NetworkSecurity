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
from fastapi import FastAPI, File, UploadFile, Request, HTTPException
from uvicorn import run as app_run
from fastapi.responses import Response, JSONResponse
from starlette.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
import pandas as pd
from pydantic import BaseModel

from networksecurity.utils.main_utils.utils import load_object
from networksecurity.utils.url_feature_extractor import extract_features

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

# ── Pydantic model for URL prediction request ──
class URLRequest(BaseModel):
    url: str

# ── Routes ──

@app.get("/", tags=["authentication"])
async def index():
    return RedirectResponse(url="/scan")

TRAIN_API_KEY = os.getenv("TRAIN_API_KEY")

@app.get("/train", tags=["train"])
async def train_route(api_key: str = None):
    if not TRAIN_API_KEY or api_key != TRAIN_API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden: invalid or missing API key.")
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


@app.get("/scan", tags=["predict"])
async def scan_page(request: Request):
    """Serve the URL prediction UI page."""
    return templates.TemplateResponse(name="predict_url.html", request=request)


@app.post("/predict_url", tags=["predict"])
async def predict_url_route(payload: URLRequest):
    """
    Accept a URL, extract 30 phishing features, run the ML model,
    and return the prediction along with the extracted features.
    """
    try:
        url = payload.url.strip()
        if not url:
            return JSONResponse(status_code=400, content={"detail": "URL is required."})

        logging.info(f"Extracting features for URL: {url}")
        features = extract_features(url)
        logging.info(f"Features extracted: {features}")

        # Build a single-row DataFrame with the same columns as the training data
        df = pd.DataFrame([features])

        preprocessor = load_object(file_path="final_model/preprocessor.pkl")
        model = load_object(file_path="final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor, model=model)

        y_pred = network_model.predict(df)
        prediction = int(y_pred[0])

        logging.info(f"Prediction for {url}: {prediction}")

        return JSONResponse(content={
            "url": url,
            "prediction": prediction,
            "features": features
        })

    except Exception as e:
        logging.error(f"Error predicting URL: {e}")
        return JSONResponse(status_code=500, content={"detail": str(e)})


if __name__ == "__main__":
    app_run(app, host="0.0.0.0", port=8000)