import os
import sys
import numpy as np
import pandas as pd

"""
defining common constant variables for training pipeline
"""
TARGET_COLUMN = "Result"
PIPELINE_NAME: str = "NetworkSecurity"
ARTIFACT_DIR: str = "Artifacts"
FILE_NAME: str = "phisingData.csv"

TRAIN_FILE_NAME: str = "train.csv"
TEST_FILE_NAME: str = "test.csv"



"""
Data Ingestion related constant start with DATA_INGESTION VAR NAME
"""
DATA_INGESTION_COLLECTION_NAME = "NetworkData"
DATA_INGESTION_DATABASE_NAME = "ANAND_DB"
DATA_INGESTION_DIR_NAME = "data_ingestion"
DATA_INGESTION_FEATURE_STORE_DIR = "feature_store"
DATA_INGESTION_INGESTED_DIR = "ingested"
DATA_INGESTION_TRAIN_TEST_SPLIT_RATIO = 0.2