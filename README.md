# Network Security Project For Phishing Data

## Overview
This project is an end-to-end Machine Learning pipeline designed for **Network Security**, specifically targeting **Phishing Data Detection**. The application incorporates automated data ingestion, validation, transformation, and model training, and it serves predictions via a robust **FastAPI** web application. 

The project has been fully containerized and successfully deployed to **AWS**.

## High Level Architecture
![High Level Diagram](images/High%20Level%20Diagram.png)

## Directory Structure
The project is organized into several key directories:
- **`networksecurity/`**: Contains the core modules for the ML pipeline (components, entities, pipelines, logging, exceptions, and cloud tools like `s3_syncer`).
- **`data_schema/`**: Contains `schema.yaml` which rigorously defines the features and expected data types for validation.
- **`Network_Data/`**: Holds the raw dataset (`phisingData.csv`) used for MongoDB ingestion.
- **`valid_data/`**: Contains validation datasets (`test.csv`) for testing models on unseen data.
- **`templates/`**: Holds HTML templates (`table.html`) used by FastAPI to visually render the prediction results.

## Pipeline Components

### 1. Data Ingestion
The process begins by fetching raw data (e.g., `phisingData.csv`) and pushing it to a **MongoDB** database. The training pipeline connects to MongoDB to retrieve this data for further processing.
![Data Ingestion](images/DataIngestion.png)

### 2. Data Validation
Ensures data quality and integrity before model training. This step includes validating the schema, checking for missing values, and identifying data drift.
![Data Validation](images/Data%20Validation.png)

### 3. Data Transformation
Applies feature engineering, imputation, and scaling to the raw data, preparing it for the machine learning algorithms. The resulting preprocessor is saved as a `.pkl` file for inference.
![Data Transformation](images/Data%20Transformation.png)

### 4. Model Trainer
Trains the machine learning models (using Scikit-Learn), evaluates their performance, and logs metrics using **MLflow** & **DAGsHub**. The best-performing model is saved for production deployment.
![Model Trainer](images/Model%20Trainer.png)

## API Endpoints (FastAPI)
The application exposes a REST API built with **FastAPI**:
- `GET /` : Redirects to the API documentation (Swagger UI).
- `GET /train` : Triggers the complete training pipeline asynchronously.
- `POST /predict` : Accepts a CSV file containing network data, applies the preprocessor, makes predictions using the trained model, and returns an HTML table with the prediction results.

## AWS Deployment Architecture
This application utilizes a modern cloud architecture on AWS for robust deployment and artifact tracking:
- **Amazon S3**: Used for syncing and storing ML pipeline **Artifacts** (models, preprocessors, logs). The project includes a dedicated `s3_syncer` module to interact with S3.
- **Amazon ECR (Elastic Container Registry)**: Used for tracking and storing the latest Docker container images of the application.
- **Amazon EC2 (Elastic Compute Cloud)**: Hosts the live Docker container, serving the FastAPI application to end users and handling prediction/training requests.

![Deployment](images/Deployment.png)

## Setup and Installation

### Prerequisites
- Python 3.8+
- MongoDB Atlas Account
- AWS Account (with S3, ECR, EC2 access configured)

### Local Development

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd NetworkSecurity
   ```

2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up Environment Variables:
   Create a `.env` file in the root directory and configure your MongoDB credentials:
   ```env
   MONGO_USER=<your-mongodb-username>
   MONGO_PASS=<your-mongodb-password>
   MONGO_CLUSTER=<your-mongodb-cluster-url>
   ```

5. Run the Data Ingestion Script (Optional, if pushing new data to MongoDB):
   ```bash
   python push_data.py
   ```

6. Start the FastAPI Server:
   ```bash
   python app.py
   ```
   The application will be available at `http://localhost:8000/`. You can view the API documentation at `http://localhost:8000/docs`.

## Technologies Used
- **Language**: Python
- **Web Framework**: FastAPI, Uvicorn
- **Machine Learning**: Scikit-Learn, Pandas, NumPy
- **Database**: MongoDB (pymongo)
- **Experiment Tracking**: MLflow, DAGsHub
- **Deployment**: Docker, AWS (EC2, ECR, S3)

---
*Developed by Anand Velpuri*
