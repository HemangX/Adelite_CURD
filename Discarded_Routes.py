import azure.functions as func
import fastapi
import pandas as pd
from datetime import datetime, timedelta
import json
from fastapi import status, Depends, Body, HTTPException, UploadFile, File, Request
from typing import Optional, Union, List
from sqlalchemy import text, update, desc, or_
import logging
import requests
from fastapi.middleware.cors import CORSMiddleware
from common import (
    verify_jwt_token,
    jsonCommonStatus,
    createconnection,
    create_jwt_token,
    Encode_password,
    patient_id_generator,
    verify_password,
    http_exception_handler,
    email_generation,
    otp_generator,
    calculate_age,
)
from schemas import *
import csv
from langchain_openai import AzureChatOpenAI
from langchain.chains import ConversationChain
from langchain.chains.conversation.memory import ConversationBufferMemory
from loguru import logger
import ast
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import re
import random
from azure.storage.blob import ContentSettings, BlobServiceClient
from Coman.Utils import get_blob_sas_url, generate_unique_filename
from const import *
import jwt
from fastapi.security import HTTPBearer


@fastapi_app.post(
    "/query_symptoms",
    status_code=status.HTTP_200_OK,
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="This API is used to query the symptoms of specific users' details.",
)
def query_symptoms(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        symptoms = (
            session.query(Symptom)
            .filter_by(patient_id=pay_load["patient_id"])
            .order_by(Symptom.ctimestamp.desc())
            .all()
        )
        health_data_list = []
        for symptom in symptoms:
            health_data = {
                "date": symptom.tdate if symptom.tdate else "NA",
                "symptoms": {},
            }
            if health_data["date"] == "NA":
                health_data["date"] = symptom.tdate
            for key in [
                "infirmity",
                "nsynacpe",
                "tirednessafterwards",
                "syncope",
                "p_tiredness",
                "breathnessda",
                "breathnessea",
                "dizziness",
                "col_swet",
                "chest_pain",
                "pressurechest",
                "worry",
                "weakness",
            ]:
                health_data["symptoms"][key] = getattr(symptom, key, "NA")
            health_data_list.append(health_data)
        return JsonCommonStatus(
            message="query symptoms fetched successfully",
            data=health_data_list,
            statuscode=200,
            status=True,
        )
    except Exception as e:
        print(f"Error: {e}")
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.get("/healthubcontentupload")
def healtHubContentUpload():
    try:
        content = {}
        session = createconnection()
        for week_key, week_data in content.items():
            new_week_detail = WeekDetails(
                week=week_key,
                week_title=week_data["week_title"],
                week_objective=json.dumps(week_data["week_Objective"]),
                week_activity=week_data["week_Activity"],
                week_desc=week_data["week_desc"],
                week_explanation=week_data["week_explanation"],
                content=week_data["content"],
            )
            session.add(new_week_detail)
        session.commit()

        return JsonCommonStatus_without_data(
            status=True,
            statuscode=200,
            message="Data inserted successfully",
        )
    except Exception as e:
        return JsonCommonStatus_without_data(
            status=False,
            statuscode=500,
            message=f"Internal Server Error: {str(e)}",
        )
