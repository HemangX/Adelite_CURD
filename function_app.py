import azure.functions as func
import fastapi
import pandas as pd
from datetime import datetime, timedelta, timezone
import json
from fastapi import status, Depends, Body, HTTPException, UploadFile, File, Request
from typing import Optional, Union
from sqlalchemy.orm import aliased
from sqlalchemy import text, update, desc, delete, or_, func as sqlalchemyfunc
import logging
import requests
from common import (
    verify_jwt_token,
    createconnection,
    create_jwt_token,
    Encode_password,
    patient_id_generator,
    verify_password,
    http_exception_handler,
    email_generation,
    otp_generator,
    calculate_age,
    get_formated_answer,
    send_email_confirmation,
    send_contact_us_email,
    send_contact_with_pdf,
    country_map,
    dail_code,
    get_blob_sas_url,
    generate_unique_filename,
    generate_blob_sas_url,
    nationality_to_country_code,
    send_tempwd_email,
    send_uic,
    generate_uic_code,
    send_account_expiration_extension_email,
    send_account_expired_email,
    generate_temp_password,
)
import hashlib
from schemas import (
    HealthRecord,
    Symptom,
    UserData,
    PatientDetails,
    history_question,
    CreationUserschema,
    ChatRequest,
    Message,
    introstate,
    preferanceSchema,
    preferanceSchemaAdmin,
    request_preferanceSchema,
    JsonCommonStatus_without_data,
    JsonCommonStatus,
    update_profile,
    loginschema,
    healthdatailsschema,
    addsymptomsschema,
    healthdetailsui,
    socialauth,
    history_chatbot_answers,
    history_command,
    generate_otp,
    forgetpwd,
    verify_otp,
    chat_bot_iteration,
    history_schema,
    profile_keys,
    changePwd,
    ProfileCompletionRequest,
    history_bypass,
    healthDetailsDateRange,
    doctorCredentials,
    doctorDetails,
    reqCreateDoctorSchemas,
    DoctorCreds,
    EmailToken,
    APILog,
    getAssetName,
    HealthHubContent,
    EmailSchema,
    ExpertMonitoring,
    HealthHubProgress,
    UpdateHealthHubStatus,
    EmailWithPdf,
    AdminUser,
    AdminCreds,
    Admin,
    SuperAdminUser,
    UpdateAdminUser,
    ChangeAdminPassword,
    ChangeUserStatus,
    Uic_generator,
    UIC_Creds,
    EducationHistory,
    UpdateAdminDetails,
    EducationHistory_admin,
    QuestionPreferenceComment,
    QuestionPreferenceCommentAdmin,
    WeekDetails,
)

import csv
from langchain_openai import AzureChatOpenAI
from langchain.chains import ConversationChain
from fastapi.middleware.cors import CORSMiddleware
from langchain.chains.conversation.memory import ConversationBufferMemory
from loguru import logger
import os
import ast
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import re
from azure.storage.blob import ContentSettings, BlobServiceClient
import jwt
from fastapi.security import HTTPBearer
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from dotenv import load_dotenv

load_dotenv()

keyVaultName = os.getenv("KEY_VAULT_NAME")
KVUri = f"https://{keyVaultName}.vault.azure.net"

credential = DefaultAzureCredential()
client = SecretClient(vault_url=KVUri, credential=credential)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logg = logging.getLogger(__name__)

fastapi_app = fastapi.FastAPI(description="Helloalfred Fast api documentation")


@fastapi_app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    try:
        error_messages = []
        for error in exc.errors():
            error_messages.append(
                {
                    "field": error.get("loc")[1],
                    "message": error.get("msg", "validation error"),
                }
            )
        return JSONResponse(
            status_code=200,
            content={
                "message": "Validation error",
                "statuscode": 422,
                "status": False,
                "detail": error_messages,
            },
        )
    except Exception as e:
        print("error in validation exception handler---------", e)


app = func.AsgiFunctionApp(app=fastapi_app, http_auth_level=func.AuthLevel.ANONYMOUS)


fastapi_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

fastapi_app.add_exception_handler(HTTPException, http_exception_handler)


@fastapi_app.middleware("http")
async def log_request(request: Request, call_next):
    start_time = datetime.now()
    entry_time = start_time.strftime("%Y-%m-%d %H:%M:%S")
    request_body = await request.body()
    response = await call_next(request)
    end_time = datetime.now()
    exit_time = end_time.strftime("%Y-%m-%d %H:%M:%S")
    total_time = (end_time - start_time).total_seconds()
    client_ip = request.headers.get("X-Real-IP")
    user_identifier = None
    authorization: str = request.headers.get("Authorization")
    if authorization:
        try:
            payload = verify_jwt_token(authorization)
            user_identifier = payload.get("patient_id")
        except Exception as e:
            print("error in auth : ", e)
    if (
        request.url.path == "/login_account"
        or request.url.path == "/create_account"
        or request.url.path == "/get-country-code"
    ):
        try:
            body = json.loads(request_body.decode("utf-8"))
            user_identifier = body.get("email") or body.get("username")
        except Exception as e:
            print(f"Failed to parse request body: {e}")
            pass

    log_record = {
        "request_url": request.url.path,
        "method": request.method,
        "client_ip": client_ip,
        "status_code": response.status_code,
        "entry_time": entry_time,
        "exit_time": exit_time,
        "duration": total_time,
        "user_identifier": user_identifier,
    }
    session = createconnection()
    try:
        log = APILog(**log_record)
        session.add(log)
        session.commit()
    except Exception as e:
        if session:
            session.rollback()
        print("error in log module : ", e)
    finally:
        if session:
            session.close()
    return response


@fastapi_app.post(
    "/create_account",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    status_code=status.HTTP_200_OK,
    description="""The function `createaccount` takes in user data, validates it, encodes the password, and creates a
    new account in the system if the email is unique.
    :param req: The function `createaccount` takes a request object `req` of type `CreationUserschema`
    as a parameter. This request object contains information such as email, username, date of birth
    (dob), gender, password, mobile number, account type (rtype), education, social security number (ss
    :type req: CreationUserschema
    :return: The function `createaccount` is returning a JSON response with a message indicating the
    outcome of the account creation process. The specific return values are as follows:
    """,
)
def createaccoutnt(req: CreationUserschema):
    req_body = req
    if "@" not in req_body.email or "." not in req_body.email:
        return JsonCommonStatus_without_data(
            message="Provide a valid email",
            statuscode=status.HTTP_422_UNPROCESSABLE_ENTITY,
            status=False,
        )
    if req_body.username == req_body.email:
        return JsonCommonStatus_without_data(
            message="Username and email cannot be the same",
            statuscode=status.HTTP_422_UNPROCESSABLE_ENTITY,
            status=False,
        )
    if not bool(re.match(r"^\+?\d+$", req_body.mobile)):
        return JsonCommonStatus_without_data(
            message="Invalid Mobile Number",
            statuscode=status.HTTP_422_UNPROCESSABLE_ENTITY,
            status=False,
        )
    if (req_body.ssn != "") and ((len(req_body.ssn) == 9 or len(req_body.ssn) == 0)):
        return JsonCommonStatus_without_data(
            message="SSN Should be exactly 9 digits!",
            statuscode=status.HTTP_422_UNPROCESSABLE_ENTITY,
            status=False,
        )
    dob = pd.to_datetime(req_body.dob).strftime("%Y-%m-%d")
    age = calculate_age(dob)
    if age < 18 or age > 120:
        return JsonCommonStatus_without_data(
            message="The person should be atleast 18 years old and not more than 120",
            statuscode=status.HTTP_422_UNPROCESSABLE_ENTITY,
            status=False,
        )
    if req_body.gender not in ["Male", "Female", "Other"]:
        return JsonCommonStatus_without_data(
            message="Specify a valid gender",
            statuscode=status.HTTP_422_UNPROCESSABLE_ENTITY,
            status=False,
        )
    # regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$' --Skiped
    # if re.match(regex,req_body.password):
    #     return JsonCommonStatus_without_data(message="A password should contain a minimum length of 8 characters with the comobination of characters",statuscode=status.HTTP_400_BAD_REQUEST, status=False)
    tp, main_ = Encode_password(req_body.password)
    salt, password = main_[0], main_[1]
    try:
        session = createconnection()
        results_email = (
            session.query(PatientDetails)
            .filter(
                or_(
                    PatientDetails.email == req_body.email.replace(" ", ""),
                    PatientDetails.mobile == req_body.mobile,
                )  # noqa: E731
            )
            .first()
        )
        resultDoctorsEmail = (
            session.query(doctorDetails)
            .filter(
                or_(
                    doctorDetails.email == req_body.email.replace(" ", ""),
                    doctorDetails.mobile == req_body.mobile.replace(" ", ""),
                )
            )
            .first()
        )
        print(not results_email and not resultDoctorsEmail, "------------------")
        if not results_email and not resultDoctorsEmail:
            patient_id = patient_id_generator()
            user_data = UserData(patient_id=patient_id, salt=salt, password=password)
            timestamp = pd.Timestamp("now")
            patient_details = PatientDetails(
                patient_id=patient_id,
                username=req_body.username.strip(),
                email=req_body.email.replace(" ", ""),
                dob=dob,
                gender=req_body.gender.strip(),
                mobile=req_body.mobile.strip(),
                rtype=req_body.rtype.strip() if req_body.education != "" else "",
                education=(
                    req_body.education.strip() if req_body.education != "" else ""
                ),
                ssn=req_body.ssn.strip() if req_body.ssn != "" else "",
                insuranceurl=(
                    req_body.insuranceurl.strip() if req_body.insuranceurl != "" else ""
                ),
                nationality=req_body.nationality.strip(),
                created_date=timestamp.strftime("%Y-%m-%d"),
            )
            session.add(user_data)
            session.add(patient_details)
            session.commit()
            session.close()
            token = create_jwt_token(data={"patient_id": patient_id})
            return JsonCommonStatus(
                message="Account Created Successfully! Thank You",
                statuscode=status.HTTP_200_OK,
                status=True,
                data={"token": token},
            )
        email = "Account with this email already exist. Please try another email"
        mobile = "Account with this mobile number already exist. Please try another mobile number"
        return JsonCommonStatus_without_data(
            message=(
                email
                if results_email
                and results_email.email == req.email
                or resultDoctorsEmail
                and resultDoctorsEmail.email == req.email
                else mobile
            ),
            statuscode=status.HTTP_409_CONFLICT,
            status=False,
        )
    except Exception as e:
        print("error in creat accout", str(e))
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )


@fastapi_app.put(
    "/update_details",
    status_code=status.HTTP_200_OK,
    response_model=JsonCommonStatus_without_data,
    description="""
    The `updateAccount` function updates a user's account details based on the provided profile update
    request and JWT token authentication.
    :param req: The `req` parameter in the `updateAccount` function seems to be of type
    `update_profile`, which is likely a custom class or model used for updating user profiles. This
    parameter is used to extract the request body for updating user details
    :type req: update_profile
    :param pay_load: The `pay_load` parameter in the `updateAccount` function is using the `Depends`
    function from FastAPI to verify a JWT token. This parameter is expecting a dictionary containing the
    payload data extracted from the JWT token. The function checks if the 'email' key is present in the
    payload
    :type pay_load: dict
    :return: The function `updateAccount` returns a JSON response with a message indicating the status
    of the update operation. The response includes a message, status code, and a boolean status flag.
    The specific messages returned include:
    - "Email is compulsory for updating details." (status code 400) if the email is not present in the
    payload.
    - "No Parameters found to update" (status code 400
    """,
)
def updateAccount(req: update_profile, pay_load: dict = Depends(verify_jwt_token)):
    try:
        req_body = req.model_dump()
        if "email" not in pay_load.keys():
            return JsonCommonStatus_without_data(
                message="Email is compulsory for updating details.",
                statuscode=400,
                status=False,
            )
        if all(value is None for value in req_body.values()):
            return JsonCommonStatus_without_data(
                message="No Parameters found to update",
                statuscode=status.HTTP_400_BAD_REQUEST,
                status=True,
            )
        session = createconnection()
        result = (
            session.query(PatientDetails)
            .filter_by(patient_id=pay_load.get("patient_id"))
            .first()
        )
        if not result:
            return JsonCommonStatus_without_data(
                message="User data not found",
                statuscode=status.HTTP_404_NOT_FOUND,
                status=False,
            )
        update_values = {}
        for key_, value in req_body.items():
            if value is not None:
                update_values[key_] = value
        update_query = (
            update(PatientDetails)
            .values(update_values)
            .where(PatientDetails.patient_id == pay_load["patient_id"])
        )
        session.execute(update_query)
        session.commit()
        session.close()
        return JsonCommonStatus_without_data(
            message="Details updated successfully",
            statuscode=status.HTTP_200_OK,
            status=True,
        )
    except Exception as e:
        logging.error("Code failed with:- " + str(e))
        print("error in update", e)
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )


@fastapi_app.post(
    "/health_details",
    response_model=JsonCommonStatus_without_data,
    description="""
    This Python function inserts or updates health details for a patient in a database table and returns
    a success or error message.
    :param pay_load: The `pay_load` parameter in the `healthdetails` function seems to be used for
    verifying a JWT token. It is likely used to extract information about the authenticated user, such
    as their `patient_id`, from the token payload. This information is then used to perform operations
    specific to the authenticated user
    :type pay_load: dict
    :param req: The `req` parameter in the `healthdetails` function is of type
    `Optional[healthdatailsschema]` and is used to receive the request body data. It is annotated with
    `Body(None)` which means that the request body can be empty or `None`. If the request body
    :type req: Optional[healthdatailsschema]
    :return: The function `healthdetails` returns a JSON response with a message indicating the status
    of the operation. The response includes a message, status code, and a boolean status flag. The
    specific messages returned are:
    - If the health details were noted successfully: "The Health details for :- {timestamp} Were noted
    successfully"
    - If unable to update health details: "Unable to update Health details"
    """,
)
def healthdetails(
    pay_load: dict = Depends(verify_jwt_token),
    req: Optional[healthdatailsschema] = Body(None),
):
    try:
        session = createconnection()
        if req is not None:
            req_body = req.model_dump()
            validate = ["weight"]
            update_values = {
                key: value for key, value in req_body.items() if key in validate
            }
            if update_values:
                update_query = (
                    update(PatientDetails)
                    .where(PatientDetails.patient_id == pay_load["patient_id"])
                    .values(update_values)
                )
                session.execute(update_query)
                session.commit()
        else:
            req_body = req
        timestamp = pd.Timestamp("now")
        query = HealthRecord(
            patient_id=pay_load["patient_id"],
            ctimestamp=timestamp.strftime("%Y-%m-%d %X"),
            weight=req_body.get("weight", "NA"),
            height=req_body.get("height", "NA"),
            tdate=req_body.get("tdate"),
            pulse=req_body.get("pulse", "NA"),
            bloodp=req_body.get("bloodp", "NA"),
        )
        session.add(query)
        session.commit()
        selectquery = (
            session.query(HealthRecord)
            .where(
                HealthRecord.tdate == req_body.get("tdate"),
                HealthRecord.patient_id == pay_load["patient_id"],
            )
            .first()
        )
        session.close()
        if selectquery:
            return JsonCommonStatus_without_data(
                message="The Health details for :- "
                + str(req_body.get("tdate"))
                + " Were noted successfully",
                statuscode=status.HTTP_200_OK,
                status=True,
            )
        else:
            return JsonCommonStatus_without_data(
                message="Unable to update Healt details",
                statuscode=status.HTTP_400_BAD_REQUEST,
                status=False,
            )
    except Exception as e:
        logging.error("healt details " + str(e))
        print("error in add health details----", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.delete(
    "/delete_account",
    status_code=status.HTTP_200_OK,
    response_model=JsonCommonStatus_without_data,
    description="""
    The `deleteAccount` function deletes a user account based on the provided email address after
    verifying the JWT token.
    :param pay_load: The `pay_load` parameter in the `deleteAccount` function is used to verify the JWT
    token and contains information about the user. It is a dictionary that likely includes details such
    as the user's email address
    :type pay_load: dict
    :param req: The `req` parameter in the `deleteAccount` function is an optional dictionary that
    represents the request body. It is used to pass additional data or information to the function if
    needed. In this case, the function is expecting a dictionary as the request body, but it is optional
    and can be set
    :type req: Optional[dict]
    :return: The function `deleteAccount` returns a JSON response with a message indicating whether the
    user account deletion was successful or not. The response includes a status code to indicate the
    outcome of the operation.
    """,
)
def deleteAccount(
    pay_load: dict = Depends(verify_jwt_token), req: Optional[dict] = Body(None)
):
    if "email" not in pay_load.keys():
        return JsonCommonStatus_without_data(
            message="Email is compulsory for updating details.",
            statuscode=400,
            status=False,
        )
    checker_query = f"SELECT patient_id FROM patient_details WHERE email='{pay_load['email']}' and activestat = 1;"
    main_query = (
        f"UPDATE patient_details SET activestat = 0 WHERE email = '{pay_load['email']}'"
    )
    session = createconnection()
    try:
        results = session.execute(text(checker_query))
        count = 0
        for val in results:
            patient_id = val[0]
            count += 1
        main_query = f"UPDATE patient_details SET activestat = 0 WHERE patient_id = '{patient_id}';"
        user_query = f"DELETE FROM user_data WHERE patient_id = '{patient_id}';"
        if count != 0:
            session.execute(text(main_query))
            session.execute(text(user_query))
            session.commit()
            session.close()
        else:
            return JsonCommonStatus_without_data(
                message="User Account with email :- "
                + pay_load["email"]
                + " Does not exsist",
                statuscode=status.HTTP_404_NOT_FOUND,
                status=False,
            )
    except Exception as e:
        logging.error("Delete account:- " + str(e))
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )
    return JsonCommonStatus_without_data(
        message="User Account Deleted Successfully. Thank You",
        statuscode=200,
        status=True,
    )


@fastapi_app.post(
    "/login_account",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    This Python function is for logging in a user account by checking the provided username and password
    against the database.
    :param req: The `req` parameter in the `login_account` function is of type `loginschema`. It seems
    to be a request object that contains user login information such as username and password. The
    function checks if the required fields (username and password) are present in the request body and
    then proceeds to
    :type req: loginschema
    :return: The `login_account` function returns a JSON response with a message and status based on the
    conditions met during the login process. The possible return scenarios are:
    """,
)
def login_account(req: loginschema):
    req_body = req.model_dump()
    logger.trace(req_body)
    required_fields = ["username", "password"]
    session = createconnection()
    print("The session is:- ", session, flush=True)

    if not all(key_ in req_body for key_ in required_fields):
        missing_fields = set(required_fields) - set(req_body.keys())
        return JsonCommonStatus_without_data(
            message=f"Missing Fields :- [ {', '.join(map(str, missing_fields))} ] in the body.",
            statuscode=400,
            status=False,
        )
    # The above Python code snippet is checking if all the keys in the `required_fields` list are
    # present in the `req_body` dictionary. If any key is missing, it identifies the missing fields
    # and constructs a message indicating which fields are missing in the body. It then returns a JSON
    # response with a message specifying the missing fields, a status code of 400, and a status of
    # False.
    if "@" in req_body["username"] or "." in req_body["username"]:
        query = (
            session.query(PatientDetails)
            .filter(PatientDetails.email == req_body["username"].replace(" ", ""))
            .first()
        )
        docterQuery = (
            session.query(doctorDetails)
            .filter(doctorDetails.email == req_body["username"].replace(" ", ""))
            .first()
        )
        superAdminQuery = (
            session.query(Admin)
            .filter(Admin.email == req_body["username"].replace(" ", ""))
            .first()
        )
    else:
        query = (
            session.query(PatientDetails)
            .filter(PatientDetails.mobile == req_body["username"].replace(" ", ""))
            .first()
        )
        docterQuery = (
            session.query(doctorDetails)
            .filter(doctorDetails.mobile == req_body["username"].replace(" ", ""))
            .first()
        )
        superAdminQuery = (
            session.query(Admin)
            .filter(Admin.mobile == req_body["username"].replace(" ", ""))
            .first()
        )

    try:
        if query or docterQuery or superAdminQuery:
            if not docterQuery and not superAdminQuery:
                user_query = (
                    session.query(UserData)
                    .filter(UserData.patient_id == query.patient_id)
                    .first()
                )
            elif not query and not docterQuery:
                user_query = (
                    session.query(AdminCreds)
                    .filter(AdminCreds.user_id == superAdminQuery.user_id)
                    .first()
                )
            else:
                return JsonCommonStatus_without_data(
                    message="Hey! Doctor currently we have don't have doctor module supportive. If you need help please reach out to support@helloalfred.ai",
                    statuscode=403,
                    status=False,
                )
                # user_query = (
                #     session.query(DoctorCreds)
                #     .filter(
                #         DoctorCreds.doctor_details_id == docterQuery.doctor_details_id
                #     )
                #     .first()
                # )

            if user_query:
                if verify_password(
                    req_body["password"], user_query.salt, user_query.password
                ):
                    if query and not query.activestat:
                        return JsonCommonStatus_without_data(
                            message="Account is under review",
                            statuscode=401,
                            status=False,
                        )
                    if docterQuery:
                        role = 2
                        user_id = docterQuery.doctor_details_id
                        email = docterQuery.email
                        username = docterQuery.fullName
                    elif superAdminQuery:
                        if (
                            not user_query.pwdchanged
                            and user_query.tempwddate
                            and user_query.tempwddate > pd.Timestamp("now")
                            and superAdminQuery.role_id == 1
                        ):
                            timestamp = pd.Timestamp("now")
                            salt, password, dynamic_password = generate_temp_password()
                            user_query.password = password
                            user_query.salt = salt
                            user_query.tempwddate = (timestamp.strftime("%Y-%m-%d %X"),)
                            send_tempwd_email(
                                superAdminQuery.name,
                                "Temporary Password",
                                superAdminQuery.email,
                                dynamic_password,
                            )
                            session.commit()
                            return JsonCommonStatus_without_data(
                                message="Your temporary password has expired. A new temporary password has been sent to your registered email.",
                                statuscode=401,
                                status=False,
                            )
                        if (
                            superAdminQuery.active_state
                            and superAdminQuery.role_id == 1
                            and superAdminQuery.expiry_date < pd.Timestamp("now")
                        ):
                            return JsonCommonStatus_without_data(
                                message="Your account has expired. Please contact support@helloalfred.ai",
                                statuscode=401,
                                status=False,
                            )
                        role = superAdminQuery.role_id
                        user_id = superAdminQuery.user_id
                        email = superAdminQuery.email
                        username = superAdminQuery.name
                    else:
                        role = 3
                        user_id = query.patient_id
                        email = query.email
                        username = query.username
                    token = create_jwt_token(
                        data={
                            "patient_id" if query else "user_id": user_id,
                            "email": email,
                            "username": username,
                            "role": role,
                            "change_pwd": (
                                not user_query.pwdchanged if superAdminQuery else False
                            ),
                        }
                    )

                    return JsonCommonStatus(
                        message="User authenticated succesfully!",
                        data={"token": token},
                        statuscode=200,
                        status=True,
                    )
                else:
                    return JsonCommonStatus_without_data(
                        message="Incorrect password or Incorrect Username",
                        statuscode=401,
                        status=False,
                    )
            else:
                return JsonCommonStatus_without_data(
                    message="Unable to access the account contact admin",
                    statuscode=401,
                    status=False,
                )
        else:
            return JsonCommonStatus_without_data(
                message="User not found", statuscode=404, status=False
            )
    except Exception as e:
        logging.error("login account username:- " + str(e))
        print("error in login api", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )
    finally:
        if session:
            session.close()


@fastapi_app.post(
    "/add_symptoms",
    status_code=status.HTTP_200_OK,
    response_model=JsonCommonStatus_without_data,
    description="This API is used to create symptoms.",
)
def add_symptoms(req: addsymptomsschema, pay_load: dict = Depends(verify_jwt_token)):
    req_body = req.model_dump()
    if "patient_id" not in pay_load.keys():
        logging.error("Error in Add_symptoms token")
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )
    try:
        session = createconnection()
        timestamp = pd.Timestamp("now")
        tdate = timestamp.date().strftime("%Y-%m-%d")
        symptom_data = {
            "patient_id": pay_load["patient_id"],
            "tdate": tdate,
            "ctimestamp": datetime.now(),
            "health_id": req_body.get("health_id"),
        }
        for key, value in req_body.items():
            if key in [
                "infirmity",
                "nsynacpe",
                "tirednessafterwards",
                "syncope",
                "breathnessda",
                "p_tiredness",
                "breathnessea",
                "dizziness",
                "col_swet",
                "chest_pain",
                "pressurechest",
                "worry",
                "weakness",
            ]:
                if value is not None:
                    symptom_data[key] = value
        symptom = Symptom(**symptom_data)
        session.add(symptom)
        session.commit()
        return JsonCommonStatus_without_data(
            message="The Symptoms for :- "
            + str(timestamp.date())
            + " Were noted successfully!",
            statuscode=200,
            status=True,
        )
    except Exception as e:
        logging.error("login account username:- " + str(e))
        print("error in Symptoms api", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.get(
    "/query_healthdetails",
    status_code=status.HTTP_200_OK,
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="This API is used to query the health details of specific users.",
)
def query_healthdetails(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        health_records = (
            session.query(HealthRecord)
            .filter_by(patient_id=pay_load["patient_id"])
            .order_by(HealthRecord.ctimestamp.desc())
            .all()
        )
        json_list_data = []
        extraction_json = {
            "date": "",
        }
        for data in health_records:
            extraction_json["date"] = data.tdate
            for key in ["weight", "feet", "inch", "bloodp", "pulse"]:
                extraction_json[key] = getattr(data, key, "NA")
            json_list_data.append(extraction_json)
        return JsonCommonStatus(
            message="health details fetched successfully",
            data=json_list_data,
            statuscode=200,
            status=True,
        )
    except Exception as e:
        print("error in query_health", str(e))
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.post(
    "/educational_bot",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="This API is used to communicate with a chatbot.",
)
async def send_message(
    message: Message, decoded_data: Optional[dict] = Depends(verify_jwt_token)
):
    return JsonCommonStatus_without_data(
        message="The API Works form streaming URL", status=False, statuscode=404
    )


@fastapi_app.get(
    "/userdetails",
    # response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The function `get_patient_details` retrieves and processes patient details from a database based on
    the provided patient ID.

    :param pay_load: The `pay_load` parameter in the `get_patient_details` function is expected to be a
    dictionary containing information about the patient. This information is used to query the database
    and retrieve details such as email, username, date of birth, gender, education, height, weight,
    social security number, mobile
    :type pay_load: dict
    :return: The function `get_patient_details` is returning a JSON response with the message "User
    details fetched successfully", the fetched patient details in the `data` field, a status code of
    200, and a status of True if the data is successfully retrieved. If there is an internal server
    error or an exception occurs during the process, it will return a JSON response with an appropriate
    error message, a status
    """,
)
def get_patient_details(pay_load: dict = Depends(verify_jwt_token)):
    query = f"""
    SELECT
        email, username, dob, gender,
        rtype, education,feet,inch,weight,ssn,mobile,nationality,bloodtype,age, profile_url
    FROM
        patient_details
    WHERE
        patient_details.patient_id = '{pay_load.get("patient_id")}'
"""
    mapkey = {
        "email": "",
        "username": "",
        "dob": "",
        "gender": "",
        "rtype": "",
        "education": "",
        "feet": "",
        "inch": "",
        "weight": "",
        "ssn": "",
        "mobile": "",
        "nationality": "",
        "bloodtype": "",
        "age": "",
    }
    nationality_to_country_code = {
        "afghanistan": "AF",
        "albania": "AL",
        "algeria": "DZ",
        "american samoa": "AS",
        "andorra": "AD",
        "angola": "AO",
        "antigua and barbuda": "AG",
        "argentina": "AR",
        "armenia": "AM",
        "australia": "AU",
        "austria": "AT",
        "azerbaijan": "AZ",
        "bahamas": "BS",
        "bahrain": "BH",
        "bangladesh": "BD",
        "barbados": "BB",
        "belarus": "BY",
        "belgium": "BE",
        "belize": "BZ",
        "benin": "BJ",
        "bhutan": "BT",
        "bolivia": "BO",
        "bosnia and herzegovina": "BA",
        "botswana": "BW",
        "brazil": "BR",
        "brunei": "BN",
        "bulgaria": "BG",
        "burkina faso": "BF",
        "burundi": "BI",
        "cambodia": "KH",
        "cameroon": "CM",
        "canada": "CA",
        "cape verde": "CV",
        "central african republic": "CF",
        "chad": "TD",
        "chile": "CL",
        "china": "CN",
        "colombia": "CO",
        "comoros": "KM",
        "congo": "CG",
        "costa rica": "CR",
        "croatia": "HR",
        "cuba": "CU",
        "cyprus": "CY",
        "czech republic": "CZ",
        "denmark": "DK",
        "djibouti": "DJ",
        "dominican republic": "DO",
        "ecuador": "EC",
        "egypt": "EG",
        "el salvador": "SV",
        "equatorial guinea": "GQ",
        "eritrea": "ER",
        "estonia": "EE",
        "eswatini": "SZ",
        "ethiopia": "ET",
        "fiji": "FJ",
        "finland": "FI",
        "france": "FR",
        "gabon": "GA",
        "gambia": "GM",
        "georgia": "GE",
        "germany": "DE",
        "ghana": "GH",
        "greece": "GR",
        "grenada": "GD",
        "guatemala": "GT",
        "guinea": "GN",
        "guinea-bissau": "GW",
        "guyana": "GY",
        "haiti": "HT",
        "honduras": "HN",
        "hungary": "HU",
        "iceland": "IS",
        "india": "IN",
        "indonesia": "ID",
        "iran": "IR",
        "iraq": "IQ",
        "ireland": "IE",
        "israel": "IL",
        "italy": "IT",
        "jamaica": "JM",
        "japan": "JP",
        "jordan": "JO",
        "kazakhstan": "KZ",
        "kenya": "KE",
        "kiribati": "KI",
        "north korea": "KP",
        "south korea": "KR",
        "kuwait": "KW",
        "kyrgyzstan": "KG",
        "laos": "LA",
        "latvia": "LV",
        "lebanon": "LB",
        "lesotho": "LS",
        "liberia": "LR",
        "libya": "LY",
        "liechtenstein": "LI",
        "lithuania": "LT",
        "luxembourg": "LU",
        "madagascar": "MG",
        "malawi": "MW",
        "malaysia": "MY",
        "maldives": "MV",
        "mali": "ML",
        "malta": "MT",
        "marshall islands": "MH",
        "mauritania": "MR",
        "mauritius": "MU",
        "mexico": "MX",
        "micronesia": "FM",
        "moldova": "MD",
        "monaco": "MC",
        "mongolia": "MN",
        "montenegro": "ME",
        "morocco": "MA",
        "mozambique": "MZ",
        "myanmar": "MM",
        "namibia": "NA",
        "nauru": "NR",
        "nepal": "NP",
        "netherlands": "NL",
        "new zealand": "NZ",
        "nicaragua": "NI",
        "niger": "NE",
        "nigeria": "NG",
        "norway": "NO",
        "oman": "OM",
        "pakistan": "PK",
        "palau": "PW",
        "panama": "PA",
        "papua new guinea": "PG",
        "paraguay": "PY",
        "peru": "PE",
        "philippines": "PH",
        "poland": "PL",
        "portugal": "PT",
        "qatar": "QA",
        "romania": "RO",
        "russia": "RU",
        "rwanda": "RW",
        "saint kitts and nevis": "KN",
        "saint lucia": "LC",
        "saint vincent and the grenadines": "VC",
        "samoa": "WS",
        "san marino": "SM",
        "sao tome and principe": "ST",
        "saudi arabia": "SA",
        "senegal": "SN",
        "serbia": "RS",
        "seychelles": "SC",
        "sierra leone": "SL",
        "singapore": "SG",
        "slovakia": "SK",
        "slovenia": "SI",
        "solomon islands": "SB",
        "somalia": "SO",
        "south africa": "ZA",
        "south sudan": "SS",
        "spain": "ES",
        "sri lanka": "LK",
        "sudan": "SD",
        "suriname": "SR",
        "sweden": "SE",
        "switzerland": "CH",
        "syria": "SY",
        "taiwan": "TW",
        "tajikistan": "TJ",
        "tanzania": "TZ",
        "thailand": "TH",
        "timor-leste": "TL",
        "togo": "TG",
        "tonga": "TO",
        "trinidad and tobago": "TT",
        "tunisia": "TN",
        "turkey": "TR",
        "turkmenistan": "TM",
        "tuvalu": "TV",
        "uganda": "UG",
        "ukraine": "UA",
        "united arab emirates": "AE",
        "united kingdom": "GB",
        "united states": "US",
        "uruguay": "UY",
        "uzbekistan": "UZ",
        "vanuatu": "VU",
        "vatican city": "VA",
        "venezuela": "VE",
        "vietnam": "VN",
        "yemen": "YE",
        "zambia": "ZM",
        "zimbabwe": "ZW",
    }

    try:
        if "patient_id" in pay_load:
            session = createconnection()
            result = session.execute(text(query))
            data = result.fetchone()
            if data:
                result = (
                    session.query(PatientDetails)
                    .filter_by(patient_id=pay_load.get("patient_id"))
                    .first()
                )
                mapedresult = {
                    key: str(data[index]) if data[index] else "NA"
                    for index, key in enumerate(mapkey)
                }
                mapedresult["subscription"] = "NA"
                mapedresult["insurance_provider"] = "NA"
                mapedresult["insurance_policy_no"] = "NA"
                mapedresult["age"] = (
                    calculate_age(mapedresult["dob"])
                    if mapedresult["dob"] != "NA"
                    else 0
                )
                if mapedresult["nationality"] != "NA":
                    if (
                        mapedresult["nationality"].lower()
                        in nationality_to_country_code
                    ):
                        mapedresult["mobile_checks"] = {
                            "country_code": nationality_to_country_code[
                                mapedresult["nationality"].lower()
                            ],
                            "max_len": (
                                country_map[
                                    nationality_to_country_code[
                                        mapedresult["nationality"].lower()
                                    ]
                                ]
                                if nationality_to_country_code[
                                    mapedresult["nationality"].lower()
                                ]
                                in country_map
                                else 0
                            ),
                            "Dial_Code": dail_code[
                                nationality_to_country_code[
                                    mapedresult["nationality"].lower()
                                ]
                            ],
                        }
                    else:
                        mapedresult["mobile_checks"] = {}
                else:
                    mapedresult["mobile_checks"] = {}
                result.subscription = None
                result.insurance_provider = None
                result.insurance_policy_no = None
                total_fields = len(result.__table__.columns)
                exclude_fields = {
                    "history_progress",
                    "insuranceurl",
                    "patient_id",
                    "activestat",
                    "height",
                    "subscription",
                    "insurance_provider",
                    "insurance_policy_no",
                    "profile_url",
                }
                # non_na_fields = sum(1 for column in result.__table__.columns if column.name not in exclude_fields and getattr(result, column.name) is not None)
                # percentage_non_na = (non_na_fields / (total_fields-len(exclude_fields))) * 100
                total_fields = len(
                    [
                        column
                        for column in result.__table__.columns
                        if column.name not in exclude_fields
                    ]
                )
                non_na_fields = sum(
                    1
                    for column in result.__table__.columns
                    if column.name not in exclude_fields
                    and getattr(result, column.name) is not None
                )
                percentage_non_na = (non_na_fields / total_fields) * 100
                if (
                    mapedresult["feet"] != "NA"
                    and mapedresult["inch"] != "NA"
                    and mapedresult["weight"] != "NA"
                ):
                    # height_m = float(mapedresult["height"])/ 100
                    height = mapedresult["feet"] + "." + mapedresult["inch"]
                    height_m = float(height) * 0.3048
                    weight_lb = float(mapedresult["weight"])  # Weight in pounds
                    weight_kg = weight_lb * 0.453592
                    bmi = weight_kg / (height_m**2)
                    mapedresult["bmi"] = round(bmi, 1)
                else:
                    mapedresult["bmi"] = 0.0
                mapedresult["profile_percentage"] = round(percentage_non_na)
                if mapedresult["dob"] != "NA":
                    img_url = generate_unique_filename(
                        str(mapedresult["dob"]), pay_load.get("patient_id")
                    )
                mapedresult["profile_url"] = (
                    get_blob_sas_url(img_url) if mapedresult["dob"] != "NA" else "NA"
                )

                print(mapedresult, "patient_details------>")

                return JsonCommonStatus(
                    message="User details fetched successfully",
                    data=mapedresult,
                    statuscode=200,
                    status=True,
                )
            else:
                return JsonCommonStatus_without_data(
                    message="Internal server error", statuscode=500, status=False
                )
    except Exception as e:
        print("error in patientdetails", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.post(
    "/socialauth",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="This API is used for logging in using Google authentication.",
)
def google_auth(request: socialauth):
    req = request.model_dump()
    try:
        if "@" not in req["email"]:
            return JsonCommonStatus_without_data(
                message="Invalid email address", statuscode=400, status=False
            )
        session = createconnection()
        main = (
            session.query(PatientDetails)
            .filter_by(email=req.get("email").strip())
            .first()
        )
        if not main:
            patient_id = patient_id_generator()
            patient_details = PatientDetails(
                patient_id=patient_id,
                username=req["username"],
                email=req["email"].replace(" ", ""),
                dob=None,
                gender="NA",
                mobile=None,
                rtype="NA",
                education="NA",
                ssn="NA",
                insuranceurl="NA",
                activestat=0,
            )
            session.add(patient_details)
            session.commit()
            session.close()
            # token = create_jwt_token(
            #     data={
            #         "patient_id": patient_id,
            #         "email": req["email"],
            #         "username": req["username"],
            #     }
            # )
            return JsonCommonStatus_without_data(
                message="Your account has been created successfully. We will review it and inform you once it has been approved.",
                statuscode=201,
                status=True,
            )
        session.close()
        token = create_jwt_token(
            data={
                "patient_id": main.patient_id,
                "email": main.email,
                "username": main.username,
            }
        )

        if main.activestat == 1:
            return JsonCommonStatus(
                message="User authenticated succesfully!",
                data={"token": token},
                statuscode=200,
                status=True,
            )
        else:
            return JsonCommonStatus_without_data(
                message="Account is under review",
                statuscode=401,
                status=False,
            )
    except Exception as e:
        print("error in google_auth", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.get(
    "/feed_csv", response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data]
)
def feed_csv():
    file = open("Questionnaire_Variations_HelloAlfred.csv")
    csvreader = csv.reader(file)
    id = 1
    try:
        session = createconnection()
        for row in csvreader:
            for index, value in enumerate(row):
                if index == 0:
                    if not value == "":
                        id = value
                    if value == "":
                        break
            if row[1] == "":
                break
            query = f'insert into Ai_questions(question, group_number) values("{row[1]}","{id}");'
            session.execute(text(query))
            session.commit()
        session.close()
        return JsonCommonStatus(
            message="csv file feeded successfully", statuscode=200, status=True
        )
    except Exception as e:
        print("error feeding csv", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.post(
    "/categorizeresponse",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The function `categorize_response` processes a chat request between a doctor and a patient,
    utilizing an AI assistant to handle responses and store data in a database.

    :param request: The `request` parameter in the `categorize_response` function is of type
    `ChatRequest`. It seems to contain information related to a chat conversation between a doctor and a
    patient. The function processes this information to categorize the response provided by the patient
    :type request: ChatRequest
    :param pay_load: The `pay_load` parameter in the `categorize_response` function is used as a
    dependency to verify the JWT token. It likely contains information related to the authenticated
    user, such as their user ID or other relevant data stored in the token payload. This information is
    used to interact with the database
    :type pay_load: dict
    :return: The function `categorize_response` returns a JSON response containing a message, data,
    status code, and status boolean. The message is extracted from the response generated by the
    conversation chain. The data includes the "alfred" and "user" values from the request. The status
    code is determined based on the response received, and it is set to 99 if the `questionno` in
    """,
)
def categorize_response(
    request: ChatRequest, pay_load: dict = Depends(verify_jwt_token)
):
    try:
        user_inp = [f"Doctor: {request.alfred}", f"Patient: {request.user}"]
        llm = AzureChatOpenAI(
            api_key="d1a9d04651ec4405a1ce74ffaa8a7b57",
            api_version="2023-07-01-preview",
            azure_deployment="HA_Test",
            azure_endpoint="https://hai1.openai.azure.com/",
            temperature=0,
        )

        conversation = ConversationChain(llm=llm, memory=ConversationBufferMemory())
        conversation.prompt.template = """
        I am a doctor that is asking a behavioral questionnaire to my patient. You are an AI assistant will help me respond to the patient.

        The questionnaire requires the patient to respond to my questions with a integer from 1 to 10 corresponding to their level of agreement to the question, either in a word (ex. five) or a number (ex. 5).
        If the patient responds in the valid way, provide me with the patient's response as an integer and a thank you message like this - "[response_integer]: [thank_you_message]"
        The [thank_you_message] will be something you creatively come up with to thank the patient for answering the question and compliment them, but DO NOT ask them any follow-up questions.

        If the patient does not respond in required way, please understand their response and provide me with a response back like this - "-1: [your_message]"
        The [your_message] will be your intelligent response you come up with since the patient did not answer the question. Be kind, understanding, and answer on-topic relevant questions they may have, but try to get them to answer the question in a valid way.

        Remember to only respond back in one of the two ways above.

        Current conversation:
        {history}
        Human: {input}
        AI:
        """

        ingestion_string = f"""
        The following is the most recent response between the doctor and the patient. Please help me respond in one of the two ways I've prompted you with.

        A patient that says they 'agree', 'disagree', 'somewhat agree' is not allowed. It is valid to use to word for the numerical value though, ie. 'two', 'three', etc.

        Remember if you have a [thank_you_message], you can compliment the patient, but do not include any follow-questions in the response you provide me.

        {user_inp}
        """

        response = conversation.invoke(ingestion_string)["response"]
        temp = response.split(":")
        data = {"alfred": request.alfred, "user": request.user}
        if temp[0] != "-1":
            session = createconnection()
            session.execute(
                text(
                    f'INSERT INTO secondary_chatbot (patient_id, ctimestamp, message, rating) VALUES ("{pay_load["patient_id"]}", "{pd.Timestamp("now").strftime("%Y-%m-%d %H:%M:%S")}", "{str(request.alfred)}", {temp[0]})'
                )
            )
            session.commit()
        return JsonCommonStatus(
            message=temp[1],
            data=data,
            statuscode=int(temp[0]) if request.questionno != 17 else 99,
            status=True,
        )
    except Exception as e:
        print("error in categorizeresponse", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.get(
    "/chatbot_questions",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The function `chatbotquestion` retrieves unanswered questions from a database table and returns them
    along with a success message.
    :return: The function `chatbotquestion()` returns a JSON response object containing a message, data,
    status code, and status boolean value. The message indicates whether the chatbot questions were
    retrieved successfully or if there are no remaining unanswered questions. The data field contains
    the retrieved questions grouped by group number. The status code is set to 200 for successful
    retrieval and 500 for internal server errors. The status boolean
    """,
)
def chatbotquestion():
    try:
        query = "select group_number, question from ai_questions;"
        session = createconnection()
        result = session.execute(text(query))
        session.close()
        data = {}
        final_data = []
        for row in result:
            group_number, question = row
            if group_number not in data:
                data[group_number] = []
            data[group_number].append(question)
        for datasd in data.values():
            final_data.append(datasd)
        if len(final_data) > 0:
            message = "Chatbot questions retrieved successfully"
        else:
            message = " There are no remaining unanswered questions from the user."
        return JsonCommonStatus(
            message=message,
            data=final_data if len(final_data) > 0 else [],
            statuscode=200,
            status=True,
        )
    except Exception as e:
        print("error in catbot_questions---------", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.post(
    "/setstatus",
    response_model=JsonCommonStatus_without_data,
    description="""
    This Python function updates the progress status of a patient's health details based on the provided
    input.
    :param req: The `req` parameter in the `mainscreenstatus` function seems to be an instance of the
    `healthdetailsui` class. This parameter is used to extract data from the model using the
    `model_dump()` method
    :type req: healthdetailsui
    :param pay_load: The `pay_load` parameter in the `mainscreenstatus` function seems to be used to
    extract the patient ID from a JWT token. This patient ID is then used in the database query to fetch
    and update the progress status for the patient in the `introstatus` table. The `pay
    :type pay_load: dict
    :return: The function `mainscreenstatus` returns a JSON response with a message indicating the
    status of the operation, a status code, and a boolean status value. The specific message returned
    depends on the outcome of the function execution, such as whether the parameters are valid, the
    entity was successfully updated, or if there was an internal server error.
    """,
)
def mainscreenstatus(req: healthdetailsui, pay_load: dict = Depends(verify_jwt_token)):
    try:
        request = req.model_dump()
        validate = [
            "health_hub",
            "expert_monitoring",
            "list_your_symptoms",
            "lifestyle_goals",
            "optimal_risk_managemment",
        ]
        if any(key not in validate for key in request.keys()):
            return JsonCommonStatus_without_data(
                message="invalid parameter", statuscode=400, status=False
            )
        session = createconnection()
        result = (
            session.query(introstate)
            .where(
                introstate.patient_id == pay_load.get("patient_id"),
                introstate.cdate == pd.Timestamp("now").date().strftime("%Y-%m-%d %X"),
            )
            .first()
        )
        if result:
            updated_progress = result.progress
            for key in request.keys():
                if request[key] is not None:
                    updated_progress[key] = request[key]
            update_query = (
                update(introstate)
                .where(
                    introstate.patient_id == pay_load.get("patient_id"),
                    introstate.cdate == datetime.now().date(),
                )
                .values({"progress": updated_progress})
            )
            session.execute(update_query)
            session.commit()
            session.close()
            return JsonCommonStatus_without_data(
                message=f"{' '.join([key if request[key] is not None else '' for key in request.keys()]).strip()} updated successfully",
                statuscode=200,
                status=True,
            )
        else:
            return JsonCommonStatus_without_data(
                message="Unable to proccess the entity", statuscode=200, status=True
            )
    except Exception as e:
        print("error in setstatus", str(e))
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.get(
    "/getstatus",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    This function retrieves the main screen status for a patient based on their ID, updating it if more
    than 24 hours have passed since the last update.

    :param pay_load: The `pay_load` parameter in the `getmainscreenstatus` function seems to be a
    dictionary containing information about the patient obtained by verifying a JWT token. This payload
    likely includes the patient's ID among other details necessary for fetching the main screen status
    :type pay_load: dict
    :return: The function `getmainscreenstatus` returns a JSON response with a message, data, status
    code, and status boolean value. The specific return values are as follows:
    """,
)
def getmainscreenstatus(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        query = (
            session.query(introstate)
            .where(introstate.patient_id == pay_load["patient_id"])
            .first()
        )
        if query:
            current_timestamp = pd.Timestamp("now")
            time_difference = current_timestamp - query.cdate
            time_difference_hours = time_difference.total_seconds() / 3600
            if time_difference_hours > 24:
                moddata = {}
                for keys in query.progress.keys():
                    moddata[keys] = 0
                print("------------------ moddata[keys]----------", query.progress)
                query = (
                    update(introstate)
                    .where(introstate.patient_id == pay_load.get("patient_id"))
                    .values(
                        {
                            "progress": moddata,
                            "cdate": pd.Timestamp("now").date().strftime("%Y-%m-%d %X"),
                        }
                    )
                )
                session.execute(query)
                session.commit()
                session.close()
                return JsonCommonStatus(
                    message="status fetched successfully",
                    data=moddata,
                    statuscode=200,
                    status=True,
                )
            else:
                print("------------------resutlt[2]----------", type(query.progress))
                return JsonCommonStatus(
                    message="status fetched successfully",
                    data=query.progress,
                    statuscode=200,
                    status=True,
                )
        else:
            default_value = {
                "health_hub": 0,
                "expert_monitoring": 0,
                "list_your_symptoms": 0,
                "lifestyle_goals": 0,
                "optimal_risk_managemment": 0,
            }
            insert_query = introstate(
                patient_id=pay_load.get("patient_id"),
                cdate=pd.Timestamp("now").date().strftime("%Y-%m-%d %X"),
                progress=default_value,
            )
            session.add(insert_query)
            session.commit()
            session.close()
            return JsonCommonStatus(
                message="status fetched successfully",
                data=default_value,
                statuscode=200,
                status=True,
            )
    except Exception as e:
        print("error in get status---", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.get(
    "/get_chat_history",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    This function retrieves chat history progress and questions for a patient, excluding those already
    answered, and returns the data in a serialized format.
    :param pay_load: The `pay_load` parameter in the `get_chat_history` function is expected to be a
    dictionary containing information extracted from a JWT token. It is used to verify the JWT token and
    retrieve the `patient_id` from it. This `patient_id` is then used to query the database for the
    :type pay_load: dict
    :return: The function `get_chat_history` is returning a JSON response with the following structure:
    - message: "History fetched successfully" if successful, or "Internal server error" if there is an
    exception
    - data: Serialized output containing history questions fetched from the database
    - statuscode: 200 if successful, or 500 if there is an exception
    - status: True if successful, False if
    """,
)
def get_chat_history(pay_load: dict = Depends(verify_jwt_token)):
    try:
        query = f"Select history_progress from patient_details where patient_id = '{pay_load.get('patient_id')}'"
        session = createconnection()
        result = session.execute(text(query)).fetchone()
        get_question = session.query(history_question).all()

        def serialize(model_instance):
            return {
                c.name: getattr(model_instance, c.name)
                for c in model_instance.__table__.columns
            }

        output = (
            get_question
            if result[0] is None
            else [data for data in get_question if data.question_key not in result[0]]
        )
        serialized_output = [serialize(question) for question in output]
        session.close()
        return JsonCommonStatus(
            message="History fetched successfully",
            data=serialized_output,
            statuscode=200,
            status=True,
        )
    except Exception as e:
        print("error in get_chat_history------", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.post(
    "/preference_chat",
    description="""
    This Python function handles storing or updating user preferences in a database based on the
    provided request and user authentication token.
    :param req: The `req` parameter in the `preference_chat` function appears to be of type
    `request_preferanceSchema`, which likely contains information related to a user's preference for a
    chat session. This parameter is used to retrieve and update preferences for a specific patient based
    on the provided `patient_id
    :type req: request_preferanceSchema
    :param pay_load: The `pay_load` parameter in the `preference_chat` function seems to be using a JWT
    token for authentication. It is likely used to verify the user's identity and access rights before
    allowing them to update their preferences in the chat system. The `verify_jwt_token` function is
    probably responsible for
    :type pay_load: dict
    :return: The function `preference_chat` is returning a JSON response with a message indicating
    whether the preference was noted or updated successfully, along with a status code and a boolean
    status value. If an error occurs during the process, it will return a message indicating an internal
    server error, along with a status code and a status value of False.
    """,
)
# def preference_chat(req:request_preferanceSchema):
#  response_model=JsonCommonStatus_without_data,
def preference_chat(head: Request, req: request_preferanceSchema):
    SECRET_KEY = client.get_secret("SECRET_KEY").value
    ALGORITHM = client.get_secret("ALGORITHM").value
    headers = head.headers
    authorization_header = headers.get("authorization")
    if authorization_header is not None:
        auth_type, token = authorization_header.split()
        if auth_type.lower() == "bearer":
            pay_load = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            try:
                session = createconnection()
                result = (
                    session.query(preferanceSchema)
                    .filter_by(
                        patient_id=pay_load.get("patient_id"), message=req.message
                    )
                    .first()
                )
                if not result:
                    new_preference = preferanceSchema(
                        message=req.message.strip(),
                        patient_id=pay_load.get("patient_id"),
                        preference=req.preference,
                    )
                    session.add(new_preference)
                else:
                    result.preference = req.preference
                session.commit()
                session.close()
                return JsonCommonStatus_without_data(
                    message=(
                        "Preference noted successfully"
                        if not result
                        else "Preference updated successfully"
                    ),
                    statuscode=200,
                    status=True,
                )
            except Exception as e:
                print("error in preference api -------------", e)
                return JsonCommonStatus_without_data(
                    message="internal server error",
                    statuscode=500,
                    status=False,
                    data=None,
                )
        else:
            raise HTTPException(
                status_code=401, detail="Invalid authorization scheme. Must be Bearer"
            )
    else:
        try:
            # if not req.patient_id:
            #     return JsonCommonStatus_without_data(message = "patient_id is required",statuscode = 404, status=False)
            session = createconnection()
            unknown_user = (
                session.query(PatientDetails)
                .filter_by(patient_id="1234-9876-54321")
                .first()
            )
            if not unknown_user:
                patient_details = PatientDetails(
                    patient_id="1234-9876-54321",
                    username=None,
                    email=None,
                    dob=None,
                    gender=None,
                    mobile=None,
                    rtype=None,
                    education=None,
                    ssn=None,
                    insuranceurl=None,
                    activestat=1,
                )
                session.add(patient_details)
                session.commit()
                session.close()

            result = (
                session.query(preferanceSchema)
                .filter_by(patient_id="1234-9876-54321", message=req.message)
                .first()
            )
            if not result:
                new_preference = preferanceSchema(
                    message=req.message.strip(),
                    patient_id="1234-9876-54321",
                    preference=req.preference,
                )
                session.add(new_preference)
            else:
                result.preference = req.preference
            session.commit()
            session.close()
            return JsonCommonStatus_without_data(
                message=(
                    "Preference noted successfully"
                    if not result
                    else "Preference updated successfully"
                ),
                statuscode=200,
                status=True,
            )
        except Exception as e:
            print("error in preference api -------------", e)
            return JsonCommonStatus_without_data(
                message="internal server error", statuscode=500, status=False, data=None
            )


@fastapi_app.post(
    "/preference_chat_admin",
    response_model=JsonCommonStatus_without_data,
    description="""
    This function handles admin preferences in a chat application by storing or updating them in a
    database.
    :param req: The `req` parameter in the `preference_chat_admin` function is of type
    `request_preferanceSchema`. the parameter is used to pass some request data related
    to admin preferences
    :type req: request_preferanceSchema
    :param pay_load: The `pay_load` parameter in the `preference_chat_admin` function is useded
    for verifying a JWT token. and the `verify_jwt_token` function is a dependency that
    checks the validity of the JWT token provided in the request. The `pay_load` parameter is expected
    :type pay_load: dict
    :return: The function `preference_chat_admin` is returning a JSON response using the
    `JsonCommonStatus_without_data` function. The response includes a message indicating whether the
    preference was noted successfully or updated successfully, a status code of 200 for success or 500
    for internal server error, and a boolean status value.
    """,
)
def preference_chat_admin(
    req: request_preferanceSchema, pay_load: dict = Depends(verify_jwt_token)
):
    try:
        session = createconnection()
        result = (
            session.query(preferanceSchemaAdmin)
            .filter_by(user_id=pay_load.get("user_id"), message=req.message)
            .first()
        )
        if not result:
            new_preference = preferanceSchemaAdmin(
                message=req.message.strip(),
                user_id=pay_load.get("user_id"),
                preference=req.preference,
            )
            session.add(new_preference)
        else:
            result.preference = req.preference
        session.commit()
        session.close()
        return JsonCommonStatus_without_data(
            message=(
                "Preference noted successfully"
                if not result
                else "Preference updated successfully"
            ),
            statuscode=200,
            status=True,
        )
    except Exception as e:
        print("error in preference api -------------", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.post(
    "/preference_chat_unknown",
    response_model=JsonCommonStatus_without_data,
    description="""
    This Python function handles storing or updating user preferences in a database based on the
    provided request and user authentication token.
    :param req: The `req` parameter in the `preference_chat` function appears to be of type
    `request_preferanceSchema`, which likely contains information related to a user's preference for a
    chat session. This parameter is used to retrieve and update preferences for a specific patient based
    on the provided `patient_id
    :type req: request_preferanceSchema
    :param pay_load: The `pay_load` parameter in the `preference_chat` function seems to be using a JWT
    token for authentication. It is likely used to verify the user's identity and access rights before
    allowing them to update their preferences in the chat system. The `verify_jwt_token` function is
    probably responsible for
    :type pay_load: dict
    :return: The function `preference_chat` is returning a JSON response with a message indicating
    whether the preference was noted or updated successfully, along with a status code and a boolean
    status value. If an error occurs during the process, it will return a message indicating an internal
    server error, along with a status code and a status value of False.
    """,
)
def preference_chat_home_screen(req: request_preferanceSchema):
    try:
        session = createconnection()
        result = (
            session.query(preferanceSchema)
            .filter_by(patient_id="1234-9876-54321", message=req.message)
            .first()
        )
        if not result:
            new_preference = preferanceSchema(
                message=req.message.strip(),
                patient_id="1234-9876-54321",
                preference=req.preference,
            )
            session.add(new_preference)
        else:
            result.preference = req.preference
        session.commit()
        session.close()
        return JsonCommonStatus_without_data(
            message=(
                "Preference noted successfully"
                if not result
                else "Preference updated successfully"
            ),
            statuscode=200,
            status=True,
        )
    except Exception as e:
        print("error in preference api -------------", e)
        return JsonCommonStatus_without_data(
            message="internal server error", statuscode=500, status=False, data=None
        )


@fastapi_app.post(
    "/history_answer",
    description="""
    The `preference_commend` function handles processing user responses in a chat bot iteration,
    categorizing responses, generating appropriate AI assistant responses, and updating database records
    accordingly.
    :param req: The `req` parameter in the `preference_commend` function seems to be an object of type
    `chat_bot_iteration`. It is used to gather information related to a chat bot iteration, such as
    question key, user message, main type, and answer category. The function appears to handle
    processing
    :type req: chat_bot_iteration
    :param payload: The `payload` parameter in the `preference_commend` function is used as a dependency
    to verify the JWT token. It is likely used to authenticate and authorize the user making the request
    by checking the validity of the JWT token provided in the request headers. This helps ensure that
    the user has the
    :type payload: dict
    :return: This function `preference_commend` takes in a request object `req` and a payload
    dictionary, verifies the JWT token, categorizes the response history of a chatbot, adds
    functionality based on question keys, gives sympathetic responses, and handles database operations
    related to patient history answers.
    """,
)
def preference_commend(
    req: chat_bot_iteration, payload: dict = Depends(verify_jwt_token)
):
    try:

        def categorize_response_historybot(chat_history, type_, ans_categ):
            llm = AzureChatOpenAI(
                api_key="d1a9d04651ec4405a1ce74ffaa8a7b57",
                api_version="2023-07-01-preview",
                azure_deployment="HA_Test",
                azure_endpoint="https://hai1.openai.azure.com/",
                temperature=0,
            )
            conversation = ConversationChain(llm=llm, memory=ConversationBufferMemory())
            conversation.prompt.template = (
                """
                    I am a doctor who is asking a question to gather the medical history of my patient. You are an AI assistant will help me respond to the patient and understand his response.

                    This question requires the patient to respond with a """
                + type_
                + """ type you should analyze if his answer makes sense with respect to """
                + chat_history[0]
                + """ + Specially try to use + """
                + ans_categ
                + """ for understanding type of answer you should extract,If you get the correct answer provide me with response_integer 1 as an integer and a thank you message like this - "[response_integer]: [Interpreted_Answer],[what did answer pointed at choose form yes or no
                    ]". Interpreted_Answer will be the user input converted into type as per  """
                + ans_categ
                + """ Don't add any kind of words or supporting things in the start or end of interpreted answer

                    If the patient's a response is not in required way or doesn't makes sense w.r.t """
                + str(chat_history[0])
                + """, please understand their response and provide me with a response back like this - "-1: [your_message],[what did answer pointed at choose form yes or no]", The [your_message] will be your intelligent response you come up with since the patient did not answer the question. Be kind, understanding, and answer on-topic relevant questions they may have, but try to get them to answer the question in a valid way.

                    When a patient responds with "IDK" or hesitates to answer a healthcare question, respond compassionately, urging them to share while emphasizing the importance of progress and confidentiality. If they persist in not answering or give an inappropriate response, continue to empathize and prompt, always returning a status code of '-1' for incorrect or irrelevant answers.

                    MOST IMPORTANT THING IS TO NOT ASK ANY FOLLOW UP QUESTIONS. Parse the answer if you can else just raise error, DONT ASK FOR ANY CONFIRMATION OF PARSED RESPONSE JUST GIVE WHATVER YOU GET!!!
                    I NEED YOU TO STRICTLY FOLLOW THE RETURN TYPE IT WILL BE \"[RESPONSE CODE] : [Interpreted_Answer],[what did answer pointed at choose form yes or no] FOLLOW ON THIS STRUCTURE ANYWAY
                    IN FEW CASE """
                + ans_categ
                + """ will mention you to parse DAYS, WEEKS or MONTHS in the response. If you are able to get suitable answer please put did_you_got_answer_not as yes
                    ONE IMPORTANT RULE Remember when you are generating your [Interpreted_Answer], It should only contain the answer of the question no supporting verbs or character should  be added to ans only direct ans should be given
                    Create a date formatting utility that ensures all entered dates are consistently formatted as DD/MM/YYYY. If the user provides only the month and year, the output should default to the 1st day of the given month. The program should strictly adhere to this date formatting rule.

                    If the input answer of the user is not wrong use """
                + ans_categ
                + """ To generate example of how to answer and return that "-1: [Example_response_type],[what did answer pointed at choose form yes or no]"

                    Current conversation:
                    "{history}'
                    Human: {input}
                    AI:
                """
            )

            ingestion_string = f"""
                The following is the most recent response between the doctor and the patient. Please help me respond in one of the two ways I've prompted you with.

                A patient that says random things w.r.t context is not allowed. It is valid to explain the answer in point or broken english but it should make sense.

                Remember you have to interpret an answer and return the interpreted answer via [Interpreted_Answer], Also do remember the type of ans will be specified in [ans_categ].

                {chat_history}
                """
            # print("reached here")
            ans = conversation.invoke(ingestion_string)["response"]
            # print(ans)
            return ans

        to_skip_key = [
            "frequency_of_weakness",
            "frequency_of_breathing",
            "frequency_of_tiredness",
            "frequency_of_chestpain",
            "frequency_of_breathlessness",
            "frequency_of_diziness",
            "frequency_of_coldsweats",
            "frequency_of_anxiety",
            "frequency_of_decreased_exercise",
            "frequency_of_palpitations",
            "frequency_of_rapid_heart_rate",
            "frequency_of_irregular_heart_rate",
            "frequency_of_harder_beats",
            "frequency_of_missed_beats",
        ]

        def add_func(start_key, user_input):
            listOfYes = [
                "arthymia_qolife",
                "frequency_acquaintances",
                "frequency_concentration",
                "frequency_fear_of_dying",
                "frequency_irritation",
                "frequency_life_satisfaction",
                "frequency_low_mood",
                "frequency_of_anxiety",
                "frequency_of_breathing",
                "frequency_of_breathlessness",
                "frequency_of_chestpain",
                "frequency_of_coldsweats",
                "frequency_of_decreased_exercise",
                "frequency_of_diziness",
                "frequency_of_harder_beats",
                "frequency_of_irregular_heart_rate",
                "frequency_of_missed_beats",
                "frequency_of_palpitations",
                "frequency_of_rapid_heart_rate",
                "frequency_of_tiredness",
                "frequency_of_weakness",
                "frequency_physical_ability",
                "frequency_planning_activities",
                "frequency_sexual_life",
                "frequency_sleep_prob",
                "frequency_social_relationships",
                "frequency_unable_to_walk",
                "frequency_worried_of_recurring",
                "skipping_frequency",
            ]

            if start_key in listOfYes:
                user_input = "I get it " + user_input
            if start_key == "AF_episodes":
                user_input = "I get it " + user_input
            if start_key == "monitor_key":
                user_input = "He told me " + user_input
            if (
                start_key in to_skip_key
                or start_key == "physical_activity"
                or start_key == "liver_test_selection"
                or start_key == "location"
                or start_key == "bot_diagnosis"
                or start_key == "kidney_test_selection"
                or start_key == "cardiac_AF"
                or start_key == "AAD_AF"
                or start_key == "AntiAAD_AF"
            ):
                user_input = 'it is "' + user_input + '"'
            if start_key == "AAD_AF":
                user_input = '"' + user_input + '"'
            if start_key == "CIED":
                user_input = 'I am using "' + user_input + '"'
            if start_key == "type":
                user_input = 'It was of type:- "' + user_input + '"'
            if start_key == "type_of_anxiety":
                user_input = 'I have "' + user_input + '"'

        def give_sympathic_response(question, answer):
            llm = AzureChatOpenAI(
                api_key="d1a9d04651ec4405a1ce74ffaa8a7b57",
                api_version="2023-07-01-preview",
                azure_deployment="HA_Test",
                azure_endpoint="https://hai1.openai.azure.com/",
                temperature=0,
            )

            conversation = ConversationChain(llm=llm, memory=ConversationBufferMemory())

            conversation.prompt.template = f""" You are an AI assistant conducting a history questionnaire with a patient in the absence of a doctor. Your role is to acknowledge all the replies given by the patient and provide specific responses based on the following guideline:

                                        Frequency of Symptoms:
                                        STRICTLY REMEMBER If the patient’s response involves the frequency of any kind of symptom, respond with:
                                            "I am sorry to hear that. I will let your healthcare provider know about your symptoms."
                                        In the same fashion, If you think he responds he don't has a symptoms. Reply with
                                            "Good to hear. Thank You"
                                        When he tells you his name, Just ackanowledge

                                        If he is answering a {question} which is asking about when did he got diagnose or informed about disease, based on his {answer} respond with a sorry message
                                        Example:

                                        Patient's Response: "I have been having headaches almost every day."
                                        Your Response: "I am sorry to hear that. I will let your healthcare provider know about your symptoms."

                                        Question: Do you have symptoms of afib?
                                        Patient's Response: "No"
                                        Your Response: "Glad to hear, you don't have symptoms of Afib"
                                        Remember, you cannot suggest, ask, or confirm any kind of medical advice. Your responses should strictly adhere to acknowledging the patient’s replies and following the specific response guideline provided.

                                        STRICTLY DON'T ASK HIM ANY FOLLOW-UP Message or ANY KIND OF QUESTION FROM YOUR END, Just acknowledge and thank him for sharing response
                                        Conversation:

                                        Question: {question}
                                        Answer: {answer}
                                        Your Response:
                                        """

            ingestion_string = f"The question asked by you is {question} and the answer given by the patient is {answer}. Generate the message as per above guidlines. STRICTLY REMEMBER TO NOT ASK FOLLOW UP QUESTION"
            ans = conversation.invoke(ingestion_string)["response"]
            return ans

        keys_to_skip = [
            "initial_question",
            "without_treatment",
            "weakness_shootup",
            "breathing_key",
            "tiredness_key",
            "chestpain_key",
            "breathlessness_at_rest_key",
            "diziness_key",
            "coldsweats_key",
            "anxiety_key",
            "exercise_key",
            "irregular_heartrate",
            "palpitations",
            "rapid_heart_rate",
            "irregular_heart_rate",
            "harder_beats",
            "missed_beats",
            "continue_medical_assistant",
            "continue_bloodpressure_medical_assistant",
            "continue_bloodpressure_medical_att",
            "continue_bloodpressure_medical_low",
            "Continue_chest_pain",
            "fibrilliaton_episodes",
            "anxiety",
            "quality_of_life",
            "scenario",
            "admitted",
            "days",
            "lasted_long_enough",
            "unable_to_walk",
            "social_relationship",
            "acquaintance",
            "planning_activities",
            "skipping_things",
            "sexual_life",
            "life_satisfaction",
            "concentration_ability",
            "low_mood",
            "irritation",
            "sleep_prob",
            "fear_of_dying",
            "worried_of_recurring",
            "medication_type",
            "medication_AAD",
            "medication_ANT",
            "valve_replacement",
            "side_effect",
            "ablation",
            "",
        ]

        session = createconnection()
        timestamp = pd.Timestamp("now")
        # user_input = add_func(req.question_key, req.user_message)  ##Needs to be checked Hemang
        out = categorize_response_historybot(
            [req.question, req.user_message], req.main_type, req.ans_categ
        )
        out_splited = out.split(":")
        get_chat_answer = (
            session.query(history_chatbot_answers)
            .filter_by(
                patient_id=payload.get("patient_id"), question_id=req.question_key
            )
            .first()
        )
        """
        Table:-
            patient_id
            question_key -> Json
            answer

        Status_code -> -1
            213213   trial: 1    {"trial": ["sanas",]}
        """
        bypassquery = (
            session.query(history_bypass)
            .filter(
                history_bypass.patient_id == payload.get("patient_id"),
                history_bypass.question_key == req.question_key,
            )
            .first()
        )

        if int("".join(re.findall(r"-?\d+", out_splited[0]))) == -1:
            if not bypassquery:
                arrdata = [req.user_message]
                first_record = history_bypass(
                    patient_id=payload.get("patient_id"),
                    question_key=req.question_key,
                    count=1,
                    answer={req.question_key: json.dumps(arrdata)},
                )
                session.add(first_record)
                session.commit()
                getquery = (
                    session.query(history_question)
                    .filter_by(question_key=req.question_key)
                    .first()
                )
                if getquery:
                    question_dict = {
                        column.name: getattr(getquery, column.name)
                        for column in getquery.__table__.columns
                    }
                    session.close()
                    return JsonCommonStatus(
                        message=out_splited[1],
                        data=question_dict,
                        statuscode=-1,
                        status=True,
                    )
                session.close()
                return JsonCommonStatus(
                    message="Question key error",
                    data={},
                    statuscode=status.HTTP_404_NOT_FOUND,
                    status=False,
                )
            else:
                if bypassquery.count == 1:
                    getquery = (
                        session.query(history_question)
                        .filter_by(question_key=req.question_key)
                        .first()
                    )
                    if getquery:
                        answerarr = json.loads(bypassquery.answer.get(req.question_key))
                        answerarr.append(req.user_message)
                        # append_data = {req.question_key: json.dumps(arrdata)}
                        # print("----------->appended answer",append_data)
                        print("----------->appended answerarr", answerarr)
                        update_query = (
                            update(history_bypass)
                            .where(
                                history_bypass.patient_id == payload.get("patient_id"),
                                history_bypass.question_key == req.question_key,
                            )
                            .values(
                                count=bypassquery.count + 1,
                                answer={req.question_key: json.dumps(answerarr)},
                            )
                        )
                        session.execute(update_query)
                        session.commit()
                        question_dict = {
                            column.name: getattr(getquery, column.name)
                            for column in getquery.__table__.columns
                        }
                        session.close()
                        return JsonCommonStatus(
                            message=out_splited[1],
                            data=question_dict,
                            statuscode=-1,
                            status=True,
                        )
                    session.close()
                    return JsonCommonStatus(
                        message="Question key error",
                        data={},
                        statuscode=status.HTTP_404_NOT_FOUND,
                        status=False,
                    )

                else:
                    if "yes" in req.user_message:
                        if req.main_type == "boolean":
                            out_splited[1] = "yes, yes"
                        else:
                            try:
                                temp_split = out_splited[1].split(",")
                                temp_split[0] = temp_split[0].replace(" ", "")
                                out_splited[1] = temp_split[0] + ",yes"
                            except Exception as e:
                                print(e, "--Error Line 1895 History Bot")
                                out_splited[1] += ",yes"
                    else:
                        if req.main_type == "boolean":
                            out_splited[1] = "no, no"
                        else:
                            try:
                                temp_split = out_splited[1].split(",")
                                temp_split[0] = temp_split[0].replace(" ", "")
                                out_splited[1] = temp_split[0] + ",no"
                            except Exception as e:
                                print(e, "---Error Line 1906 History Bot")
                                out_splited[1] += ",no"
            # out_splited[1] = "yes, yes"
            # getquery = session.query(history_question).filter_by(question_key=req.question_key).first()
            # if getquery:
            #     question_dict = {column.name: getattr(getquery, column.name) for column in getquery.__table__.columns}
            #     return JsonCommonStatus(message=out_splited[1], data=question_dict, statuscode=-1, status=True)
            # return JsonCommonStatus(message="Question key error", data={}, statuscode=status.HTTP_404_NOT_FOUND, status=False)

        print("out_splited[1]", out_splited)
        temp_split = out_splited[1].split(",")
        temp_split[0] = temp_split[0].replace(" ", "")
        temp_split[1] = temp_split[1].replace(" ", "")
        print("--=-tempsplit-----------------", out_splited)
        point_list = [
            "blood_pressure_medications",
            "age_above_75",
            "gender_female",
            "diabetes_melitus",
            "vascular_disease",
            "stroke_mini_stroke",
            "diabetes_treatment",
        ]

        if (temp_split[0].lower() != "no") or (temp_split[1].lower() != "no"):
            query = f"SELECT yes FROM question_table WHERE question_key='{req.question_key}'"
            data = session.execute(text(query)).fetchone()
            for val in data:
                start_key = val
            if req.question_key in point_list:
                fetch_CHADS2VA2SC = (
                    session.query(history_chatbot_answers)
                    .filter_by(
                        question_id="CHADS2VA2SC", patient_id=payload["patient_id"]
                    )
                    .first()
                )
                if fetch_CHADS2VA2SC:
                    score = fetch_CHADS2VA2SC.answer
                    if req.question_key == "age_above_75":
                        fetch_CHADS2VA2SC.answer = str(int(score) + 2)
                    else:
                        fetch_CHADS2VA2SC.answer = str(int(score) + 1)
                    session.commit()
                else:
                    new_answer = history_chatbot_answers(
                        patient_id=payload.get("patient_id"),
                        question_id="CHADS2VA2SC",
                        answer="1",
                        ctimestamp=timestamp.strftime("%Y-%m-%d %X"),
                    )
                    session.add(new_answer)
                session.commit()
        else:
            query = (
                f"SELECT no FROM question_table WHERE question_key='{req.question_key}'"
            )
            data = session.execute(text(query)).fetchone()
            for val in data:
                start_key = val

        getquestions = (
            session.query(history_question).filter_by(question_key=start_key).first()
        )
        updation = (
            session.query(PatientDetails)
            .filter_by(patient_id=payload.get("patient_id"))
            .first()
        )
        if get_chat_answer is None:
            new_answer = history_chatbot_answers(
                patient_id=payload.get("patient_id"),
                question_id=req.question_key.strip(),
                answer=req.user_message.strip(),
                ctimestamp=timestamp.strftime("%Y-%m-%d %X"),
            )
            if updation.history_progress is not None:
                details = json.loads(updation.history_progress)
                details.append(req.question_key)
                update_query = (
                    update(PatientDetails)
                    .values({"history_progress": json.dumps(details)})
                    .where(PatientDetails.patient_id == payload["patient_id"])
                )
                session.execute(update_query)
            else:
                listdata = [req.question_key]

                update_query = (
                    update(PatientDetails)
                    .values({"history_progress": json.dumps(listdata)})
                    .where(PatientDetails.patient_id == payload["patient_id"])
                )
                session.execute(update_query)
            session.add(new_answer)
        else:
            if updation.history_progress is not None:
                details = json.loads(updation.history_progress)
                if req.question_key not in details:
                    details.append(req.question_key)
                    update_query = (
                        update(PatientDetails)
                        .values({"history_progress": json.dumps(details)})
                        .where(PatientDetails.patient_id == payload["patient_id"])
                    )
                    session.execute(update_query)
            else:
                listdata = [req.question_key]
                update_query = (
                    update(PatientDetails)
                    .values({"history_progress": json.dumps(listdata)})
                    .where(PatientDetails.patient_id == payload["patient_id"])
                )
                session.execute(update_query)
            get_chat_answer.answer = req.user_message
            get_chat_answer.ctimestamp = timestamp.strftime("%Y-%m-%d %X")
        session.commit()
        if getquestions:
            question_dict = {
                column.name: getattr(getquestions, column.name)
                for column in getquestions.__table__.columns
            }
            question_dict["options"] = json.loads(getquestions.options)
            if start_key not in keys_to_skip:
                return JsonCommonStatus(
                    message=(
                        give_sympathic_response(req.question, temp_split[0].lower())
                        if start_key not in keys_to_skip
                        and ("911" not in req.question_key)
                        else "Okay! Calling 911..."
                    ),
                    data=question_dict,
                    statuscode=status.HTTP_200_OK,
                    status=True,
                )
            else:
                return JsonCommonStatus(
                    message="",
                    data=question_dict,
                    statuscode=status.HTTP_200_OK,
                    status=True,
                )
        if start_key == "quit":
            return JsonCommonStatus_without_data(
                message="Thank you for answering all the questions.",
                statuscode=99,
                status=True,
            )
        return JsonCommonStatus(
            message="no question found",
            data={},
            statuscode=status.HTTP_404_NOT_FOUND,
            status=False,
        )
    except Exception as e:
        print("error in history_answer api -------------", e)
        return JsonCommonStatus_without_data(
            message="internal server error", statuscode=500, status=False, data=None
        )


@fastapi_app.get(
    "/show_accounts",
    response_model=Union[JsonCommonStatus_without_data, JsonCommonStatus],
    description="""
    The function `show_account` retrieves account details based on specified criteria from a database
    table and returns the results in a structured format.

    :param req: The `req` parameter in the `show_account` function is an optional dictionary that can be
    passed as a request body. It contains information that can be used to filter the accounts to be
    displayed. If the "password" key is present in the `req` dictionary, the function will return a
    :type req: Optional[dict]
    :param pay_load: The `pay_load` parameter in the `show_account` function is using the `Depends`
    dependency from FastAPI. It is likely being used to verify the JWT token for authentication and
    authorization purposes. The `verify_jwt_token` function is expected to handle the verification of
    the JWT token and return
    :type pay_load: dict
    :return: The function `show_account` is returning a JSON response with the following structure:
    - If the request body contains a "password" key, it returns a JSON response indicating that accounts
    cannot be viewed based on the password.
    - It constructs a SQL query based on the request body parameters to fetch data from the
    "patient_details" table.
    - It processes the query results, converts date format, and constructs
    """,
)
def show_account(req: Optional[dict] = {}, pay_load: dict = Depends(verify_jwt_token)):
    valdata = {
        "username": "",
        "email": "",
        "d.o.b": "",
        "gender": "",
        "mobile": "",
        "residenttype": "",
        "education": "",
        "ssn": "",
        "insurance": "",
        "patientid": "",
        "accoutstatus": "",
    }
    req_body = req
    if "password" in req_body.keys():
        return JsonCommonStatus_without_data(
            message="Can not view accounts on the basis of Password.",
            statuscode=400,
            status=False,
        )
    main_query = "SELECT * FROM patient_details"
    if len(req_body) > 0:
        for cn, key_ in enumerate(req_body.keys()):
            if key_ == "activestat":
                main_query += f" AND {key_} = {req_body[key_]}"
                continue
            main_query += f" AND {key_} = '{req_body[key_]}'"
    main_query += ";"
    try:
        session = createconnection()
        out = []
        results = session.execute(text(main_query))
        for row in results:
            row = list(row)
            row[2] = pd.to_datetime(row[2]).strftime("%Y-%m-%d") if row[2] else None
            result = {
                key: row[index] if row[index] else "NA"
                for index, key in enumerate(valdata.keys())
            }
            out.append(result)
        session.close()
        return JsonCommonStatus(
            message="Accounts fetched successfully",
            data=out,
            statuscode=200,
            status=True,
        )
    except Exception as e:
        print("error in show account----------", e)
        logging.error("Code failed with:- " + str(e))
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.post(
    "/chat_comment",
    response_model=JsonCommonStatus_without_data,
    description="""
    This Python function handles creating or updating comments for a patient based on their preferences.

    :param request: The `request` parameter in the `chat_comment` function seems to be of type
    `history_command`, which is not a standard Python type. It appears to be a custom type or class
    specific to your application. You may need to provide more information about the `history_command`
    type for further assistance
    :type request: history_command
    :param pay_load: The `pay_load` parameter in the `chat_comment` function seems to be used to verify
    the JWT token for authentication purposes. It is likely that the `pay_load` dictionary contains
    information about the authenticated user, such as their `patient_id`, which is used to perform
    operations specific to that user
    :type pay_load: dict
    :return: The function `chat_comment` returns a JSON response with a message indicating the status of
    the operation performed. The possible return messages are:
    - "Comment updated successfully" if an existing comment is updated successfully.
    - "Comment created successfully" if a new comment is created successfully.
    - "Enter a valid {key}" if the input for a specific key (question or comment) is empty.
    - "
    """,
)
def chat_comment(request: history_command, pay_load: dict = Depends(verify_jwt_token)):
    try:
        req = request.model_dump()
        session = createconnection()
        checkquery = (
            session.query(QuestionPreferenceComment)
            .filter_by(patient_id=pay_load.get("patient_id"), message=request.question)
            .first()
        )
        verify = ["question", "comment"]
        for key, value in req.items():
            if key in verify:
                if len(value) == 0:
                    return JsonCommonStatus_without_data(
                        message=f"Enter a valid {key}",
                        statuscode=status.HTTP_400_BAD_REQUEST,
                        status=False,
                    )
            else:
                return JsonCommonStatus_without_data(
                    message="Unprocessable entity",
                    statuscode=status.HTTP_404_NOT_FOUND,
                    status=False,
                )
        if checkquery:
            checkquery.comment = req.get("comment")
            session.commit()
            return JsonCommonStatus_without_data(
                message="Comment updated successfully",
                status=True,
                statuscode=status.HTTP_200_OK,
            )
        questionPreferenceCommentQuery = QuestionPreferenceComment(
            message=req.get("question"),
            comment=req.get("comment"),
            ctimestap=pd.Timestamp("now").strftime("%d-%m-%y"),
            patient_id=pay_load.get("patient_id"),
        )
        session.add(questionPreferenceCommentQuery)
        session.commit()
        return JsonCommonStatus_without_data(
            message="Comment created successfully",
            status=True,
            statuscode=status.HTTP_200_OK,
        )
    except Exception as e:
        print("error in chat_comments ---------", e)
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )
    finally:
        if session:
            session.close()


@fastapi_app.post(
    "/chat_comment_admin",
    response_model=JsonCommonStatus_without_data,
    description="""
    The function `chat_comment_admin` handles updating or creating comments for a admin in a database
    table based on the request data.
    :param request: The `request` parameter in the `chat_comment_admin` function is to be of type
    `history_command`. It is used to store the history of commands or requests made by the admin. This
    parameter is to track the admin's actions or inputs leading up to the current request
    being processed in
    :type request: history_command
    :param pay_load: The `pay_load` parameter in the `chat_comment_admin` function
    containing admins information extracted from a JWT token. It is being accessed using the
    `verify_jwt_token` dependency.
    :type pay_load: dict
    :return: The function `chat_comment_admin` returns a JSON response with a message indicating the
    outcome of the operation. If successful, it returns a message confirming whether the comment was
    updated or created successfully, along with a status code of 200. If there are any issues such as
    invalid input or server errors, it returns an appropriate error message and status code.
    """,
)
def chat_comment_admin(
    request: history_command, pay_load: dict = Depends(verify_jwt_token)
):
    try:
        req = request.model_dump()
        session = createconnection()
        checkquery = (
            session.query(QuestionPreferenceCommentAdmin)
            .filter_by(user_id=pay_load.get("user_id"), message=request.question)
            .first()
        )
        verify = ["question", "comment"]
        for key, value in req.items():
            if key in verify:
                if len(value) == 0:
                    return JsonCommonStatus_without_data(
                        message=f"Enter a valid {key}",
                        statuscode=status.HTTP_400_BAD_REQUEST,
                        status=False,
                    )
            else:
                return JsonCommonStatus_without_data(
                    message="Unprocessable entity",
                    statuscode=status.HTTP_404_NOT_FOUND,
                    status=False,
                )
        if checkquery:
            checkquery.comment = req.get("comment")
            session.commit()
            return JsonCommonStatus_without_data(
                message="Comment updated successfully",
                status=True,
                statuscode=status.HTTP_200_OK,
            )
        questionPreferenceCommentQuery = QuestionPreferenceCommentAdmin(
            message=req.get("question"),
            comment=req.get("comment"),
            ctimestamp=pd.Timestamp("now").strftime("%Y-%m-%d %H:%M:%S"),
            user_id=pay_load.get("user_id"),
        )
        session.add(questionPreferenceCommentQuery)
        session.commit()
        return JsonCommonStatus_without_data(
            message="Comment created successfully",
            status=True,
            statuscode=status.HTTP_200_OK,
        )
    except Exception as e:
        print("error in chat_comments ---------", e)
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )
    finally:
        if session:
            session.close()


@fastapi_app.post(
    "/generate_otp",
    response_model=JsonCommonStatus_without_data,
    description="""
    The function `generateotp` generates and sends an OTP to a user's email address, handling various
    scenarios such as account existence and error handling.

    :param reqe: The `generateotp` function takes a parameter `reqe`, which is expected to be an object
    that has a method `model_dump()` that can be called within the function. The function uses the data
    extracted from `reqe` to generate an OTP (One Time Password) for a user
    :type reqe: generate_otp
    :return: The function `generateotp` returns a JSON response with a message indicating the status of
    the OTP generation process. The response includes information such as whether the OTP was
    successfully sent, any error messages encountered during the process, and the status code of the
    response.
    """,
)
def generateotp(reqe: generate_otp):
    try:
        req = reqe.model_dump()
        otp = otp_generator()
        session = createconnection()
        timestamp = pd.Timestamp("now")
        if req["email"]:
            optswlquery = text("SELECT otp FROM otp WHERE email = :email")
            otp_result = session.execute(
                optswlquery, {"email": req["email"]}
            ).fetchone()
        elif req["mobile"]:
            optswlquery = text("SELECT otp FROM otp WHERE mobile = :mobile")
            otp_result = session.execute(
                optswlquery, {"mobile": req["mobile"]}
            ).fetchone()
        else:
            return JsonCommonStatus_without_data(
                message="Either email or mobile must be provided",
                statuscode=status.HTTP_400_BAD_REQUEST,
                status=False,
            )

        patientEmail = (
            session.query(PatientDetails)
            .filter(
                PatientDetails.email == reqe.email,  # noqa: E721
            )
            .first()
        )

        patientMobile = (
            session.query(PatientDetails)
            .filter(
                PatientDetails.mobile == reqe.mobile,  # noqa: E721
            )
            .first()
        )

        doctorEmail = (
            session.query(doctorDetails)
            .filter(doctorDetails.email == reqe.email)
            .first()
        )

        doctorMobile = (
            session.query(doctorDetails)
            .filter(doctorDetails.mobile == reqe.mobile)
            .first()
        )

        adminUserMobile = (
            session.query(Admin).filter(Admin.mobile == reqe.mobile).first()
        )

        adminUserEmail = session.query(Admin).filter(Admin.email == reqe.email).first()

        if req.get("email") and req.get("mobile") and req.get("username"):
            if patientMobile or doctorMobile or adminUserMobile:
                return JsonCommonStatus_without_data(
                    message="Account with this mobile number already exist",
                    statuscode=status.HTTP_409_CONFLICT,
                    status=False,
                )

            if patientEmail or doctorEmail or adminUserEmail:
                return JsonCommonStatus_without_data(
                    message="Account with this email already exist",
                    statuscode=status.HTTP_409_CONFLICT,
                    status=False,
                )
        elif not patientEmail and not doctorEmail and not adminUserEmail:
            return JsonCommonStatus_without_data(
                message="Account with this email dosn't exist. Please Create an account",
                statuscode=status.HTTP_409_CONFLICT,
                status=False,
            )

        if not req.get("username"):
            patientEmailforget = (
                session.query(PatientDetails)
                .filter(
                    PatientDetails.email == reqe.email,  # noqa: E721
                    PatientDetails.activestat.is_(True),  # noqa: E721
                )
                .first()
            )
            if patientEmailforget or doctorEmail:
                req["username"] = (
                    patientEmail.username if patientEmail else doctorEmail.fullName
                )
            elif patientMobile or doctorMobile:
                req["username"] = (
                    patientMobile.username if patientMobile else doctorMobile.fullName
                )

        if otp_result:
            if req["email"]:
                otpins = f'update otp set otp = "{otp}", time_stamp="{str(timestamp)}" where email = "{req["email"]}"'
            elif req["mobile"]:
                otpins = f'update otp set otp = "{otp}", time_stamp="{str(timestamp)}" where mobile = "{req["mobile"]}"'
            session.execute(text(otpins))
            session.commit()
        else:
            instotp = text(
                "insert into otp (otp, time_stamp,email) values (:otp,:time_stamp, :email)"
            )
            session.execute(
                instotp,
                {"otp": otp, "time_stamp": str(timestamp), "email": req["email"]},
            )
            session.commit()
        email_generation(email=req["email"], username=req["username"], otp=otp)
        username, domain = req["email"].split("@")
        return JsonCommonStatus_without_data(
            message=f"One Time Passcode was succesfully send to {'*' * (len(username) - 4) + username[-4:] + '@' + domain}",
            status=True,
            statuscode=200,
        )
    except Exception as e:
        print("error in generate_otp-----------", e)
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )
    finally:
        if session:
            session.close()


@fastapi_app.post(
    "/verify_otp",
    response_model=JsonCommonStatus_without_data,
    description="""
    This Python function verifies an OTP by checking its validity and expiration time in a database
    table.

    :param reqs: The `verifyOtp` function takes a parameter `reqs` of type `verify_otp`. This function
    is responsible for verifying an OTP (One Time Password) provided by a user. The OTP is checked
    against the OTP stored in the database for a specific email address within a validity duration of
    :type reqs: verify_otp
    :return: The function `verifyOtp` returns a JSON response with a message indicating the status of
    OTP verification. The response includes a message, a status (True or False), and a status code.
    """,
)
def verifyOtp(reqs: verify_otp):
    try:
        req = reqs.model_dump()
        session = createconnection()
        optswlquery = text("SELECT otp,time_stamp FROM otp WHERE email = :email")
        otp_result = session.execute(optswlquery, {"email": req["email"]}).fetchone()
        if otp_result:
            validity_duration = timedelta(minutes=10)
            expiration_time = otp_result[1] + validity_duration
            if otp_result[0] == req["otp"] and pd.Timestamp("now") <= expiration_time:

                return JsonCommonStatus_without_data(
                    message="One Time Passcode authenticated successfully",
                    status=True,
                    statuscode=200,
                )
            else:
                return JsonCommonStatus_without_data(
                    message="Invalid Passcode/Passcode expired",
                    status=False,
                    statuscode=400,
                )
        else:
            return JsonCommonStatus_without_data(
                message="Unable to process Passcode", status=False, statuscode=400
            )
    except Exception as e:
        print("error in verify_otp-----------", e)
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )


@fastapi_app.put(
    "/update_password",
    response_model=JsonCommonStatus_without_data,
    description="""
    This Python function updates a user's password in a database based on the provided email and
    password.
    :param req: The `req` parameter in the `updatePassword` function seems to be of type `forgetpwd`. It
    is used to retrieve the email and password information needed to update the password for a user
    account. The function then checks if the email exists in the database, encodes the new password, and
    :type req: forgetpwd
    :return: The function `updatePassword` is returning a JSON response with a message indicating the
    status of the password update operation. The specific responses being returned are:
    1. If the account with the provided email doesn't exist, it returns a message stating "Account with
    this email doesn't exist. Please Create an account" with a status code of 409 (CONFLICT) and status
    as False.
    """,
)
def updatePassword(req: forgetpwd):
    try:
        session = createconnection()
        results = (
            session.query(PatientDetails)
            .filter_by(email=req.email.replace(" ", ""), activestat=True)
            .first()
        )
        if not results:
            return JsonCommonStatus_without_data(
                message="Account with this email dosn't exist. Please Create an account",
                statuscode=status.HTTP_409_CONFLICT,
                status=False,
            )

        tp, main_ = Encode_password(req.password)
        salt, password = main_[0], main_[1]
        user = session.query(UserData).filter_by(patient_id=results.patient_id).first()
        if user:
            user.password = password
            user.salt = salt
            session.commit()
            return JsonCommonStatus_without_data(
                message="Password changed successfully",
                statuscode=status.HTTP_200_OK,
                status=True,
            )
        else:
            return JsonCommonStatus_without_data(
                message="User data not found",
                statuscode=status.HTTP_404_NOT_FOUND,
                status=False,
            )
    except Exception as e:
        print("error in update_otp-----------", e)
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )


@fastapi_app.get(
    "/healthdetails_lastupdate",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The function `last_updated` retrieves the most recent health record date for a patient and
    calculates the difference in days from the current date.

    :param pay_load: The `pay_load` parameter in the `last_updated` function seems to be a dictionary
    that is expected to contain information related to a JWT token. This token is likely used for
    authentication and authorization purposes, and the function is using it to retrieve the `patient_id`
    to fetch the most recent health
    :type pay_load: dict
    :return: The function `last_updated` returns a JSON response with a message, data, status code, and
    status boolean value. The message can vary depending on the outcome of the function. If a recent
    health record is found, it returns a message indicating success along with the date and the
    difference in days between the current timestamp and the record timestamp. If no health record is
    found, it returns a message indicating
    """,
)
def last_updated(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        healthrecord = (
            session.query(HealthRecord)
            .filter_by(patient_id=pay_load["patient_id"])
            .order_by(HealthRecord.ctimestamp.desc())
            .first()
        )
        if healthrecord:
            current_timestamp = pd.Timestamp("now")
            record_timestamp = healthrecord.ctimestamp
            print(record_timestamp, "-------------")
            difference_date = current_timestamp - pd.Timestamp(record_timestamp)
            if difference_date < pd.Timedelta(0):
                # Swap the order of subtraction to ensure a positive result
                difference_date = record_timestamp - current_timestamp
            return JsonCommonStatus(
                message="recent health date fetched successfully",
                data={
                    "date": f"{datetime.strftime(healthrecord.ctimestamp,'%d-%m-%Y')}",
                    "difference": f"{difference_date.days}",
                },
                statuscode=status.HTTP_200_OK,
                status=True,
            )
        return JsonCommonStatus(
            message="health details not found",
            data={},
            statuscode=status.HTTP_200_OK,
            status=True,
        )
    except Exception as e:
        print("healthdetails_lastupdate-----", e)
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )


@fastapi_app.post(
    "/profile_completion",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    This Python function retrieves profile completion details for a patient based on their ID and
    calculates the percentage of non-empty fields, determining if the profile has reached 75%
    completion.

    :param pay_load: The `pay_load` parameter in the `profile_complitions` function seems to be a
    dictionary containing information extracted from a JWT token. It is used to identify the patient for
    whom the profile completions are being checked. The function retrieves the `patient_id` from the
    payload to fetch the corresponding
    :type pay_load: dict
    :return: The function `profile_complitions` returns a JSON response with the following structure:
    - message: "Profile completion details fetched successfully" or "Internal server error" depending on
    the outcome
    - data:
      - "reached_75_percent": a boolean indicating whether the profile completion percentage is equal to
    or greater than 75%
      - "profile_percent": the rounded percentage of non-null
    """,
)
def profile_complitions(req: profile_keys, pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        result = (
            session.query(PatientDetails)
            .filter_by(patient_id=pay_load.get("patient_id"))
            .first()
        )
        result.subscription = None
        result.insurance_provider = None
        result.insurance_policy_no = None
        health_history_criteria = (
            session.query(HealthRecord)
            .filter_by(patient_id=pay_load.get("patient_id"))
            .first()
        )
        total_fields = len(result.__table__.columns)
        exclude_fields = {
            "history_progress",
            "insuranceurl",
            "patient_id",
            "activestat",
            "height",
            "subscription",
            "insurance_provider",
            "insurance_policy_no",
            "profile_url",
        }
        total_fields = len(
            [
                column
                for column in result.__table__.columns
                if column.name not in exclude_fields
            ]
        )
        non_na_fields = sum(
            1
            for column in result.__table__.columns
            if column.name not in exclude_fields
            and getattr(result, column.name) is not None
        )
        percentage_non_na = (non_na_fields / total_fields) * 100
        reached_75_percent = True if percentage_non_na >= 75 else False
        history_progress = (
            False
            if not result.history_progress
            else (
                True
                if "first_procedure_key" in json.loads(result.history_progress)
                and health_history_criteria
                and reached_75_percent
                else False
            )
        )
        datas = {}

        if req.history_chat:
            datas["reached_75_percent"] = reached_75_percent

        if req.profile:
            datas["profile_percent"] = round(percentage_non_na)

        if req.history_trans:
            datas["history_progress_criteria"] = history_progress

        message_parts = []

        if "reached_75_percent" in datas:
            message_parts.append(
                "Profile reached 75 percent"
                if reached_75_percent
                else "Profile didn't reach 75 percent"
            )

        if "profile_percent" in datas:
            message_parts.append("Profile percentage fetched successfully")

        if "history_progress_criteria" in datas:
            message_parts.append(
                "History progress criteria fetched"
                if history_progress
                else "Profile didn't meet history progress criteria"
            )

        # Join the message parts with commas
        dynamic_message = ", ".join(message_parts)

        return JsonCommonStatus(
            message=dynamic_message,
            data=datas,
            statuscode=status.HTTP_200_OK,
            status=True,
        )
    except Exception as e:
        print("error in profile_completion------------", e)
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )


@fastapi_app.get(
    "/initial_question",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    This Python function retrieves an initial question based on a patient's ID and history progress,
    handling exceptions and returning appropriate responses.

    :param pay_load: The `pay_load` parameter in the `initial_question` function seems to be a
    dictionary that is expected to contain information related to a JWT token. It is likely used for
    verifying the JWT token and extracting the `patient_id` from it. The `Depends` function suggests
    that this parameter is
    :type pay_load: dict
    :return: The function `initial_question` returns a JSON response with the following structure:
    - If a question is found, it returns a JSON response with status code 200 OK, containing the fetched
    question data in the `data` field and a success message.
    - If no question is found, it returns a JSON response with status code 404 NOT FOUND and a message
    indicating that no question was found.
    -
    """,
)
def initial_question(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        validation_check = (
            session.query(PatientDetails)
            .filter_by(patient_id=pay_load.get("patient_id"))
            .first()
        )
        valdata = (
            json.loads(validation_check.history_progress)[
                len(json.loads(validation_check.history_progress)) - 1
            ]
            if validation_check.history_progress
            else None
        )
        if valdata is None:
            question = (
                session.query(history_question)
                .filter_by(question_key="prefered_name")
                .first()
            )
        else:
            querys = (
                session.query(history_question).filter_by(question_key=valdata).first()
            )
            if querys and querys.yes is not None:
                question = (
                    session.query(history_question)
                    .filter_by(question_key=querys.yes)
                    .first()
                )
            if querys.yes is None:
                return JsonCommonStatus_without_data(
                    message="no question found",
                    statuscode=status.HTTP_404_NOT_FOUND,
                    status=False,
                )
        if question:
            question_dict = {
                column.name: getattr(question, column.name)
                for column in question.__table__.columns
            }
            question_dict["options"] = json.loads(question.options)

            return JsonCommonStatus(
                message="Initial question fetched successfully",
                data=question_dict,
                statuscode=status.HTTP_200_OK,
                status=True,
            )
        return JsonCommonStatus_without_data(
            message="Thank you for answering all the questions.",
            statuscode=99,
            status=False,
        )
    except Exception as e:
        print("error in initial_question------------", e)
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )


@fastapi_app.post(
    "/educational_bot_home",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The function is capable to answer education question about atrial friblation based on the PDF's
    feeded in the backend and it canprocess answer the answer in the formated fashion and return to user

    :param item: The `item` parameter in the `history_dump` function is of type `history_schema`. It
    seems to contain information related to a message, including the message content and an ID
    associated with it. The function performs operations like querying a database, sending a POST
    request to a specific endpoint, processing the
    :type item: history_schema
    :return: The function `history_dump` returns a JSON response with the following structure:
    - If the API call is successful:
      - A message indicating success
      - Data containing the user message and the response from the assistant
      - Status code 200 and status as True

    - If there is an exception (error):
      - A message indicating internal server error
      - Status code 500 and
    """,
)
async def history_dump(item: history_schema):
    return JsonCommonStatus_without_data(
        message="The API Works form streaming URL", status=False, statuscode=404
    )


@fastapi_app.post(
    "/upload-profile-image",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    Upload a profile image for a patient.

    This endpoint allows authenticated users to upload a profile image for a patient. The image file should be included in
    the request. The endpoint processes the file and stores it in Azure Blob Storage with a unique filename.
    The unique filename is generated using a combination of the reversed date of birth and patient ID,
    ensuring that the filename is unique.

    Parameters:
    - pay_load: A dictionary containing the JWT token payload, which includes the patient ID.
    - file_: The image file to be uploaded.

    Returns:
    - JsonCommonStatus: A response indicating that the image was uploaded successfully, including the URL of the uploaded image.
    - JsonCommonStatus_without_data: A response indicating an error occurred during the upload process.

    """,
)
def upload_profile_image(
    pay_load: dict = Depends(verify_jwt_token), file_: UploadFile = File(...)
):
    try:
        session = createconnection()
        admin = (
            session.query(Admin)
            .filter(Admin.user_id == pay_load.get("user_id"))
            .first()
        )
        result = (
            session.query(PatientDetails)
            .filter_by(patient_id=pay_load.get("patient_id"))
            .first()
        )
        extension = file_.filename.split(".")[-1].lower()
        if result:
            blob_name_without_extension = generate_unique_filename(
                str(result.dob), result.patient_id
            )
        elif admin:
            part1, part2, part3 = admin.user_id.split("-")
            blob_name_without_extension = (
                f"{part1}{admin.designation}{part3}{part2}_profile_img"
            )
        unique_filename = blob_name_without_extension + "." + extension
        blob_service_client = BlobServiceClient(
            account_url=client.get_secret("BLOBSERVICECLIENTACNAME").value,
            credential=client.get_secret("ACCOUNTKEY").value,
        )
        container_client = blob_service_client.get_container_client(
            container=client.get_secret("IMAGECONTAINERNAME").value
        )
        blob_list = container_client.list_blobs(
            name_starts_with=blob_name_without_extension
        )
        for blob in blob_list:
            blob_client = container_client.get_blob_client(blob=blob.name)
            blob_client.delete_blob()

        blob_client = container_client.get_blob_client(blob=unique_filename)
        blob_client.upload_blob(
            file_.file,
            content_settings=ContentSettings(content_type=file_.content_type),
        )
        profile_img = get_blob_sas_url(blob_name_without_extension)
        session.commit()
        return JsonCommonStatus(
            message="Image uploaded successfully",
            data={"profile_img": profile_img},
            statuscode=200,
            status=True,
        )
    except Exception as e:
        print(e, "----Upload Profile Image")
        if session:
            session.close()
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )
    finally:
        if session:
            session.close()


@fastapi_app.get(
    "/history_transcript",
    description="""
    The function `get_patient_info` generates random patient information and returns it in an HTML
    format along with a success message.

    :param pay_load: The `get_patient_info` function seems to generate random patient information based
    on various parameters. The `pay_load` parameter is expected to be a dictionary containing
    information necessary for verifying a JWT token. In this case, it seems like the function is using
    the JWT token to authenticate the request and retrieve patient
    :type pay_load: dict
    :return: The function `get_patient_info` is returning a JSON response with a message indicating that
    the patient's history transcript was fetched successfully. The data being returned includes various
    randomly generated patient information such as name, age, gender, type of atrial fibrillation,
    symptoms, CHADS2VA2SC score, cardiac conditions, co-morbidities, antiarrhythmic medication, prior
    medical history,
    """,
)
def get_patient_info(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()

        def symptoms():
            try:
                selection = (
                    session.query(Symptom)
                    .filter_by(patient_id=pay_load.get("patient_id"))
                    .all()
                )
                severity_order = {
                    "None": 0,
                    "Mild": 1,
                    "Moderate": 2,
                    "Severe": 3,
                    "Extreme": 4,
                }
                severity_order_frequency = {
                    "Never": 0,
                    "Occasionally": 1,
                    "Often": 2,
                    "Always": 3,
                }
                maindata = []
                data = {}
                for entry in selection:
                    data["infirmity"] = entry.infirmity
                    data["nsynacpe"] = entry.nsynacpe
                    data["tirednessafterwards"] = entry.tirednessafterwards
                    data["breathnessda"] = entry.breathnessda
                    data["breathnessea"] = entry.breathnessea
                    data["dizziness"] = entry.dizziness
                    data["col_swet"] = entry.col_swet
                    data["chest_pain"] = entry.chest_pain
                    data["pressurechest"] = entry.pressurechest
                    data["worry"] = entry.worry
                    data["weakness"] = entry.weakness
                    maindata.append(data)
                    data = {}

                def calculate_sorting_key(entry):
                    # print("entry-----------", entry)
                    total_quality_of_life = sum(
                        1
                        for symptom in entry.values()
                        if symptom["quality_of_life"] is True
                    )
                    total_severity = sum(
                        severity_order[symptom["severity"]]
                        for symptom in entry.values()
                    )
                    total_frequency = sum(
                        severity_order_frequency[
                            (
                                symptom.get("frequency")
                                if symptom.get("frequency")
                                else "Never"
                            )
                        ]
                        for symptom in entry.values()
                    )
                    return (total_severity, total_frequency, total_quality_of_life)

                sorted_data = sorted(maindata, key=calculate_sorting_key, reverse=True)
                topfive = sorted_data[:1]

                sorted_symptoms = sorted(
                    topfive[0].items(),
                    key=lambda x: (
                        severity_order[x[1]["severity"]],
                        severity_order_frequency.get(
                            x[1]["frequency"], severity_order_frequency["Never"]
                        ),
                    ),
                    reverse=True,
                )

                outPutString = ""
                for symptom, details in sorted_symptoms[:3]:
                    if len(outPutString) == 0:
                        outPutString = f"{details['frequency']} suffering from {details['severity']} {symptom}"
                    else:
                        outPutString += f" and {details['frequency']} suffering from {details['severity']} {symptom}"

                return outPutString
            except Exception as e:
                print("----------exception", e)

        def predision():
            try:
                main_string = ""
                patient_details = (
                    session.query(PatientDetails)
                    .filter_by(patient_id=pay_load.get("patient_id"))
                    .first()
                )
                answered_question = json.loads(patient_details.history_progress)

                responses = {
                    "electrical_shock": lambda: f"The {name.answer} confirmed they had an electrical shock (cardioversion) to restore normal heart rhythm when in atrial fibrillation and ",
                    "electrical_shock_progress": lambda: (
                        "The cardioversion was successful."
                        if "normal_rhythm" in answered_question
                        else "The cardioversion was not successful."
                    ),
                    "rhythm medications": lambda: f"The {name.answer} was on rhythm medications including flecainide (Tambocor), propafenone (Rhythmol), dronedarone (Multaq), sotalol, amiodarone, and dofetilide (Tikosyn) and ",
                    "normal_rhythm": lambda: f"The {name.answer} reverted back to atrial fibrillation after 6 days in normal (sinus) rhythm and",
                    "rhythm_control": lambda: (
                        f"The medications was effective in controlling the {name.answer}'s rhythm."
                        if "side_effects" in answered_question
                        else f"The medications were not effective in controlling the {name.answer}'s rhythm."
                    ),
                    "side_effects": lambda: "The user confirmed they had side effects from the rhythm medication and ",
                    "ablation": lambda: (
                        f"The {name.answer} confirmed that they had ablation for atrial fibrillation."
                        if "time_key" in answered_question
                        else f"The {name.answer} denied having ablation for atrial fibrillation."
                    ),
                    "reason": lambda: f" and The medications were not effective in controlling the {name.answer}'s rhythm .",
                    "side_effects_type": lambda: f"The {name.answer} experienced breathing problems as a side effect.",
                    "second_procedure": lambda: f"and The {name.answer} confirmed they had a second procedure.",
                    "time_key": lambda: "The ablation was performed on May 20, 2021.",
                    "place": lambda: "The procedure took place at King's Hospital.",
                    "normalrhythm_key": lambda: f" and The ablation helped the {name.answer} maintain a normal rhythm",
                    "quality_of_life": lambda: f"The ablation significantly improved the {name.answer}'s quality of life.",
                    "freezing_key": lambda: "The ablation was the electrical (pulsed-field ablation) type.",
                    "first_procedure_key": lambda: "and The second procedure was done after 4 months",
                }
                for answerKey in answered_question:
                    if answerKey in responses:
                        main_string += responses[answerKey]()
                return main_string

            except Exception as e:
                print("erererer===============>", e)
                return JsonCommonStatus_without_data(
                    message="Internal server error", statuscode=500, status=False
                )

        def historyChatbotAnswer(question):
            query = (
                session.query(history_chatbot_answers)
                .filter(
                    history_chatbot_answers.question_id == question,
                    history_chatbot_answers.patient_id == pay_load.get("patient_id"),
                )
                .first()
            )
            return query

        temp = (
            session.query(PatientDetails)
            .filter(PatientDetails.patient_id == pay_load.get("patient_id"))
            .first()
        )

        pronoun = historyChatbotAnswer("pronoun_question")
        name = historyChatbotAnswer("prefered_name")
        type_af = historyChatbotAnswer("type_of_af")
        year = historyChatbotAnswer("year_of_af")
        diagnose_af = historyChatbotAnswer("location")
        CHADS2VA2SC = historyChatbotAnswer("CHADS2VA2SC")
        hypertension = historyChatbotAnswer("hypertension")
        blood_pressure_medications = historyChatbotAnswer("blood_pressure_medications")
        cied = historyChatbotAnswer("cied")
        symptoms = symptoms()
        predictions = predision()
        AAD_Medication = True

        # if symptoms, cied, blood_pressure_medications
        style = "{font-size: 22px;}"
        result = f"""<html> <head>
        <style>body{style}</style>
        </head> <body>    <p><strong>{pronoun.answer}</strong>.
        <strong>{name.answer}</strong> is a <strong>{calculate_age(temp.dob)}</strong>-year-old
        <strong>{temp.gender}</strong> with <strong>{type_af.answer}</strong>, first detected in the year <strong>{year.answer}</strong>
        and diagnosed by <strong>{diagnose_af.answer}</strong>.</p>
        <p><strong>{pronoun.answer}</strong>.<strong>{name.answer}</strong>
        has symptoms of <strong>{symptoms}</strong>.</p>
       <p><strong>{pronoun.answer}</strong>. <strong>{name.answer}</strong>
       has a CHADS2VA2SC score of <strong>{CHADS2VA2SC.answer}</strong>
       and has the cardiac conditions of <strong>{"Hypertension" if "yes" in hypertension.answer else ""}
       AND {"Blood Pressure" if "yes" in blood_pressure_medications.answer else ""}</strong>.</p>
       <p>They have other patient co-morbidities such as <strong>{"Coronary Artery Calcification, Hypothyroidism, EKG shows Right bundle block" if True else "None"}</strong>.
       </p> <p>They are currently on <strong>{AAD_Medication}</strong>.</p>
       <p>The patient has prior <strong>{predictions}</strong>.</p>
       <p><strong>{pronoun.answer}</strong>. <strong>{name.answer}</strong> has
       <strong>{cied.answer}</strong>.</p> </body> </html>"""

        return JsonCommonStatus(
            message="history_transcript fetched successfully",
            data={"patient_info": result},
            status=True,
            statuscode=status.HTTP_200_OK,
        )

        # return result

    except Exception as e:
        print("Got exception inside history_transcript:- ", e)
        return JsonCommonStatus_without_data(
            Message="Could not get patient history right now! Try again later",
            status=False,
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@fastapi_app.put("/change-password", response_model=JsonCommonStatus_without_data)
def changePassword(req: changePwd, pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        results = (
            session.query(PatientDetails)
            .filter_by(patient_id=pay_load.get("patient_id"))
            .first()
        )
        user = session.query(UserData).filter_by(patient_id=results.patient_id).first()
        # Verify old password
        if not verify_password(req.old_password, user.salt, user.password):
            return JsonCommonStatus_without_data(
                message="Current password is incorrect",
                statuscode=status.HTTP_401_UNAUTHORIZED,
                status=False,
            )
        tp, main_ = Encode_password(req.new_password)
        new_salt, new_password_hash = main_[0], main_[1]
        # Update user password and salt
        user.password = new_password_hash
        user.salt = new_salt
        session.commit()

        return JsonCommonStatus_without_data(
            message="Password changed successfully",
            statuscode=status.HTTP_200_OK,
            status=True,
        )
    except Exception as e:
        print(e, "---Error in change password")
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )


@fastapi_app.post(
    "/profile-completions-summary",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    This Python function retrieves profile completion details for a patient based on their ID and
    calculates the percentage of non-empty fields, determining if the profile has reached 75%
    completion.
    :param pay_load: The `pay_load` parameter in the `profile_completions` function seems to be a
    dictionary containing information extracted from a JWT token. It is used to identify the patient for
    whom the profile completions are being checked. The function retrieves the `patient_id` from the
    payload to fetch the corresponding
    :type pay_load: dict
    :param request: The `request` parameter is a dictionary containing keys like "history_chat", "history_trans", or "profile" with boolean values indicating what information to fetch.
    :type request: dict
    :return: The function `profile_completions` returns a JSON response with the requested profile completion detail.
    """,
)
def profile_completions(
    request: ProfileCompletionRequest, pay_load: dict = Depends(verify_jwt_token)
):
    try:
        session = createconnection()
        patient_id = pay_load.get("patient_id")
        result = session.query(PatientDetails).filter_by(patient_id=patient_id).first()

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found"
            )

        # Calculate non-null fields excluding certain fields
        total_fields = len(result.__table__.columns)
        exclude_fields = {
            "history_progress",
            "insuranceurl",
            "patient_id",
            "activestat",
            "height",
            "subscription",
            "insurance_provider",
            "insurance_policy_no",
            "profile_url",
        }
        total_fields = len(
            [
                column
                for column in result.__table__.columns
                if column.name not in exclude_fields
            ]
        )
        non_na_fields = sum(
            1
            for column in result.__table__.columns
            if column.name not in exclude_fields
            and getattr(result, column.name) is not None
        )
        percentage_non_na = (non_na_fields / total_fields) * 100

        # Check if history_progress is completed
        history_progress = False
        if result.history_progress:
            history_progress_data = json.loads(result.history_progress)
            history_progress = "first_procedure_key" in history_progress_data

        # Query for symptoms record
        symptoms_record = (
            session.query(Symptom).filter_by(patient_id=patient_id).first()
        )

        message = "Patient Qualify to Accesss!"
        redirection_key = ""
        web_redirection_key = ""
        status_code = status.HTTP_200_OK
        status_ = True
        if request.history_chat:
            if percentage_non_na < 75:
                message = "Incomplete Profile! Please complete at least 75%"
                redirection_key = "profile"
                web_redirection_key = "profile"
                status_code = status.HTTP_200_OK
                status_ = True
            elif symptoms_record is None:
                message = "No Entry for List Of Symptoms Recorded! Please complete List of Symptoms"
                redirection_key = "list_of_symptoms"
                web_redirection_key = "home"
                status_code = status.HTTP_200_OK
                status_ = True
        elif (request.history_trans and not history_progress) or (
            request.behavioural_chat and not history_progress
        ):
            message = "Please first complete all the questions under history bot"
            redirection_key = "history_chat"
            web_redirection_key = "historychat"
            status_code = status.HTTP_200_OK
            status_ = True
        elif request.profile and percentage_non_na < 75:
            message = "Incomplete Profile! Please complete at least 75%"
            redirection_key = "profile"
            web_redirection_key = "profile"
            status_code = status.HTTP_200_OK
            status_ = True

        # Return response based on the redirection key presence
        if redirection_key:
            return JsonCommonStatus(
                message=message,
                statuscode=status_code,
                status=status_,
                data={
                    "redirection_key": redirection_key,
                    "web_redirection_key": web_redirection_key,
                },
            )
        else:
            return JsonCommonStatus_without_data(
                message=message, statuscode=status_code, status=status_
            )

    except Exception as e:
        print(e, "--Error in profile completion line 3360")
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )


@fastapi_app.post(
    "/health_details_graph",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    Fetch the health details graph data for a patient.
    This endpoint retrieves all health records for a specific patient, ordered by the latest date first.
    Each record is processed to convert blood pressure readings from a string format to separate systolic and diastolic values.
    The resulting data is returned as an array of records.
    """,
)
def expertMonitor(
    date_range: healthDetailsDateRange, pay_load: dict = Depends(verify_jwt_token)
):
    try:
        session = createconnection()
        patient_id = pay_load.get("patient_id")
        params = {"patient_id": patient_id}
        sql_query = """
            SELECT *, TIMESTAMPDIFF(SECOND, tdate, ctimestamp) AS diff
            FROM helloalfred.health_details
            WHERE patient_id = :patient_id
        """
        if date_range.start_date:
            params["start_date"] = datetime.strptime(date_range.start_date, "%Y-%m-%d")
            sql_query += " AND tdate >= :start_date"
        if date_range.end_date:
            params["end_date"] = datetime.strptime(date_range.end_date, "%Y-%m-%d")
            sql_query += " AND tdate <= :end_date"
        sql_query += " ORDER BY tdate, diff DESC;"
        results = session.execute(text(sql_query), params).fetchall()
        if not results:
            patient_exists = (
                session.query(HealthRecord).filter_by(patient_id=patient_id).first()
                is not None
            )
            if patient_exists:
                return JsonCommonStatus(
                    statuscode=200, status=True, message="No records found", data=[]
                )
            else:
                return JsonCommonStatus(
                    statuscode=204, status=True, message="No records found", data=[]
                )
        data = []
        seen_dates = set()
        for result in results:
            if not result.tdate:
                continue
            tdate_str = result.tdate.strftime("%Y-%m-%d")
            if tdate_str not in seen_dates:
                bloodp = result.bloodp
                systolic_p = None
                diastolic_p = None
                if bloodp:
                    try:
                        systolic_p, diastolic_p = map(int, bloodp.split("/"))
                    except ValueError:
                        continue

                record = {
                    "tdate": tdate_str,
                    "weight": result.weight,
                    "systolic_p": systolic_p,
                    "diastolic_p": diastolic_p,
                    "pulse": result.pulse,
                }
                if len(seen_dates) < int(client.get_secret("NUMBEROFRECORDS").value):
                    data.append(record)
                    seen_dates.add(tdate_str)
                else:
                    break
        return JsonCommonStatus(
            message="Data fetched successfully",
            data=reversed(data),
            statuscode=200,
            status=True,
        )
    except Exception as e:
        print("error in health_details_graph", e)
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )
    finally:
        if session:
            session.close()


@fastapi_app.post(
    "/delete-profile-image",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    This endpoint allows users to delete their profile image from the system.

    ### Key Actions
    - **Authentication**: Validates the user's identity using a JWT token.
    - **Database Query**: Retrieves the user details based on the provided `patient_id`.
    - **Azure Blob Storage Interaction**: Connects to Azure Blob Storage, identifies the relevant profile image files, and deletes them.

    ### Responses
    - **Success (200)**: Returns a confirmation message that the profile image was successfully deleted.
    - **Error (500)**: Returns an error message if an internal server error occurs during the process.

    This ensures that users can manage their profile images securely and effectively.
    """,
)
def delProfilePic(pay_load: dict = Depends(verify_jwt_token)):
    session = None
    try:
        session = createconnection()
        admin = (
            session.query(Admin)
            .filter(Admin.user_id == pay_load.get("user_id"))
            .first()
        )
        result = (
            session.query(PatientDetails)
            .filter_by(patient_id=pay_load.get("patient_id"))
            .first()
        )
        if not result and not admin:
            return JsonCommonStatus_without_data(
                message="Patient not found", statuscode=404, status=False
            )
        blob_service_client = BlobServiceClient(
            account_url=f"https://{client.get_secret('ACCOUNTNAME').value}.blob.core.windows.net",
            credential=client.get_secret("ACCOUNTKEY").value,
        )
        if result:
            blob_name_without_extension = generate_unique_filename(
                result.dob.strftime("%Y-%m-%d"), result.patient_id
            )
        elif admin:
            part1, part2, part3 = admin.user_id.split("-")
            blob_name_without_extension = (
                f"{part1}{admin.designation}{part3}{part2}_profile_img"
            )
        container_client = blob_service_client.get_container_client(
            container=client.get_secret("IMAGECONTAINERNAME").value
        )

        blob_list = container_client.list_blobs(
            name_starts_with=blob_name_without_extension
        )
        for blob in blob_list:
            blob_client = container_client.get_blob_client(blob=blob.name)
            blob_client.delete_blob()
        return JsonCommonStatus_without_data(
            message="Profile image deleted successfully!", statuscode=200, status=True
        )
    except Exception as e:
        print(f"Error deleting profile image: {e}")
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )
    finally:
        if session:
            session.close()


@fastapi_app.get(
    "/latest-symptoms-record-date",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The function `lastUpdatedListOfSymptoms` retrieves the most recent record date of symptoms for a
    specific patient from a database.
    :param pay_load: The `pay_load` parameter in the `lastUpdatedListOfSymptoms` function is used to
    pass a dictionary containing the payload data, typically obtained from verifying a JWT token. This
    payload may contain information such as the `patient_id` needed to query the database for the last
    updated list of symptoms for
    :type pay_load: dict
    :return: The function `lastUpdatedListOfSymptoms` is returning a JSON response using the
    `JsonCommonStatus` class. The response includes a message indicating the success or failure of
    fetching the recent record date of the list of symptoms, along with the fetched data which includes
    the record timestamp and the difference in days between the current timestamp and the record
    timestamp. The status code is set to 200 if successful,
    """,
)
def lastUpdatedListOfSymptoms(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        result = (
            session.query(Symptom)
            .filter(Symptom.patient_id == pay_load.get("patient_id"))
            .order_by(desc(Symptom.ctimestamp))
            .first()
        )
        if result is None:
            return JsonCommonStatus(
                message="List of symptoms not found",
                data={},
                statuscode=204,
                status=True,
            )
        current_timestamp = pd.Timestamp("now")
        record_timestamp = pd.to_datetime(result.ctimestamp, format="%d-%m-%Y")
        difference_date = current_timestamp - pd.Timestamp(record_timestamp)

        return JsonCommonStatus(
            message="recent record date of the list of symptoms fetched successfully",
            data={
                "date": record_timestamp.strftime("%d-%m-%Y"),
                "difference": difference_date.days,
            },
            statuscode=status.HTTP_200_OK,
            status=True,
        )
    except Exception as e:
        print(f"Error in lastUpdatedListOfSymptoms: {e}")
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )
    finally:
        if session:
            session.close()


@fastapi_app.get(
    "/get-latest-symptoms",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The function `get_latest_symptoms` retrieves the latest symptoms of a patient from a database and
    returns them in a JSON response.
    :param pay_load: The `pay_load` parameter in the `get_latest_symptoms` function is used to retrieve
    the JSON Web Token (JWT) payload data. This payload typically contains information about the
    authenticated user, such as their user ID or any other relevant data needed for authorization or
    identification purposes. In this case,
    :type pay_load: dict
    :return: The `get_latest_symptoms` function returns a JSON response containing the latest symptoms
    fetched successfully for a specific patient. The response includes a message indicating the success
    of fetching symptoms, a status code of 200 for success, a boolean status value of True, and the data
    which consists of the latest symptoms in a dictionary format. If an error occurs during the process,
    an error message is returned with a
    """,
)
def get_latest_symptoms(pay_load: dict = Depends(verify_jwt_token)):
    def severity_mapper(sev_val):
        try:
            ans = {
                0: "None",
                20: "Mild",
                45: "Moderate",
                70: "Severe",
                90: "Extreme",
            }
            return ans[int(sev_val)]
        except Exception as e:
            print(e)
            return ""

    try:
        session = createconnection()
        result = (
            session.query(Symptom)
            .filter(Symptom.patient_id == pay_load.get("patient_id"))
            .order_by(desc(Symptom.ctimestamp))
            .first()
        )
        response = []
        emptyData = {"severity": "", "frequency": "None", "quality_of_life": ""}
        if result:
            for key, value in result.__dict__.items():
                if (
                    key
                    not in [
                        "symptoms_id",
                        "tdate",
                        "ctimestamp",
                        "health_id",
                        "patient_id",
                    ]
                    and key != "_sa_instance_state"
                    and value is not None
                ):
                    if value != emptyData:
                        if "severity" in value:
                            value["severity"] = severity_mapper(
                                value["severity"],
                            )
                        if key:
                            value["symptoms_key"] = key
                        response.append(value)
        return JsonCommonStatus(
            message="Symptoms fetched successfully",
            statuscode=status.HTTP_200_OK,
            status=True,
            data=response,
        )
    except Exception as e:
        print("error in get latest symptoms ", e)
        return JsonCommonStatus_without_data(
            message="Internal server error",
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
        )
    finally:
        if session:
            session.close()


@fastapi_app.post(
    "/create-doctor-account",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The function `creationDoctorDetails` creates a new doctor account with provided details, checking
    for existing accounts with the same email or mobile number.
    :param req: The `req` parameter in the `creationDoctorDetails` function seems to be an instance of
    `reqCreateDoctorSchemas`. This instance is used to extract the request data needed for creating a
    new doctor account. The `model_dump()` method is likely used to retrieve the data from this request
    object
    :type req: reqCreateDoctorSchemas
    :return: The function `creationDoctorDetails` returns a JSON response with a message indicating
    whether the doctor account was created successfully or if there was a conflict due to an existing
    account with the same email or mobile number. The status code and status boolean are also included
    in the response. If there is an error during the process, it returns an internal server error
    message.
    """,
)
def creationDoctorDetails(req: reqCreateDoctorSchemas):
    try:
        session = createconnection()
        checkPreviousUser = (
            session.query(doctorDetails)
            .filter(
                or_(
                    doctorDetails.email == req.email,
                    doctorDetails.mobile == req.mobile,
                )
            )
            .first()
        )

        checkPreviousPatient = (
            session.query(PatientDetails)
            .filter(
                or_(
                    PatientDetails.email == req.email,
                    PatientDetails.mobile == req.mobile,
                )
            )
            .first()
        )

        tp, main_ = Encode_password(req.password)
        salt, password = main_[0], main_[1]
        if not checkPreviousUser and not checkPreviousPatient:
            doctorId = patient_id_generator()
            doctorData = doctorCredentials(
                doctor_details_id=doctorId, salt=salt, password=password
            )
            doctorDetail = doctorDetails(
                doctor_details_id=doctorId,
                fullName=req.username,
                email=req.email.replace(" ", ""),
                mobile=req.mobile,
                highest_grade=req.highest_grade,
                state_of_practice=req.state_of_practice,
                national_provider_id=req.national_provider_id,
                medical_license_number=req.medical_license_number,
                country=req.country,
                state=req.state,
                name_of_hospital=req.name_of_hospital.strip(),
                referral_code=req.referral_code,
                city=req.city,
            )
            session.add(doctorDetail)
            session.add(doctorData)
            session.commit()
            return JsonCommonStatus_without_data(
                message="Doctor account created successfully",
                statuscode=status.HTTP_200_OK,
                status=True,
            )
        email = "Account with this email already exist. Please try another email"
        mobile = "Account with this mobile number already exist. Please try another mobile number"
        return JsonCommonStatus_without_data(
            message=(
                email
                if checkPreviousUser
                and checkPreviousUser.email == req.email
                or checkPreviousPatient
                and checkPreviousPatient.email == req.email
                else mobile
            ),
            statuscode=status.HTTP_409_CONFLICT,
            status=False,
        )
    except Exception as e:
        print(f"Error in create-doctor-details: {e}")
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )
    finally:
        if session:
            session.close()


# @fastapi_app.post(
#     "/upload-asset",
#     response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
#     description="""
#     Description:
#         This endpoint allows users to upload an asset (file) to Azure Blob Storage. If a file with the same name already exists
#         in the storage container, it will be deleted before the new file is uploaded. This ensures that the storage container always contains the latest file.

#         Request:
#         Method: POST
#         Request Parameter:
#         file_ (UploadFile): The file to be uploaded. This parameter is required and should be included in the request as a form-data field.
#         Responses:
#         200 OK: If the file is successfully uploaded.
#     """,
# )
# def upload_asset(file_: UploadFile = File(...)):
#     try:
#         blob_service_client = BlobServiceClient(
#             account_url=os.getenv("BLOB_SERVICE_CLIENT_AC_NAME"),
#             credential=os.getenv("ACCOUNT_KEY"),
#         )
#         container_client = blob_service_client.get_container_client(
#             container=os.getenv("ASSET_CONTAINER_NAME")
#         )
#         blob_client = container_client.get_blob_client(blob=file_.filename)
#         blob_client.upload_blob(
#             file_.file,
#             content_settings=ContentSettings(content_type=file_.content_type),
#             overwrite=True,
#         )
#         return JsonCommonStatus_without_data(
#             message="Asset Uploaded Sucessfully!", statuscode=200, status=True
#         )
#     except Exception as e:
#         print(f"Exception in Upload_asset : {e}")
#         return JsonCommonStatus_without_data(
#             message="Internal server error", statuscode=500, status=False
#         )


@fastapi_app.post(
    "/get-asset-url",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
        This endpoint generates a secure URL for accessing an asset (image) stored in Azure Blob Storage.
        The URL is valid for 2 minutes, ensuring temporary access to the specified asset.

        Request:
        Method: GET

        Request Model: getAssetName

        Attributes:
        filename (str): The name of the file for which the secure URL is to be generated.

        Responses:
        200 OK: If the filename is provided and the URL is successfully generated
    """,
)
def get_asset_url(req: getAssetName):
    try:
        filename = req.filename
        blob_service_client = BlobServiceClient(
            account_url=client.get_secret("BLOBSERVICECLIENTACNAME").value,
            credential=client.get_secret("ACCOUNTKEY").value,
        )
        asset_container_name = client.get_secret("ASSETCONTAINERNAME").value
        container_client = blob_service_client.get_container_client(
            container=asset_container_name
        )

        blob_client = container_client.get_blob_client(blob=filename)

        if not blob_client.exists():
            return JsonCommonStatus_without_data(
                message=f"Asset with filename '{filename}' not found!",
                statuscode=404,
                status=False,
            )

        expiry_time = datetime.now() + timedelta(minutes=2)
        img_url = generate_blob_sas_url(filename, expiry_time, asset_container_name)

        return JsonCommonStatus(
            message="Asset URL fetched successfully!",
            data={"asset_url": img_url},
            statuscode=200,
            status=True,
        )

    except Exception as e:
        print(f"Exception in get_asset_url : {e}")
        return JsonCommonStatus_without_data(
            message="Internal server error", statuscode=500, status=False
        )


@fastapi_app.post(
    "/send-confirmation-email",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The request payload must include a valid JWT token. Upon successful verification of the token, the patient's details
    are retrieved from the database using the patient_id provided in the payload. If the patient is found, an email
    confirmation is sent to the doctor's registered email address.
    """,
)
def send_confirmation_email(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        patient_id = pay_load.get("patient_id")
        result = session.query(PatientDetails).filter_by(patient_id=patient_id).first()
        if not result:
            return JsonCommonStatus_without_data(
                statuscode=404, status=False, message="Patient not found"
            )
        res = send_email_confirmation(result.username, result.patient_id, result.email)
        if res["status"] == "Succeeded":
            return JsonCommonStatus_without_data(
                message="Email sent successfully", statuscode=200, status=True
            )
        elif res["status"] == "Failed":
            logg.error("Email not sent, Failed for patient_id: %s", patient_id)
            return JsonCommonStatus_without_data(
                message="Email not sent, Failed!", statuscode=200, status=False
            )
        else:
            logg.error(
                "Unexpected status in send_email_confirmation for patient_id: %s",
                patient_id,
            )
            return JsonCommonStatus_without_data(
                statuscode=500, status=False, message="Internal server error"
            )

    except Exception as e:
        print("Error in send_confirmation_email", e)
        return JsonCommonStatus_without_data(
            statuscode=500, status=False, message="Internal server error"
        )
    finally:
        if session:
            session.close()


@fastapi_app.get(
    "/respond",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    This endpoint captures the response from a doctor and updates the patient's status in the database.
    It requires the response (accept/reject/On-Hold/Pending), patient ID, and a token for verification.
    The token ensures the response is associated with a valid and active email request.
    The patient's status is updated based on the doctor's response.

    Request Parameters:
    response (str): The doctor's response, either "accept" or "reject" or "On-Hold" or "Pending".
    patient_id (str): The ID of the patient whose status needs to be updated.
    token (str): The token sent in the email to verify the request.
    """,
)
def handle_response(response: str, patient_id: str, token: str):
    try:
        session = createconnection()
        patient = session.query(PatientDetails).filter_by(patient_id=patient_id).first()
        if not patient:
            return JsonCommonStatus_without_data(
                statuscode=404, status=False, message="Patient not found"
            )
        email_token = (
            session.query(EmailToken)
            .filter_by(patient_id=patient_id, token=token)
            .first()
        )
        if not email_token:
            logg.error(
                "The mail initiation doesn't exist, for patient_id : ", patient_id
            )
            return JsonCommonStatus_without_data(
                statuscode=404,
                status=False,
                message="The mail initiation doesn't exist!",
            )
        elif email_token.expires_at < datetime.now(timezone.utc):
            logg.error("link expired for patient_id : ", patient_id)
            return JsonCommonStatus_without_data(
                statuscode=404, status=False, message="expired link"
            )

        if response == "accept":
            patient.activestat = 1
        else:
            patient.activestat = 0
        session.delete(email_token)
        session.commit()
        return JsonCommonStatus_without_data(
            message=f"Status updated to {response}", statuscode=200, status=True
        )
    except Exception as e:
        logg.error("Exception in repond : ", e)
        return JsonCommonStatus_without_data(
            statuscode=500, status=False, message="Internal Server error!"
        )
    finally:
        if session:
            session.close()


@fastapi_app.get(
    "/weekly-unlock",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The function `fetchWeeklyContent` retrieves weekly content based on user identifier and returns a
    response indicating the status of content availability for each week.
    :param pay_load: The `pay_load` parameter in the `fetchWeeklyContent` function is used to retrieve
    the JSON Web Token (JWT) payload data. This payload typically contains information about the
    authenticated user, such as their user ID or other relevant details. In this case, the function is
    using the `verify_jwt
    :type pay_load: dict
    :return: The `fetchWeeklyContent` function returns a JSON response containing the weekly status
    fetched successfully if the operation is successful. The response includes a status code of 200
    (HTTP_200_OK), a status of True, data containing information about the weekly status, and a message
    indicating the successful fetch.
    """,
)
def fetchWeeklyContent(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        distinct_dates_query = (
            session.query(sqlalchemyfunc.date(APILog.entry_time))
            .filter(APILog.user_identifier == pay_load.get("patient_id"))
            .distinct()
            .all()
        )
        unique_dates_count = len(distinct_dates_query)
        response = {f"week{i}": True if i == 1 else False for i in range(1, 13)}
        for i in range(2, 13):
            if unique_dates_count >= i * 7:
                response[f"week{i}"] = True

        healtHubProgressData = (
            session.query(HealthHubProgress)
            .filter(HealthHubProgress.patient_id == pay_load.get("patient_id"))
            .first()
        )
        if not healtHubProgressData:
            healtHubProgress = HealthHubProgress(
                patient_id=pay_load.get("patient_id"), week_data=json.dumps(response)
            )
            session.add(healtHubProgress)
            session.commit()
            return JsonCommonStatus(
                statuscode=status.HTTP_200_OK,
                status=True,
                data=response,
                message="weekly status fetched successfully",
            )
        healtHubProgressWeekData = json.loads(healtHubProgressData.week_data)
        for i in range(1, 13):
            if unique_dates_count >= i * 7:
                response[f"week{i}"] = (
                    True
                    if healtHubProgressWeekData.get(f"week{i}") is not None
                    and healtHubProgressWeekData.get(f"week{i}") is not True
                    else healtHubProgressWeekData.get(f"week{i}")
                )
            else:
                response[f"week{i}"] = healtHubProgressWeekData.get(f"week{i}")

        updateHealtHubProgressWeekData = (
            update(HealthHubProgress)
            .values(week_data=json.dumps(response))
            .where(HealthHubProgress.patient_id == pay_load.get("patient_id"))
        )
        session.execute(updateHealtHubProgressWeekData)
        session.commit()
        return JsonCommonStatus(
            statuscode=status.HTTP_200_OK,
            status=True,
            data=response,
            message="weekly status fetched successfully",
        )
    except Exception as e:
        print("error in fetchweeklycontent", e)
        return JsonCommonStatus_without_data(
            statuscode=500, status=False, message="Internal Server error!"
        )
    finally:
        if session:
            session.close()


@fastapi_app.get(
    "/getweeklycontent/{week}",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The function `getweeklycontent` retrieves weekly health content based on the provided week parameter
    and handles exceptions gracefully.
    :param week: The `getweeklycontent` function takes a parameter `week` which is a string representing
    the week for which you want to retrieve content. The function then queries the database to fetch the
    content related to that specific week. If the content is found, it constructs a response with the
    week title, description
    :type week: str
    :return: The `getweeklycontent` function returns a JSON response with the fetched content for a
    specific week. If the content for the specified week is found in the database, it returns a JSON
    response with status code 200 and the fetched content details including week title, week
    description, and content. If no content is found for the specified week, it returns a JSON response
    with status code 200 and a
    """,
)
def getweeklycontent(week: str, pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        query = session.query(WeekDetails).filter(WeekDetails.week == week).first()
        if not query:
            return JsonCommonStatus_without_data(
                message="No content found !", statuscode=200, status=True
            )
        finaloutput = {
            "week_title": query.week_title,
            "week_objective": query.week_objective,
            "week_activity": query.week_activity,
            "week_desc": query.week_desc,
            "week_explanation": query.week_explanation,
            "content": query.content,
        }
        return JsonCommonStatus(
            message="content fetched successfully",
            statuscode=status.HTTP_200_OK,
            status=True,
            data=finaloutput,
        )
    except Exception as e:
        print("error in getweeklycontent", e)
        return JsonCommonStatus_without_data(
            statuscode=500, status=False, message="Internal Server error!"
        )
    finally:
        if session:
            session.close()


@fastapi_app.post(
    "/support-email",
    description="""
    Endpoint to send an email to the user.
    The endpoint accepts a JSON payload containing the following fields:
    - name: The name of the user.
    - subject: The subject of the email.
    - user_email: The email address of the user.
    - message: The body of the email message.

    The endpoint returns a JSON response indicating whether the email was sent successfully or if there was a failure.
    Possible status responses include:
    - "Succeeded": Email was sent successfully.
    - "Failed": Email failed to send.
    - "Internal server error": An error occurred on the server.
""",
)
def support_email(email: EmailSchema):
    try:
        res = send_contact_us_email(
            email.name, email.subject, email.user_email, email.message
        )
        if res["status"] == "Succeeded":
            return JsonCommonStatus_without_data(
                message="Email sent successfully", statuscode=200, status=True
            )
        elif res["status"] == "Failed":
            logg.error("Email not sent, Failed for %s", email.user_email)
            return JsonCommonStatus_without_data(
                message="Email not sent, Failed!", statuscode=200, status=False
            )
    except Exception as e:
        print("Error in sending contact us email.", e)
        return JsonCommonStatus_without_data(
            statuscode=500, status=False, message="Internal server error"
        )


@fastapi_app.get(
    "/get-latest-expertmonitoring",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    The function `getLatesExperMonitoring` retrieves the latest expert monitoring data for a specific
    patient from a database.
    :param pay_load: The `pay_load` parameter in the `getLatesExperMonitoring` function is used to
    verify the JWT token. It is a dictionary containing information extracted from the JWT token, such
    as the `patient_id` needed to fetch the latest expert monitoring data for a specific patient. This
    parameter is
    :type pay_load: dict
    :return: The function `getLatesExperMonitoring` returns a JSON response with the latest expert
    monitoring data for a specific patient. The response includes the patient's feet, weight, blood
    pressure, and pulse readings. If no data is found for the specified patient, a message indicating
    "No data found" is returned. In case of any exceptions or errors during the process, an error
    message with "Internal
    """,
)
def getLatesExperMonitoring(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        PatientDetailsAlias = aliased(PatientDetails)
        query = (
            session.query(
                HealthRecord, PatientDetailsAlias.feet, PatientDetailsAlias.weight
            )
            .outerjoin(
                PatientDetailsAlias,
                HealthRecord.patient_id == PatientDetailsAlias.patient_id,
            )
            .filter(HealthRecord.patient_id == pay_load.get("patient_id"))
            .order_by(desc(HealthRecord.ctimestamp))
            .first()
        )
        if not query:
            return JsonCommonStatus_without_data(
                statuscode=400, status=False, message="No data found"
            )
        finalout = {
            "feet": query[1],
            "weight": query[2],
            "bloodp": query[0].bloodp,
            "pulse": query[0].pulse,
        }
        return JsonCommonStatus(
            message="Latest expert Monitoring fetched successfully",
            statuscode=status.HTTP_200_OK,
            status=True,
            data=finalout,
        )
    except Exception as e:
        print("error in expertmonitoring", e)
        return JsonCommonStatus_without_data(
            statuscode=500, status=False, message="Internal server error"
        )
    finally:
        if session:
            session.close()


@fastapi_app.post("/update-health-hub-Status")
def update_health_hub_Status(
    req: UpdateHealthHubStatus, pay_load: dict = Depends(verify_jwt_token)
):
    try:
        session = createconnection()

        def updateWeekStatus(status, week):
            healtHubProgressData = (
                session.query(HealthHubProgress)
                .filter(HealthHubProgress.patient_id == pay_load.get("patient_id"))
                .first()
            )
            print(healtHubProgressData, "healtHubProgressData")
            if not healtHubProgressData:
                return False
            processData = json.loads(healtHubProgressData.week_data)
            processData[f"week{week}"] = status
            if week != 12 and not processData.get(f"week{week+1}", False):
                processData[f"week{week+1}"] = True
            healtHubProgressData.week_data = json.dumps(processData)
            return True

        if req.skip_week:
            updatedResponse = updateWeekStatus(None, req.skip_week)
        elif req.update_complete_week:
            updatedResponse = updateWeekStatus(True, req.update_complete_week)

        if not updatedResponse:
            return JsonCommonStatus_without_data(
                message="health hub week data not found",
                statuscode=status.HTTP_404_NOT_FOUND,
                status=False,
            )
        session.commit()
        return JsonCommonStatus_without_data(
            message="health hub week Status updated successfully",
            statuscode=status.HTTP_200_OK,
            status=True,
        )
    except Exception as e:
        print("error in update-health-hub-Status", e)
        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
            message="Internal server error",
        )
    finally:
        if session:
            session.close()


@fastapi_app.post(
    "/get-country-code",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    This API provides the typical phone number length (excluding the country code) for all 195 countries.
    By querying the API with a specific country code (e.g., "US" for the United States),
    the API returns the expected phone number length for that country. This can be used for validating phone numbers or
    formatting purposes in applications that require accurate phone number data across different regions.
    """,
)
def get_country_code(req: dict):
    country_code_upper = req.get("country_code").upper()
    if country_code_upper in country_map:
        return JsonCommonStatus(
            message="Country mobile length fetched successfully!",
            status=True,
            statuscode=200,
            data={"max_len": country_map[country_code_upper]},
        )
    else:
        return JsonCommonStatus_without_data(
            message="Not a valid country!", status=False, statuscode=401
        )


@fastapi_app.post("/send_tnc")
def emailWithPdf(req: EmailWithPdf):
    try:
        res = send_contact_with_pdf(
            " Important: You've reviewed our Terms and Conditions", req.email
        )
        if res["status"] == "Succeeded":
            return JsonCommonStatus_without_data(
                message="Email sent successfully", statuscode=200, status=True
            )
        elif res["status"] == "Failed":
            logg.error("Email not sent, Failed for %s", req.email)
            return JsonCommonStatus_without_data(
                message="Email not sent, Failed!", statuscode=200, status=False
            )
    except Exception as e:
        print("Error in sending tnc email.", e)
        return JsonCommonStatus_without_data(
            statuscode=500, status=False, message="Internal server error"
        )


@fastapi_app.get(
    "/admin/get_users_with_state/{status}",
    description="""
    This function retrieves a list of users based on their status. It checks the user's role to ensure the request is authorized.
    `NOTE`:
        Classifications of Status
            0:Pending User
            1:Approved User
            2:Users in Hold
            3:Rejected User
            4:undo previous user status
    Parameters:
    - status (int): The status of the users to retrieve. It can be one of the following: 0, 1, 2, or 3.
    - payload (dict): The payload containing the user's role. It is obtained using the `verify_jwt_token` function.
    Returns:
    - If the user's role is authorized, it returns a JSON response containing a list of users with the specified status.
        The "data" field contains a list of dictionaries, where each dictionary represents a user with the specified status.
    - If the user's role is not authorized, it returns a JSON response with a status code of 401 and a message indicating unauthorized access.
    """,
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
)
def getAllUsersWithStatus(status: int, payload: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        if payload.get("role") != 1 and payload.get("role") != 9:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_401_UNAUTHORIZED,
                status=False,
                message="You are not authorized",
            )
        User_with_status = (
            session.query(
                PatientDetails,
                Admin.name.label("admin_name"),
            )
            .outerjoin(Admin, PatientDetails.updated_by == Admin.user_id)
            .filter(PatientDetails.user_status == status)
            .all()
        )
        if not User_with_status:
            return JsonCommonStatus(
                message="No users found", statuscode=200, status=True, data=[]
            )

        def asdict(model_instance):
            return {
                column.name: getattr(model_instance, column.name)
                for column in model_instance.__table__.columns
            }

        serialized_data = [
            {
                **asdict(patient),
                "updated_by": admin_name,
            }
            for patient, admin_name in User_with_status
        ]

        return JsonCommonStatus(
            statuscode=200,
            status=True,
            message="Patient fetched successfully",
            data=serialized_data,
        )
    except Exception as e:
        print("Error in getpendinguser", e)
        return JsonCommonStatus_without_data(
            statuscode=500, status=False, message="Internal server error"
        )
    finally:
        if session:
            session.close()


@fastapi_app.post(
    "/superadmin/createadmin",
    response_model=JsonCommonStatus_without_data,
    description="""
    :Purpose:
This API endpoint is designed for the superadmin to create a new admin account in the system. It checks if the admin already exists by comparing the provided email and mobile number with existing records. If no existing account is found, a new admin account is created with a unique user ID, and the credentials are securely stored.

Request Body:
The request body must contain the following fields as defined by the AdminUser model:

`email (string)`: The email address of the new admin.
`mobile (string)`: The mobile number of the new admin.
`designation (string)`: The role or designation of the admin.
`expiry_date (string)`: The date when the admin account will expire.
`Unique_identification_code (string)`: A unique identifier assigned to the admin by the superadmin.
:Behavior:
`Validation`: The API first checks if an admin account with the provided email or mobile number already exists.
`Account Creation`: If no existing account is found, it generates a unique user ID and securely encodes the password with a salt. It then stores the admin's basic information and credentials in the database.
Error Handling: The API gracefully handles exceptions and returns a meaningful error message without exposing sensitive information.
Database Connection: The session is properly managed to ensure it is closed after the operation, regardless of the outcome.

""",
)
def createAdminAccount(req: AdminUser, pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        if pay_load.get("role") != 9:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_401_UNAUTHORIZED,
                status=False,
                message="You are not authorized",
            )
        previosUser = (
            session.query(Admin)
            .filter(or_(Admin.email == req.email, Admin.mobile == req.mobile))
            .first()
        )
        results_email = (
            session.query(PatientDetails)
            .filter(
                or_(
                    PatientDetails.email == req.email.replace(" ", ""),
                    PatientDetails.mobile == req.mobile,
                )  # noqa: E731
            )
            .first()
        )
        resultDoctorsEmail = (
            session.query(doctorDetails)
            .filter(
                or_(
                    doctorDetails.email == req.email.replace(" ", ""),
                    doctorDetails.mobile == req.mobile.replace(" ", ""),
                )
            )
            .first()
        )
        if not previosUser and not results_email and not resultDoctorsEmail:
            sAdminUser = (
                session.query(UIC_Creds)
                .filter(UIC_Creds.email == req.super_admin_email)
                .first()
            )
            if not sAdminUser:
                return JsonCommonStatus_without_data(
                    statuscode=status.HTTP_400_BAD_REQUEST,
                    status=False,
                    message="This UIC is not linked with this mail ID or invalid UIC",
                )
            if not verify_password(
                req.Unique_identification_code, sAdminUser.salt, sAdminUser.UIC
            ):
                return JsonCommonStatus_without_data(
                    statuscode=status.HTTP_400_BAD_REQUEST,
                    status=False,
                    message="Invalid code. Please enter a valid code",
                )
            generate_user_id = patient_id_generator()
            timestamp = pd.Timestamp("now")
            hashed_password = hashlib.sha256(
                f"{generate_user_id}{timestamp}".encode()
            ).hexdigest()
            dynamic_password = hashed_password[:8]
            tp, main_ = Encode_password(dynamic_password)
            salt, password = main_[0], main_[1]
            adminUserData = Admin(
                email=req.email.strip(),
                mobile=req.mobile,
                user_id=generate_user_id,
                designation=req.designation,
                assigned_date=timestamp.strftime("%Y-%m-%d %X"),
                expiry_date=req.expiry_date,
                assigned_by=sAdminUser.name if sAdminUser else "",
                Unique_identification_code="",
                nationality=req.nationality,
                name=req.name,
            )
            adminCreddata = AdminCreds(
                user_id=generate_user_id,
                password=password,
                salt=salt,
                tempwddate=timestamp.strftime("%Y-%m-%d %X"),
            )
            session.add(adminUserData)
            session.add(adminCreddata)
            session.commit()

            send_tempwd_email(
                req.name,
                "Temporary Password",
                req.email.strip(),
                dynamic_password,
            )
            return JsonCommonStatus_without_data(
                status=True,
                statuscode=status.HTTP_201_CREATED,
                message="Admin created successfully",
            )
        return JsonCommonStatus_without_data(
            status=False,
            statuscode=status.HTTP_302_FOUND,
            message="Account with this email or mobile alredy exist",
        )
    except Exception as e:
        print("Error in createadminaccount", e)
        return JsonCommonStatus_without_data(
            statuscode=500, status=False, message="Internal server error"
        )
    finally:
        if session:
            session.close()


@fastapi_app.get(
    "/superadmin/getalladmin",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
    description="""
    `Purpose:`
      This API endpoint allows the superadmin to retrieve a list of all admin users in the system. It queries the database for all admin records, serializes the data, and returns it in a structured format. If an error occurs, it responds with an appropriate error message.
    `Behavior:
`Fetching Admin Data:` The API queries the Admin table to fetch all admin users.
Data Serialization: Each admin user record is serialized into a dictionary format for easier JSON conversion using a helper function asdict.
Response Handling: The API returns a success response with all admin users if data retrieval is successful. If an error occurs, it catches the exception, logs it, and returns an appropriate error message.
Database Session Management: The session is closed properly in the finally block to ensure resources are released, regardless of success or failure.`
    """,
)
def getalladmin(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        if pay_load.get("role") != 9:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_401_UNAUTHORIZED,
                status=False,
                message="You are not authorized",
            )
        allAdminUser = (
            session.query(Admin)
            .filter(Admin.role_id == 1, Admin.active_state == True)
            .order_by(desc(Admin.admin_id))
            .all()
        )

        def asdict(model_instance):
            return {
                column.name: getattr(model_instance, column.name)
                for column in model_instance.__table__.columns
                if column.name != "Unique_identification_code"
            }

        serialized_data = []

        for patient in allAdminUser:
            mapedresult = asdict(patient)
            if mapedresult["nationality"] is not None:
                nationality_lower = mapedresult["nationality"].lower()
                if nationality_lower in nationality_to_country_code:
                    country_code = nationality_to_country_code[nationality_lower]
                    max_len = (
                        country_map[country_code] if country_code in country_map else 0
                    )
                    dial_code = dail_code[country_code]

                    mapedresult["mobile_checks"] = {
                        "country_code": country_code,
                        "max_len": max_len,
                        "Dial_Code": dial_code,
                    }
            else:
                mapedresult["mobile_checks"] = {
                    "country_code": None,
                    "max_len": None,
                    "Dial_Code": None,
                }

            # Checking for expired account
            if pd.to_datetime(mapedresult["expiry_date"]) < pd.Timestamp("now"):
                mapedresult["expired"] = True
            else:
                mapedresult["expired"] = False
            serialized_data.append(mapedresult)
        return JsonCommonStatus(
            statuscode=200,
            status=True,
            message="Admin users fetched successfully",
            data=serialized_data,
        )
    except Exception as e:
        print("Error in getAllAdmin", e)
        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
            message="Internal server error",
        )
    finally:
        if session:
            session.close()


@fastapi_app.post(
    "/createsuperadmin",
    response_model=JsonCommonStatus_without_data,
    description="""
    :Purpose:
This API endpoint is designed for the superadmin to create a new admin account in the system. It checks if the admin already exists by comparing the provided email and mobile number with existing records. If no existing account is found, a new admin account is created with a unique user ID, and the credentials are securely stored.

Request Body:
The request body must contain the following fields as defined by the AdminUser model:

`email (string)`: The email address of the new admin.
`mobile (string)`: The mobile number of the new admin.
`designation (string)`: The role or designation of the admin.
`expiry_date (string)`: The date when the admin account will expire.
`Unique_identification_code (string)`: A unique identifier assigned to the admin by the superadmin.
:Behavior:
`Validation`: The API first checks if an admin account with the provided email or mobile number already exists.
`Account Creation`: If no existing account is found, it generates a unique user ID and securely encodes the password with a salt. It then stores the admin's basic information and credentials in the database.
Error Handling: The API gracefully handles exceptions and returns a meaningful error message without exposing sensitive information.
Database Connection: The session is properly managed to ensure it is closed after the operation, regardless of the outcome.

""",
)
def createSuperAdminAccount(req: SuperAdminUser):
    try:
        session = createconnection()
        previosUser = (
            session.query(Admin)
            .filter(or_(Admin.email == req.email, Admin.mobile == req.mobile))
            .first()
        )
        results_email = (
            session.query(PatientDetails)
            .filter(
                or_(
                    PatientDetails.email == req.email.replace(" ", ""),
                    PatientDetails.mobile == req.mobile,
                )  # noqa: E731
            )
            .first()
        )
        resultDoctorsEmail = (
            session.query(doctorDetails)
            .filter(
                or_(
                    doctorDetails.email == req.email.replace(" ", ""),
                    doctorDetails.mobile == req.mobile.replace(" ", ""),
                )
            )
            .first()
        )
        if not previosUser and not results_email and not resultDoctorsEmail:
            generate_user_id = patient_id_generator()
            timestamp = pd.Timestamp("now")
            tp, main_ = Encode_password(req.password)
            salt, password = main_[0], main_[1]
            adminUserData = Admin(
                email=req.email.strip(),
                mobile=req.mobile,
                user_id=generate_user_id,
                designation=req.designation,
                assigned_date=timestamp.strftime("%Y-%m-%d %X"),
                expiry_date=req.expiry_date,
                assigned_by=None,
                Unique_identification_code=req.Unique_identification_code,
                role_id=9,
                name=req.name,
                nationality=req.nationality,
            )
            adminCreddata = AdminCreds(
                user_id=generate_user_id, password=password, salt=salt
            )
            session.add(adminUserData)
            session.add(adminCreddata)
            session.commit()
            return JsonCommonStatus_without_data(
                status=True,
                statuscode=status.HTTP_201_CREATED,
                message="super Admin created successfully",
            )
        return JsonCommonStatus_without_data(
            status=False,
            statuscode=status.HTTP_302_FOUND,
            message="Account with this email or mobile alredy exist",
        )
    except Exception as e:
        print("Error in createSuperadminaccount", e)
        return JsonCommonStatus_without_data(
            statuscode=500, status=False, message="Internal server error"
        )
    finally:
        if session:
            session.close()


@fastapi_app.put(
    "/superadmin/updateadmindetails",
    response_model=JsonCommonStatus_without_data,
    description="""
                 `Purpose:`
This endpoint allows authorized users, specifically those with the role of superadmin (role code "9"), to update the details of an existing admin user in the system. The fields that can be updated include the admin's name, email, mobile number, designation, and expiry date. Only the specified fields provided in the request will be updated, leaving the others unchanged.
                 """,
)
def updateAdminDetails(
    req: UpdateAdminUser, pay_load: dict = Depends(verify_jwt_token)
):
    try:
        session = createconnection()
        if pay_load.get("role") != 9:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_401_UNAUTHORIZED,
                status=False,
                message="You are not authorized",
            )
        admin = session.query(Admin).filter(Admin.user_id == req.user_id).first()
        if not admin:
            return JsonCommonStatus_without_data(
                status=False,
                statuscode=status.HTTP_404_NOT_FOUND,
                message="Admin not found",
            )
        if admin.Unique_identification_code != req.Unique_identification_code:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_401_UNAUTHORIZED,
                status=False,
                message="You are not permitted to edit this profile",
            )

        if req.name is not None:
            admin.name = req.name
        if req.email is not None:
            admin.email = req.email
        if req.mobile is not None:
            admin.mobile = req.mobile
        if req.designation is not None:
            admin.designation = req.designation
        if req.expiry_date is not None:
            admin.expiry_date = req.expiry_date
            send_account_expiration_extension_email(
                name=admin.name, user_email=admin.email, extension_date=req.expiry_date
            )
        if req.nationality is not None:
            admin.nationality = req.nationality

        session.commit()

        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_200_OK,
            status=True,
            message="Admin details updated successfully",
        )

    except Exception as e:
        print("Error in createSuperadminaccount", e)
        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
            message="Internal server error",
        )
    finally:
        if session:
            session.close()


@fastapi_app.delete(
    "/superadmin/delete_admin_user/{user_id}",
    response_model=JsonCommonStatus_without_data,
)
def delete_admin_user(user_id: str, pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        if pay_load.get("role") != 9:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_401_UNAUTHORIZED,
                status=False,
                message="You are not authorized",
            )
        accountExistance = session.query(AdminCreds).filter(
            AdminCreds.user_id == user_id
        )
        if not accountExistance:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_404_NOT_FOUND,
                status=False,
                message="Admin user not found",
            )

        deleteAdminUserQuery = delete(AdminCreds).where(AdminCreds.user_id == user_id)
        UpdateAdminState = (
            update(Admin).values({"active_state": 0}).where(Admin.user_id == user_id)
        )
        session.execute(deleteAdminUserQuery)
        session.execute(UpdateAdminState)
        session.commit()
        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_200_OK,
            status=True,
            message="Admin user deleted successfully",
        )

    except Exception as e:
        print("Error in deleteadminaccount", e)
        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
            message="Internal server error",
        )
    finally:
        if session:
            session.close()


@fastapi_app.get(
    "/getadmin_details",
    response_model=Union[JsonCommonStatus, JsonCommonStatus_without_data],
)
def getAdminDetails(pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        if pay_load.get("role") != 1 and pay_load.get("role") != 9:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_401_UNAUTHORIZED,
                status=False,
                message="You are not authorized",
            )
        AdminUserDetails = (
            session.query(Admin)
            .filter(
                Admin.role_id == pay_load.get("role"),
                Admin.active_state == True,
                Admin.user_id == pay_load.get("user_id"),
            )
            .all()
        )

        def asdict(model_instance, exclude_columns=None):
            exclude_columns = exclude_columns or []
            return {
                column.name: getattr(model_instance, column.name)
                for column in model_instance.__table__.columns
                if column.name not in exclude_columns
            }

        for admindata in AdminUserDetails:
            mapedresult = asdict(
                admindata, exclude_columns=["admin_id", "active_state"]
            )
            if mapedresult["nationality"] is not None:
                nationality_lower = mapedresult["nationality"].lower()
                if nationality_lower in nationality_to_country_code:
                    country_code = nationality_to_country_code[nationality_lower]
                    max_len = (
                        country_map[country_code] if country_code in country_map else 0
                    )
                    dial_code = dail_code[country_code]

                    mapedresult["mobile_checks"] = {
                        "country_code": country_code,
                        "max_len": max_len,
                        "Dial_Code": dial_code,
                    }
            else:
                mapedresult["mobile_checks"] = {
                    "country_code": None,
                    "max_len": None,
                    "Dial_Code": None,
                }
            if mapedresult["designation"] != "NA":
                part1, part2, part3 = mapedresult.get("user_id").split("-")
                blob_name_without_extension = (
                    f"{part1}{mapedresult.get('designation')}{part3}{part2}_profile_img"
                )
                mapedresult["profile_url"] = get_blob_sas_url(
                    blob_name_without_extension
                )

            return JsonCommonStatus(
                statuscode=200,
                status=True,
                message="Admin users fetched successfully",
                data=mapedresult,
            )
    except Exception as e:
        print("Error in getadminaccount", e)
        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
            message="Internal server error",
        )
    finally:
        if session:
            session.close()


@fastapi_app.put(
    "/admin/change_admin_password", response_model=JsonCommonStatus_without_data
)
def changeAdminPassword(
    req: ChangeAdminPassword, pay_load: dict = Depends(verify_jwt_token)
):
    try:
        session = createconnection()
        user_query = (
            session.query(AdminCreds)
            .filter(AdminCreds.user_id == pay_load.get("user_id"))
            .first()
        )
        if not user_query:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_404_NOT_FOUND,
                status=False,
                message="Admin user not found",
            )
        if verify_password(
            req.temporary_password, user_query.salt, user_query.password
        ):
            tp, main_ = Encode_password(req.new_password)
            salt, password = main_[0], main_[1]
            user_query.password = password
            user_query.salt = salt
            user_query.pwdchanged = 1
            session.commit()

            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_200_OK,
                status=True,
                message="Admin password changed successfully",
            )
        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_401_UNAUTHORIZED,
            status=False,
            message="Invalid credentials. Please try again.",
        )

    except Exception as e:
        print("Error in changeadminpassword", e)
        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
            message="Internal server error",
        )
    finally:
        if session:
            session.close()


@fastapi_app.put(
    "/admin/set_user_state",
    description="""
    Update the status of a patient in the system.
    `NOTE`:
        Classifications of Status
            0:Pending User
            1:Approved User
            2:Users in Hold
            3:Rejected User
            4:undo previous user status
    Parameters:
    req (ChangeUserStatus): An object containing the patient ID and the new status.
    pay_load (dict): The payload containing the user's authentication information.
    Returns:
    JsonCommonStatus_without_data: A response object indicating the success or failure of the operation.
    """,
    response_model=JsonCommonStatus_without_data,
)
def setUserStatus(req: ChangeUserStatus, pay_load: dict = Depends(verify_jwt_token)):
    try:
        session = createconnection()
        if pay_load.get("role") != 9 and pay_load.get("role") != 1:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_401_UNAUTHORIZED,
                status=False,
                message="You are not authorized",
            )
        if req.status not in [0, 1, 2, 3, 4]:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_400_BAD_REQUEST,
                status=False,
                message="Invalid status. Please provide valid status",
            )
        get_patient_details = (
            session.query(PatientDetails)
            .filter(PatientDetails.patient_id == req.patient_id)
            .first()
        )
        if not get_patient_details:
            return JsonCommonStatus_without_data(
                statuscode=status.HTTP_404_NOT_FOUND,
                status=False,
                message="Patient not found",
            )
        if req.status == 1:
            get_patient_details.activestat = 1
            get_patient_details.remark = None
            get_patient_details.updated_date = pd.Timestamp("now").strftime("%Y-%m-%d")
            get_patient_details.updated_by = pay_load.get("user_id")
        else:
            get_patient_details.activestat = 0

        get_patient_details.user_status = req.status
        if req.status in [0, 2, 3]:
            if req.remark is not None:
                get_patient_details.remark = req.remark
                get_patient_details.updated_by = pay_load.get("user_id")
            else:
                return JsonCommonStatus_without_data(
                    statuscode=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    status=False,
                    message="A remark is required for this status.",
                )
        if req.status == 4:
            get_patient_details.user_status = 0
            get_patient_details.remark = None
        else:
            req.status
        session.commit()
        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_200_OK,
            status=True,
            message="Patient status updated successfully",
        )
    except Exception as e:
        print("Error in setUserStatus", e)
        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            status=False,
            message="Internal server error",
        )
    finally:
        if session:
            session.close()


@fastapi_app.get("/termsandconditions", response_model=JsonCommonStatus)
def termsandconditions():
    htmlContent = """
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Terms and Conditions</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
            padding: 0;
        }
        h1, h2, h3 {
            color: #333;
        }
        h1 {
            text-align: center;
        }
        p {
            margin: 1em 0;
        }
        ul {
            margin: 0;
            padding-left: 20px;
        }
    </style>
</head>
<body>
    <h1>HelloAlfred Web or Digital App Terms of Use</h1>
    <p>Last Updated: 6/16/24</p>
    <h2>1. Acceptance of Terms</h2>
    <p>By creating an account or using the App, you confirm that you are at least 18 years old and capable of entering into a legally binding agreement. If you are under 18, you must have the permission of a parent or guardian to use the App.</p>
    <h2>2. Privacy Policy</h2>
    <p>Your privacy is important to us. Please review our <a href="https://dev.helloalfred.ai/#/privacypolicy">Privacy Policy</a>, which explains how we collect, use, and share your information.</p>
    <h2>3. Use of the App</h2>
    <p><strong>3.1 Personal Use:</strong> The App is provided for your personal, non-commercial use only.</p>
    <p><strong>3.2 Prohibited Activities:</strong> You agree not to:</p>
    <ul>
        <li>Use the App for any illegal purpose.</li>
        <li>Violate any applicable local, state, national, or international law.</li>
        <li>Engage in any activity that could harm or interfere with the operation of the App.</li>
        <li>Attempt to gain unauthorized access to any part of the App or its systems.</li>
        <li>Use the App to distribute viruses or other harmful software.</li>
    </ul>
    <h2>4. Health Information</h2>
    <p><strong>4.1 Not Medical Advice:</strong> The App provides health-related information but is not a substitute for professional medical advice, diagnosis, or treatment. Always seek the advice of your physician or other qualified health provider with any questions you may have regarding a medical condition.</p>
    <p><strong>4.2 Accuracy of Information:</strong> While we strive to provide accurate and up-to-date information, we cannot guarantee the accuracy, completeness, or timeliness of any information provided through the App.</p>
    <h2>5. User Content</h2>
    <p><strong>5.1 Ownership:</strong> You retain ownership of any content you post or upload to the App ("User Content"). By posting User Content, you grant us a non-exclusive, royalty-free, worldwide, transferable, and sublicensable license to use, reproduce, modify, display, and distribute your User Content in connection with the App.</p>
    <p><strong>5.2 Prohibited Content:</strong> You agree not to post any User Content that:</p>
    <ul>
        <li>Is false, misleading, or fraudulent.</li>
        <li>Is defamatory, obscene, offensive, or otherwise objectionable.</li>
        <li>Infringes the rights of any third party, including intellectual property rights.</li>
        <li>Contains personal information of another person without their consent.</li>
    </ul>
    <h2>6. Data Use and Rights</h2>
    <p><strong>6.1 Data Collection:</strong> We collect various types of information in connection with your use of the App, including personal information and health-related data. This information is collected in accordance with our Privacy Policy.</p>
    <p><strong>6.2 Data Use:</strong> The data we collect is used to provide and improve the App, customize your user experience, communicate with you, and for other purposes described in our Privacy Policy. We may also use aggregated and anonymized data for research and analytics purposes.</p>
    <p><strong>6.3 Data Sharing:</strong> We do not sell your personal information. We may share your data with third parties as described in our Privacy Policy, including with service providers who assist us in operating the App and with healthcare professionals if you choose to share your information with them.</p>
    <p><strong>6.4 Data Security:</strong> We implement appropriate technical and organizational measures to protect your data against unauthorized access, alteration, disclosure, or destruction. However, no security measures are completely foolproof, and we cannot guarantee the security of your data.</p>
    <p><strong>6.5 Data Rights:</strong> Depending on your jurisdiction, you may have certain rights regarding your data, including the right to access, correct, delete, or restrict the use of your data. You may also have the right to object to the processing of your data or to request data portability. To exercise these rights, please contact us at [Contact Information].</p>
    <h2>7. Artificial Intelligence Use</h2>
    <p><strong>7.1 AI Functionality:</strong> The App may use artificial intelligence (AI) technologies to provide certain features and functionalities, such as personalized recommendations, health assessments, and data analysis.</p>
    <p><strong>7.2 AI Data Use:</strong> Data processed by our AI systems may include personal and health-related information. This data is used to improve the accuracy and effectiveness of our AI-driven features and to enhance your user experience.</p>
    <p><strong>7.3 Limitations of AI:</strong> While our AI technologies are designed to assist and enhance your use of the App, they are not infallible. AI-generated insights and recommendations are not a substitute for professional medical advice, diagnosis, or treatment. Always consult with a qualified healthcare provider before making decisions based on AI-generated information.</p>
    <p><strong>7.4 Transparency:</strong> We strive to ensure transparency in our use of AI technologies. You can learn more about how we use AI and the data involved in our Privacy Policy [Link to Privacy Policy].</p>
    <p><strong>7.5 User Consent:</strong> By using the App, you consent to the processing of your data by our AI systems as described in these Terms and our Privacy Policy.</p>
    <h2>8. Accounts, Passwords, and Security</h2>
    <p><strong>8.1 Account Creation:</strong> To use certain features of the App, you may need to create an account. You agree to provide accurate, current, and complete information during the registration process and to update such information to keep it accurate, current, and complete.</p>
    <p><strong>8.2 Account Security:</strong> You are responsible for maintaining the confidentiality of your account credentials, including your username and password, and for all activities that occur under your account. You agree to:</p>
    <ul>
        <li>Promptly notify us of any unauthorized use of your account or any other breach of security.</li>
        <li>Ensure that you exit from your account at the end of each session, especially when accessing the App from a public or shared device.</li>
    </ul>
    <p><strong>8.3 Account Termination:</strong> We reserve the right to suspend or terminate your account at any time, without prior notice, for any reason, including if we believe you have violated these Terms. Upon termination, your right to use the App will immediately cease.</p>
    <h2>9. Links to Other Sites and the Digital App</h2>
    <p><strong>9.1 Third-Party Links:</strong> The App may contain links to third-party websites or services that are not owned or controlled by us. We have no control over, and assume no responsibility for, the content, privacy policies, or practices of any third-party websites or services. You acknowledge and agree that we are not responsible or liable, directly or indirectly, for any damage or loss caused or alleged to be caused by or in connection with the use of or reliance on any such content, goods, or services available on or through any such websites or services.</p>
    <p><strong>9.2 Linking to the App:</strong> You may link to the App, provided you do so in a way that is fair and legal and does not damage our reputation or take advantage of it. You must not establish a link in such a way as to suggest any form of association, approval, or endorsement on our part where none exists. We reserve the right to withdraw linking permission without notice.</p>
    <h2>10. Violation of the Above Terms of Use</h2>
    <p><strong>10.1 Consequences of Violation:</strong> If you violate these Terms, we may take actions that we deem appropriate, including but not limited to:</p>
    <ul>
        <li>Issuing a warning.</li>
        <li>Suspending or terminating your account.</li>
        <li>Blocking your access to the App.</li>
        <li>Taking legal action against you.</li>
    </ul>
    <p><strong>10.2 Reporting Violations:</strong> If you become aware of any misuse of the App or any violation of these Terms, please report it to us immediately at [Contact Information].</p>
    <p><strong>10.3 Cooperation with Authorities:</strong> We reserve the right to cooperate fully with law enforcement authorities or court orders requesting or directing us to disclose the identity of anyone using the App in a manner that violates these Terms or any applicable law.</p>
    <h2>11. Intellectual Property</h2>
    <p>All intellectual property rights in the App, including but not limited to trademarks, service marks, logos, and copyrighted materials, are owned by us or our licensors. You agree not to use any such intellectual property without our prior written consent.</p>
    <h2>12. Disclaimers and Limitation of Liability</h2>
    <p><strong>12.1 Disclaimers:</strong> The App is provided "as is" and "as available" without any warranties of any kind, either express or implied. We do not warrant that the App will be uninterrupted or error-free.</p>
    <p><strong>12.2 Limitation of Liability:</strong> To the maximum extent permitted by law, we shall not be liable for any indirect, incidental, special, consequential, or punitive damages, or any loss of profits or revenues, whether incurred directly or indirectly, or any loss of data, use, goodwill, or other intangible losses, resulting from:</p>
    <ul>
        <li>Your use of or inability to use the App.</li>
        <li>Any unauthorized access to or use of our servers and/or any personal information stored therein.</li>
        <li>Any errors or omissions in the App.</li>
    </ul>
    <h2>13. Indemnification</h2>
    <p>You agree to indemnify, defend, and hold harmless [App Name], its affiliates, and their respective officers, directors, employees, and agents from and against any claims, liabilities, damages, losses, and expenses, including reasonable attorneys' fees, arising out of or in any way connected with your use of the App or violation of these Terms.</p>
    <h2>14. Termination</h2>
    <p>We may terminate or suspend your access to the App at any time, without prior notice or liability, for any reason, including if you breach these Terms. Upon termination, your right to use the App will immediately cease.</p>
    <h2>15. Governing Law</h2>
    <p>These Terms shall be governed by and construed in accordance with the laws of State of Texas, without regard to its conflict of law principles. Any legal action or proceeding arising under these Terms will be brought exclusively in the federal or state courts located in State of Texas.</p>
    <p><strong>15.1. Texas-Specific Terms:</strong> Consumer Protection: These Terms are subject to the provisions of the Texas Deceptive Trade Practices-Consumer Protection Act. If any provision of these Terms conflicts with the Act, the conflicting provision shall be considered modified to the extent necessary to comply with the Act.</p>
    <p><strong>15.2 Texas-Specific Terms:</strong> Notification: In accordance with Texas Business and Commerce Code Section 17.505, you must notify us in writing of any alleged defect or breach of these Terms and allow us 60 days to remedy the issue before initiating any legal action.</p>
    <h2>16. Changes to Terms</h2>
    <p>We reserve the right to modify these Terms at any time. Any changes will be effective immediately upon posting the updated Terms on the App. Your continued use of the App following the posting of changes constitutes your acceptance of those changes.</p>
    <h2>17. Miscellaneous Terms</h2>
    <p><strong>17.1 Entire Agreement:</strong> These Terms, together with the Privacy Policy and any other legal notices published by us on the App, constitute the entire agreement between you and us concerning your use of the App.</p>
    <p><strong>17.2 Severability:</strong> If any provision of these Terms is found to be invalid, illegal, or unenforceable, the remaining provisions will continue in full force and effect.</p>
    <p><strong>17.3 Waiver:</strong> Our failure to enforce any right or provision of these Terms will not be considered a waiver of those rights. Any waiver of any provision of these Terms will be effective only if in writing and signed by us.</p>
    <p><strong>17.4 Assignment:</strong> We may assign our rights and obligations under these Terms to any party at any time without notice to you. You may not assign your rights or obligations under these Terms without our prior written consent.</p>
    <p><strong>17.5 Force Majeure:</strong> We will not be liable for any failure or delay in performance due to any cause beyond our reasonable control, including but not limited to acts of God, war, strikes, labor disputes, embargoes, government orders, or any other force majeure event.</p>
    <h2>18. Contact Us</h2>
    <p>If you have any questions about these Terms, please contact us at [Contact Information].</p>
</body>
</html>
    """
    return JsonCommonStatus(
        statuscode=200,
        status=True,
        message="Terms of Service fetched successfully",
        data={"result": htmlContent},
    )


@fastapi_app.put(
    "/updateadminaccount",
    response_model=JsonCommonStatus_without_data,
    description="""
                The function updateAdminAccount is responsible for updating admin account details in a FastAPI application. It handles exceptions and ensures proper database connection management.""",
)
def updateAdminAccount(
    req: UpdateAdminDetails, pay_load: dict = Depends(verify_jwt_token)
):
    try:
        session = createconnection()
        admin = (
            session.query(Admin)
            .filter(Admin.user_id == pay_load.get("user_id"))
            .first()
        )
        if not admin:
            return JsonCommonStatus_without_data(
                status=False,
                statuscode=status.HTTP_404_NOT_FOUND,
                message="Admin not found",
            )

        if req.name is not None:
            admin.name = req.name
        if req.email is not None:
            admin.email = req.email
        if req.mobile is not None:
            admin.mobile = req.mobile
        if req.designation is not None:
            admin.designation = req.designation
        if req.nationality is not None:
            admin.nationality = req.nationality

        session.commit()

        return JsonCommonStatus_without_data(
            statuscode=status.HTTP_200_OK,
            status=True,
            message="Admin details updated successfully",
        )
    except Exception as e:
        print("Error updating admin account", e)
        return JsonCommonStatus_without_data(
            status=False,
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="Internal server error",
        )


@fastapi_app.post(
    "/superadmin/uic_generator", response_model=JsonCommonStatus_without_data
)
def uicgenerator(body: Uic_generator, pay_load: dict = Depends(verify_jwt_token)):
    if (
        body.user_desg == ""
        or body.user_email == ""
        or body.user_name == ""
        or body.user_phn == ""
    ):
        return JsonCommonStatus_without_data(
            status=False,
            statuscode=403,
            message="Please fill all the fields",
        )
    try:
        session = createconnection()
        existing_user = (
            session.query(UIC_Creds)
            .filter(
                UIC_Creds.email == body.user_email,
                UIC_Creds.phone_number == body.user_phn,
            )
            .first()
        )
        if existing_user:
            return JsonCommonStatus(
                message="Sorry This email or phone number is already used by another SuperAdmin",
                status=False,
                statuscode=409,
            )
        decode_uic = generate_uic_code()
        _, enc_pass = Encode_password(decode_uic)
        salt, uic = enc_pass[0], enc_pass[1]
        new_user = UIC_Creds(
            name=body.user_name,
            email=body.user_email,
            phone_number=body.user_phn,
            designation=body.user_desg,
            UIC=uic,
            salt=salt,
        )
        session.add(new_user)
        session.commit()
        session.close()
        send_uic(body.user_name, decode_uic, body.user_email)
        return JsonCommonStatus_without_data(
            status=True,
            statuscode=status.HTTP_200_OK,
            message=f"UIC for {body.user_name} generated succesfully!",
        )
    except Exception as e:
        print("Code got failed while generating UIC")
        return JsonCommonStatus_without_data(
            status=False,
            statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message=f"Internal Server Error: {str(e)}",
        )


@fastapi_app.post(
    "/admin/get_conversation",
    description=""""
    The function `getoldconversation` retrieves education history records for a specific patient or user
    within the last 7 days and formats the output in a JSON response.
    :param pay_load: The `pay_load` parameter in the `getoldconversation` function is used to pass a
    dictionary containing information about the user or patient whose education history records need to
    be retrieved. The function uses this payload to filter the records based on the `patient_id` or
    `user_id` provided in the
    :type pay_load: dict
    :return: The function `getoldconversation` returns a JSON response containing the fetched data in a
    specific format. The response includes a status indicating whether the data was fetched
    successfully, a status code, a message, and the fetched data in JSON format. If an exception occurs
    during the process, an error response is returned with details of the internal server error.""",
    response_model=Union[JsonCommonStatus_without_data, JsonCommonStatus],
)
def getoldconversation(pay_load: dict = Depends(verify_jwt_token)):

    try:
        today = pd.Timestamp("now").date()
        yesterday = today - pd.Timedelta(days=1)
        seven_days_ago = today - pd.Timedelta(days=7)

        session = createconnection()

        if "patient_id" in pay_load:
            records = (
                session.query(EducationHistory)
                .filter(EducationHistory.patient_id == pay_load.get("patient_id"))
                .filter(EducationHistory.cdate >= seven_days_ago)
                .all()
            )
        elif "user_id" in pay_load:
            records = (
                session.query(EducationHistory_admin)
                .filter(EducationHistory_admin.user_id == pay_load.get("user_id"))
                .filter(EducationHistory_admin.cdate >= seven_days_ago)
                .order_by(desc(EducationHistory_admin.cdate))
                .all()
            )

        result_json = {"today": [], "yesterday": [], "past_7_days": []}

        for record in records:
            if record.cdate == today:
                result_json["today"].append(record)
            elif record.cdate == yesterday:
                result_json["yesterday"].append(record)
            else:
                result_json["past_7_days"].append(record)

        total_entries = (
            result_json["today"] + result_json["yesterday"] + result_json["past_7_days"]
        )
        if len(total_entries) > 8:
            limited_entries = (
                result_json["today"][:8]
                + result_json["yesterday"][: max(0, 8 - len(result_json["today"]))]
                + result_json["past_7_days"][
                    : max(
                        0, 8 - len(result_json["today"]) - len(result_json["yesterday"])
                    )
                ]
            )
        else:
            limited_entries = total_entries

        final_output = {
            "records": [
                {
                    **record.__dict__,
                    "cdate": pd.to_datetime(record.__dict__["cdate"]).strftime(
                        "%Y-%m-%d"
                    ),  # Convert timestamp to date
                }
                for record in limited_entries
            ],
            "count": len(limited_entries),
        }
        final_json_str = json.dumps(final_output, default=str)
        if not final_output["records"]:
            return JsonCommonStatus(
                status=True,
                statuscode=204,
                message="No records found",
                data=final_json_str,
            )
        return JsonCommonStatus(
            status=True,
            statuscode=200,
            message="Data Fetched Succesfully",
            data=final_json_str,
        )

    except Exception as e:
        print("Code got failed while getting old conversation:- ", e)
        return JsonCommonStatus_without_data(
            status=False,
            statuscode=500,
            message=f"Internal Server Error: {str(e)}",
        )
    finally:
        if session:
            session.close()


@fastapi_app.post("/patient/get_video_link", response_model=JsonCommonStatus)
def gethealthubvideo():
    main_list = [
        "https://storageaccountforpublic.blob.core.windows.net/publiccontainer/dr._ajay_tripuraneni___“introduction_to_a-fib”.mp4",
        "https://storageaccountforpublic.blob.core.windows.net/publiccontainer/audrey_nicholson,_pac_-_rate_and_rhythm_control_interventions_for_af (1080p).mp4",
        "https://storageaccountforpublic.blob.core.windows.net/publiccontainer/brian_krustchinsky,_pac_-_atrial_fib.mp4",
        "https://storageaccountforpublic.blob.core.windows.net/publiccontainer/jaime_molden,_md.mp4",
        "https://storageaccountforpublic.blob.core.windows.net/publiccontainer/karen_cooper,_agacnp_-_atrial_fib (1080p).mp4",
        "https://storageaccountforpublic.blob.core.windows.net/publiccontainer/karen_cooper,_agacnp_-_atrial_fib.mp4",
    ]
    return JsonCommonStatus(
        data=main_list, status=True, statuscode=200, message="Data Fetched succesfully!"
    )
