from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import pandas as pd
import ast
import uuid
from datetime import datetime, timedelta, timezone
import jwt
import json
from fastapi import HTTPException, Header, Response, Request
from typing import Optional
from fastapi.security import HTTPBearer
import hashlib
import secrets
import os
import string

# import redis
import random
from azure.communication.email import EmailClient
from langchain_openai import AzureChatOpenAI
from langchain.chains import ConversationChain
from langchain.chains.conversation.memory import ConversationBufferMemory
from schemas import EmailToken
import time
import function_app
from azure.storage.blob import generate_blob_sas, BlobSasPermissions, BlobServiceClient


security = HTTPBearer()


def createconnection():
    try:
        connection_string = function_app.client.get_secret("MYSQLDBCONNECTION").value
        print("The connection string is:- ", connection_string, flush=True)
        engine = create_engine(
            connection_string, echo=True, pool_size=20, max_overflow=0
        )
        Session = sessionmaker(bind=engine)
        session = Session()
        return session
    except Exception as e:
        print("error in create connection-----", e)


def redis_connection():
    # host = "alfredcrud.redis.cache.windows.net"
    # port = "6380"
    # ssl_enabled = True
    # password = "IJTOyg6jKnPhgLj3tOqAD0Nn0N2oJ7Ch4AzCaH00gYE="
    # r = redis.StrictRedis(
    #     host=host, port=port, ssl=ssl_enabled, password=password, decode_responses=True
    # )
    return "Redis Not yet Active"


# def mongocreateconnection():
#     connectionstring = "mongodb+srv://alfred:admin_123@alfred.mongocluster.cosmos.azure.com/?tls=true&authMechanism=SCRAM-SHA-256&retrywrites=false&maxIdleTimeMS=120000"
#     myclient = pymongo.MongoClient(connectionstring)
#     mydb = myclient["alfred"]
#     return mydb


def parse_header(req):
    req_body_bytes = req
    req_body = req_body_bytes.decode("utf-8")
    req_body = ast.literal_eval(req_body)
    return req_body


def patient_id_generator():
    return str(uuid.uuid4())[:18]


def jsonCommonStatus(message, code, status):
    return {"statuscode": code, "status": status, "message": message}


def create_jwt_token(data: dict):
    expire = datetime.now(timezone.utc) + timedelta(minutes=600)
    data["exp"] = expire
    return jwt.encode(data, function_app.client.get_secret("SECRET_KEY").value, algorithm=function_app.client.get_secret("ALGORITHM").value)


def verify_jwt_token(authorization: Optional[str] = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Authorization header is missing")
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=401, detail="Invalid authorization scheme. Must be Bearer"
            )

        payload = jwt.decode(
            token, function_app.client.get_secret("SECRET_KEY").value, algorithms=[function_app.client.get_secret("ALGORITHM").value]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except (jwt.InvalidTokenError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")


async def http_exception_handler(request: Request, exc: HTTPException):
    return Response(
        content=json.dumps({"message": exc.detail, "statuscode": exc.status_code})
    )


def recover_original_string(shifted_string):
    original_chars = []
    for char in shifted_string:
        ascii_value = ord(char) - 1
        original_char = chr(ascii_value)
        original_chars.append(original_char)
    return "".join(original_chars)


def reverse_string(input_string):
    return input_string[::-1]


def reverse_modified_string_to_original(modified_string):
    original_string = ""
    for i, char in enumerate(modified_string):
        if i % 2 == 0:
            original_char = chr(ord(char) + 3)
        else:
            original_char = chr(ord(char) + 2)
        original_string += original_char

    return original_string


def decode_password(input_str: str) -> str:
    input_str = recover_original_string(input_str)
    input_str = reverse_string(input_str)
    input_str = reverse_modified_string_to_original(input_str)
    input_str = input_str.swapcase()
    return input_str


def shift_string(input_string):
    shifted_chars = []
    for char in input_string:
        ascii_value = ord(char) + 1
        shifted_char = chr(ascii_value)
        shifted_chars.append(shifted_char)
    return "".join(shifted_chars)


def convert_string_to_modified_string(input_string):
    modified_string = ""
    for i, char in enumerate(input_string):
        if i % 2 == 0:
            modified_char = chr(ord(char) - 3)
        else:
            modified_char = chr(ord(char) - 2)
        modified_string += modified_char

    return modified_string


def custom_salt_and_hash(password):
    salt = secrets.token_bytes(16)  # 16 bytes = 128 bits
    salted_password = salt + password.encode("utf-8")
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return salt, hashed_password


def Encode_password(pass_):
    pass_ = pass_.swapcase()
    pass_ = convert_string_to_modified_string(pass_)
    pass_ = reverse_string(pass_)
    shifted_string = pass_
    converted_to = shift_string(shifted_string)
    enc = custom_salt_and_hash(converted_to)
    return converted_to, enc


def verify_password(entered_password, stored_salt, stored_hashed_password):
    entered_password, funused = Encode_password(entered_password)
    salted_password = stored_salt + entered_password.encode("utf-8")
    computed_hashed_password = hashlib.sha256(salted_password).hexdigest()
    return computed_hashed_password == stored_hashed_password


def otp_generator():
    otp = random.randint(1000, 9999)
    return otp


def email_generation(email, username, otp):
    try:
        connection_string = function_app.client.get_secret("CONNECTIONSTRING").value
        client = EmailClient.from_connection_string(connection_string)
        subject = "HelloAlfred.AI"
        html_content = f"""
                                <p>Dear {username},</p>
                                <p>To complete your verification process, please use the following One-Time Password (OTP): <strong>{otp}</strong>. This code is valid for the next 10 minutes and will allow you to securely access our services.</p>
                                <p>If you did not request this code, please disregard this email or contact our support team immediately for assistance.</p>
                                <p>Thank you from the HA Team.</p>
                                """
        message = {
            "senderAddress": "DoNotReply@5db40576-79c1-4902-b7b1-3e107c47ddb6.azurecomm.net",
            "recipients": {
                "to": [{"address": email}],
            },
            "content": {
                "subject": subject,
                "html": html_content,
            },
        }
        poller = client.begin_send(message)
        result = poller.result()
        return result
    except Exception as e:
        print("error in email otp generater---------------", e)
        return jsonCommonStatus("Internal server error", 500, False)


def calculate_age(birth_date):
    """
    The function `calculate_age` takes a birth date as input and returns the age of the person based on
    the current date.

    :param birth_date: The `birth_date` parameter is expected to be a date in the format 'YYYY-MM-DD'.
    This function calculates the age based on the provided birth date. If the `birth_date` is a string,
    it will be converted to a datetime object using the `datetime.strptime` method before calculating
    the
    :return: The function `calculate_age` returns the age calculated based on the birth date provided.
    """
    if isinstance(birth_date, str):
        birth_date = datetime.strptime(birth_date, "%Y-%m-%d")
    today = pd.Timestamp("now")
    age = (
        today.year
        - birth_date.year
        - ((today.month, today.day) < (birth_date.month, birth_date.day))
    )
    return age


def get_formated_answer(response_from_model, patient_question):
    llm = AzureChatOpenAI(
        api_key="5d1e16305a5e4b348d624342198f8cc2",
        api_version="2024-05-01-preview",
        azure_deployment="TestChatGPT",
        azure_endpoint="https://testingchatgpt4.openai.azure.com/",
        temperature=0,
    )
    conversation = ConversationChain(llm=llm, memory=ConversationBufferMemory())
    conversation.prompt.template = f"""
    You are an expert AI assistant who answers patient questions with extreme empathy and provides emotional support. You receive a response generated by another model in text format. Your task is to infuse empathy and emotional support into the response while avoiding being overly dramatic. Format the enhanced response in HTML with proper use of <strong> tags and bullet points wherever needed. Here is the response you need to enhance:

    "{response_from_model}"

    Remember to be extremely emotional and supportive but not overly dramatic. Ensure the patient feels heard, understood, and supported. Always reference the patient as "you". Format the final response in HTML.
    """

    ingestion_string = f"""
    Patient Question: {patient_question}
    Response from Model: {response_from_model}
    """
    response = conversation.invoke(ingestion_string)["response"]
    return response


def send_email_confirmation(username, patient_id, email):
    try:
        token = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        db = createconnection()

        email_token = EmailToken(
            token=token, expires_at=expires_at, patient_id=patient_id
        )
        db.add(email_token)
        db.commit()

        connection_string = client.get_secret("CONNECTIONSTRING").value
        client = EmailClient.from_connection_string(connection_string)

        subject = "New User Registration Notification"
        base_url = os.getenv("BASE_URL")
        options = {
            "Accept": f"{base_url}?response=accept&patient_id={patient_id}&token={token}",
            "Reject": f"{base_url}?response=reject&patient_id={patient_id}&token={token}",
            "On Hold": f"{base_url}?response=on_hold&patient_id={patient_id}&token={token}",
            "Pending": f"{base_url}?response=pending&patient_id={patient_id}&token={token}",
        }

        # Read the HTML template from file
        with open(function_app.client.get_secret("STATICPATH").value, "r") as file:
            html_template = file.read()

        # Replace placeholders with actual values
        html_content = html_template.replace("[DR_NAME]", function_app.client.get_secret("DRNAME").value)
        html_content = html_content.replace("{username}", username)
        html_content = html_content.replace("{email}", email)
        html_content = html_content.replace(
            "{CURRENT_DATE}", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        html_content = html_content.replace("{ACCEPT_URL}", options["Accept"])
        html_content = html_content.replace("{REJECT_URL}", options["Reject"])
        html_content = html_content.replace("{ON_HOLD_URL}", options["On Hold"])
        html_content = html_content.replace("{PENDING_URL}", options["Pending"])

        message = {
            "senderAddress": function_app.client.get_secret("SENDEREMAILADD").value,
            "recipients": {
                "to": [{"address": function_app.client.get_secret("DRMAILID").value}],
            },
            "content": {
                "subject": subject,
                "html": html_content,
            },
        }
        poller = client.begin_send(message)
        result = poller.result()
        while result["status"] == "Running":
            time.sleep(5)
            result = poller.result()
        return result
    except Exception as e:
        print("Exception while sending email : ", e)
        return jsonCommonStatus("Internal server error", 500, False)
    finally:
        if db:
            db.close()


def send_contact_us_email(name: str, subject: str, user_email: str, message: str):

    client = EmailClient.from_connection_string(function_app.client.get_secret("CONNECTIONSTRING").value)

    html_content = f"""
        <html>
        <head>
            <style>
                .message {{
                    color: grey;
                }}
            </style>
        </head>
        <body>
            <h3>Hi {name},</h3>
            <p>We have received your request regarding {subject}.</p>
            <p class="message">{message}</p>
            <p>Our support team is looking into the issue and will get back to you shortly.</p>
            <p>Thanks,</br>
            Team HelloAlfred.ai</p>
        </body>
        </html>
        """
    email_message = {
        "senderAddress": function_app.client.get_secret("SENDEREMAILADD").value,
        "recipients": {
            "to": [{"address": function_app.client.get_secret("SUPPORTEMAILADDRES").value}],
            "cc": [{"address": user_email}],
        },
        "content": {
            "subject": subject,
            "html": html_content,
        },
    }
    try:
        poller = client.begin_send(email_message)
        result = poller.result()
        while result["status"] == "Running":
            time.sleep(5)
            result = poller.result()
        return result
    except Exception as e:
        print("Exception while sending email : ", e)
        return jsonCommonStatus("Internal server error", 500, False)


def send_account_expired_email(
    admin_name: str, admin_email: str, expirty_date: datetime
):
    client = EmailClient.from_connection_string(function_app.client.get_secret("CONNECTIONSTRING").value)
    message = f"The admin account for {admin_name}, Has been expired and was un-accable can you please either extend expiry okay take nessary action over the same"
    subject = f"Admin Account expirty for :- {admin_name}"
    html_content = f"""
        <html>
        <head>
            <style>
                .message {{
                    color: grey;
                }}
            </style>
        </head>
        <body>
            <h3>Hi {admin_name},</h3>
            <p>We have received your request regarding {subject}.</p>
            <p class="message">{message}</p>
            <p>Our support team is looking into the issue and will get back to you shortly.</p>
            <p>Thanks,</br>
            Team HelloAlfred.ai</p>
        </body>
        </html>
        """
    email_message = {
        "senderAddress": function_app.client.get_secret("SENDEREMAILADD").value,
        "recipients": {
            "to": [{"address": function_app.client.get_secret("SUPPORTEMAILADDRES").value}],
            "cc": [{"address": admin_email}],
        },
        "content": {
            "subject": subject,
            "html": html_content,
        },
    }
    try:
        poller = client.begin_send(email_message)
        result = poller.result()
        while result["status"] == "Running":
            time.sleep(5)
            result = poller.result()
        return result
    except Exception as e:
        print("Exception while sending email : ", e)
        return jsonCommonStatus("Internal server error", 500, False)


def send_contact_with_pdf(
    subject: str,
    user_email: str,
):

    client = EmailClient.from_connection_string(function_app.client.get_secret("CONNECTIONSTRING").value)

    html_content = """
        <html>
        <head>
            <style>
                .message {{
                    color: grey;
                }}
            </style>
        </head>
        <body>
            <p>Hey Alfred user</p>
            <p class="message">We appreciate you taking the time to review our Terms and Conditions. Your understanding
            of these terms is crucial to ensure a smooth experience with us</p>
            <p class="message">Thank you for choosing Helloalfred.ai.</br>
            <p class="message"><b>Terms and Conditions: </b><a href="https://helloalfred.ai/#/tnc">https://helloalfred.ai/tnc</a><p>
            Team HelloAlfred.ai</p>
        </body>
        </html>
        """
    email_message = {
        "senderAddress": function_app.client.get_secret("SENDEREMAILADD").value,
        "recipients": {
            "to": [{"address": function_app.client.get_secret("SUPPORTEMAILADDRES").value}],
            "cc": [{"address": user_email}],
        },
        "content": {
            "subject": subject,
            "html": html_content,
        },
    }
    try:
        poller = client.begin_send(email_message)
        result = poller.result()
        while result["status"] == "Running":
            time.sleep(5)
            result = poller.result()
        return result
    except Exception as e:
        print("Exception while sending email : ", e)
        return jsonCommonStatus("Internal server error", 500, False)


def send_account_expiration_extension_email(
    name: str, user_email: str, extension_date: str
):
    client = EmailClient.from_connection_string(function_app.client.get_secret("CONNECTIONSTRING").value)
    html_content = f"""
        <html>
        <head>
            <style>
                .message {{
                    color: grey;
                }}
            </style>
        </head>
        <body>
            <h3>Hi {name},</h3>
            <p>We wanted to let you know that your account expiration date has been extended.</p>
            <p>Your new expiration date is <strong>{extension_date}</strong>.</p>
            <p>If you have any questions or need further assistance, feel free to reach out to our support team.</p>
            <p>Thanks,</br>
            Team HelloAlfred.ai</p>
        </body>
        </html>
        """

    email_message = {
        "senderAddress": function_app.client.get_secret("SENDEREMAILADD").value,
        "recipients": {
            "to": [{"address": user_email}],  # Sending directly to the user
        },
        "content": {
            "subject": "Your Account Expiration Has Been Extended",
            "html": html_content,
        },
    }

    try:
        poller = client.begin_send(email_message)
        result = poller.result()
        while result["status"] == "Running":
            time.sleep(5)
            result = poller.result()
        return result
    except Exception as e:
        print("Exception while sending email:", e)
        return jsonCommonStatus("Internal server error", 500, False)


country_map = {
    "AF": 9,
    "AL": 9,
    "DZ": 9,
    "AS": 10,
    "AD": 6,
    "AO": 9,
    "AG": 10,
    "AR": 10,
    "AM": 8,
    "AU": 9,
    "AT": 10,
    "AZ": 9,
    "BS": 10,
    "BH": 8,
    "BD": 10,
    "BB": 10,
    "BY": 9,
    "BE": 9,
    "BZ": 7,
    "BJ": 8,
    "BT": 8,
    "BO": 8,
    "BA": 8,
    "BW": 7,
    "BR": 11,
    "BN": 7,
    "BG": 9,
    "BF": 8,
    "BI": 8,
    "KH": 9,
    "CM": 9,
    "CA": 10,
    "CV": 7,
    "CF": 8,
    "TD": 9,
    "CL": 9,
    "CN": 11,
    "CO": 10,
    "KM": 7,
    "CG": 9,
    "CR": 8,
    "HR": 9,
    "CU": 8,
    "CY": 8,
    "CZ": 9,
    "DK": 8,
    "DJ": 8,
    "DM": 10,
    "DO": 10,
    "EC": 9,
    "EG": 10,
    "SV": 8,
    "GQ": 9,
    "ER": 7,
    "EE": 7,
    "SZ": 7,
    "ET": 9,
    "FJ": 7,
    "FI": 9,
    "FR": 9,
    "GA": 7,
    "GM": 7,
    "GE": 9,
    "DE": 10,
    "GH": 9,
    "GR": 10,
    "GD": 10,
    "GT": 8,
    "GN": 9,
    "GW": 7,
    "GY": 7,
    "HT": 8,
    "HN": 8,
    "HU": 9,
    "IS": 7,
    "IN": 10,
    "ID": 10,
    "IR": 10,
    "IQ": 10,
    "IE": 9,
    "IL": 9,
    "IT": 10,
    "JM": 10,
    "JP": 10,
    "JO": 9,
    "KZ": 10,
    "KE": 9,
    "KI": 8,
    "KP": 10,
    "KR": 10,
    "KW": 8,
    "KG": 9,
    "LA": 9,
    "LV": 8,
    "LB": 8,
    "LS": 9,
    "LR": 7,
    "LY": 10,
    "LI": 7,
    "LT": 8,
    "LU": 9,
    "MG": 9,
    "MW": 9,
    "MY": 9,
    "MV": 7,
    "ML": 8,
    "MT": 8,
    "MH": 7,
    "MR": 7,
    "MU": 8,
    "MX": 10,
    "FM": 7,
    "MD": 8,
    "MC": 8,
    "MN": 8,
    "ME": 8,
    "MA": 9,
    "MZ": 9,
    "MM": 9,
    "NA": 9,
    "NR": 7,
    "NP": 10,
    "NL": 9,
    "NZ": 9,
    "NI": 8,
    "NE": 8,
    "NG": 10,
    "NO": 8,
    "OM": 8,
    "PK": 10,
    "PW": 7,
    "PA": 8,
    "PG": 7,
    "PY": 9,
    "PE": 9,
    "PH": 10,
    "PL": 9,
    "PT": 9,
    "QA": 8,
    "RO": 10,
    "RU": 10,
    "RW": 9,
    "KN": 10,
    "LC": 10,
    "VC": 10,
    "WS": 7,
    "SM": 9,
    "ST": 7,
    "SA": 9,
    "SN": 9,
    "RS": 9,
    "SC": 7,
    "SL": 8,
    "SG": 8,
    "SK": 9,
    "SI": 9,
    "SB": 7,
    "SO": 8,
    "ZA": 9,
    "SS": 9,
    "ES": 9,
    "LK": 9,
    "SD": 9,
    "SR": 7,
    "SE": 9,
    "CH": 9,
    "SY": 9,
    "TW": 9,
    "TJ": 9,
    "TZ": 9,
    "TH": 9,
    "TL": 7,
    "TG": 8,
    "TO": 7,
    "TT": 10,
    "TN": 8,
    "TR": 10,
    "TM": 8,
    "TV": 6,
    "UG": 9,
    "UA": 9,
    "AE": 9,
    "GB": 10,
    "US": 10,
    "UY": 9,
    "UZ": 9,
    "VU": 7,
    "VA": 8,
    "VE": 10,
    "VN": 9,
    "YE": 9,
    "ZM": 9,
    "ZW": 9,
}

dail_code = {
    "AF": 93,
    "AL": 355,
    "DZ": 213,
    "AS": 1684,
    "AD": 376,
    "AO": 244,
    "AG": 1268,
    "AR": 54,
    "AM": 374,
    "AU": 61,
    "AT": 43,
    "AZ": 994,
    "BS": 1242,
    "BH": 973,
    "BD": 880,
    "BB": 1246,
    "BY": 375,
    "BE": 32,
    "BZ": 501,
    "BJ": 229,
    "BT": 975,
    "BO": 591,
    "BA": 387,
    "BW": 267,
    "BR": 55,
    "BN": 673,
    "BG": 359,
    "BF": 226,
    "BI": 257,
    "KH": 855,
    "CM": 237,
    "CA": 1,
    "CV": 238,
    "CF": 236,
    "TD": 235,
    "CL": 56,
    "CN": 86,
    "CO": 57,
    "KM": 269,
    "CG": 242,
    "CR": 506,
    "HR": 385,
    "CU": 53,
    "CY": 357,
    "CZ": 420,
    "DK": 45,
    "DJ": 253,
    "DM": 1767,
    "DO": 1809,
    "EC": 593,
    "EG": 20,
    "SV": 503,
    "GQ": 240,
    "ER": 291,
    "EE": 372,
    "SZ": 268,
    "ET": 251,
    "FJ": 679,
    "FI": 358,
    "FR": 33,
    "GA": 241,
    "GM": 220,
    "GE": 995,
    "DE": 49,
    "GH": 233,
    "GR": 30,
    "GD": 1473,
    "GT": 502,
    "GN": 224,
    "GW": 245,
    "GY": 592,
    "HT": 509,
    "HN": 504,
    "HU": 36,
    "IS": 354,
    "IN": 91,
    "ID": 62,
    "IR": 98,
    "IQ": 964,
    "IE": 353,
    "IL": 972,
    "IT": 39,
    "JM": 1876,
    "JP": 81,
    "JO": 962,
    "KZ": 7,
    "KE": 254,
    "KI": 686,
    "KP": 850,
    "KR": 82,
    "KW": 965,
    "KG": 996,
    "LA": 856,
    "LV": 371,
    "LB": 961,
    "LS": 266,
    "LR": 231,
    "LY": 218,
    "LI": 423,
    "LT": 370,
    "LU": 352,
    "MG": 261,
    "MW": 265,
    "MY": 60,
    "MV": 960,
    "ML": 223,
    "MT": 356,
    "MH": 692,
    "MR": 222,
    "MU": 230,
    "MX": 52,
    "FM": 691,
    "MD": 373,
    "MC": 377,
    "MN": 976,
    "ME": 382,
    "MA": 212,
    "MZ": 258,
    "MM": 95,
    "NA": 264,
    "NR": 674,
    "NP": 977,
    "NL": 31,
    "NZ": 64,
    "NI": 505,
    "NE": 227,
    "NG": 234,
    "NO": 47,
    "OM": 968,
    "PK": 92,
    "PW": 680,
    "PA": 507,
    "PG": 675,
    "PY": 595,
    "PE": 51,
    "PH": 63,
    "PL": 48,
    "PT": 351,
    "QA": 974,
    "RO": 40,
    "RU": 7,
    "RW": 250,
    "KN": 1869,
    "LC": 1758,
    "VC": 1784,
    "WS": 685,
    "SM": 378,
    "ST": 239,
    "SA": 966,
    "SN": 221,
    "RS": 381,
    "SC": 248,
    "SL": 232,
    "SG": 65,
    "SK": 421,
    "SI": 386,
    "SB": 677,
    "SO": 252,
    "ZA": 27,
    "SS": 211,
    "ES": 34,
    "LK": 94,
    "SD": 249,
    "SR": 597,
    "SE": 46,
    "CH": 41,
    "SY": 963,
    "TW": 886,
    "TJ": 992,
    "TZ": 255,
    "TH": 66,
    "TL": 670,
    "TG": 228,
    "TO": 676,
    "TT": 1868,
    "TN": 216,
    "TR": 90,
    "TM": 993,
    "TV": 688,
    "UG": 256,
    "UA": 380,
    "AE": 971,
    "GB": 44,
    "US": 1,
    "UY": 598,
    "UZ": 998,
    "VU": 678,
    "VA": 379,
    "VE": 58,
    "VN": 84,
    "YE": 967,
    "ZM": 260,
    "ZW": 263,
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


def get_blob_sas_url(blob_name_without_extension):

    blob_service_client = BlobServiceClient(
        account_url=function_app.client.get_secret("BLOBSERVICECLIENTACNAME").value,
        credential=function_app.client.get_secret("ACCOUNTKEY").value,
    )
    container_client = blob_service_client.get_container_client(
        function_app.client.get_secret("IMAGECONTAINERNAME").value
    )
    for blob in container_client.list_blobs(
        name_starts_with=blob_name_without_extension
    ):
        img_containername = function_app.client.get_secret("IMAGECONTAINERNAME").value
        expiry_time = datetime.now() + timedelta(
            minutes=1
        )  # URL will be valid for 1 minute
        sas_url = generate_blob_sas_url(blob.name, expiry_time, img_containername)
        return sas_url
    return "NA"


def generate_unique_filename(dob, patient_id):

    part1, part2, part3 = patient_id.split("-")

    year, month, day = dob.split("-")

    unique_string = (
        f"{part1[::-1]}{day[::-1]}{part2[::-1]}{month[::-1]}{part3[::-1]}{year[::-1]}"
    )

    unique_filename = f"{unique_string}_profile_img"

    return unique_filename


def generate_blob_sas_url(blob_name, expiry_time, cont_name):
    sas_token = generate_blob_sas(
        account_name=function_app.client.get_secret("ACCOUNTNAME").value,
        container_name=cont_name,
        blob_name=blob_name,
        account_key=function_app.client.get_secret("ACCOUNTKEY").value,
        permission=BlobSasPermissions(read=True),
        expiry=expiry_time,
    )
    sas_url = f"{function_app.client.get_secret('BLOBSERVICECLIENTACNAME').value}/{cont_name}/{blob_name}?{sas_token}"
    return sas_url


def send_tempwd_email(
    name: str, subject: str, user_email: str, temporary_password: str
):

    client = EmailClient.from_connection_string(function_app.client.get_secret("CONNECTIONSTRING").value)

    html_content = (
        html_content
    ) = f"""
            <html>
            <head>
                <style>
                    .message {{
                        color: grey;
                    }}
                    .password {{
                        font-weight: bold;
                        color: #d9534f;
                    }}
                </style>
            </head>
            <body>
                <h3>Hi {name},</h3>
                <p>We have generated a temporary password for you to access your account.</p>
                <p class="message">Please use the following temporary password to log in:</p>
                <p class="password">{temporary_password}</p>
                <p>For security reasons, we recommend that you change your password immediately after logging in. You can do this by navigating to the "Change Password" section under your account settings.</p>
                <p>If you did not request this password reset, please contact our support team immediately.</p>
                <p>Thanks,</br>
                Team HelloAlfred.ai</p>
            </body>
            </html>
            """
    email_message = {
        "senderAddress": function_app.client.get_secret("SENDEREMAILADD").value,
        "recipients": {
            "to": [{"address": function_app.client.get_secret("SUPPORTEMAILADDRES").value}],
            "cc": [{"address": user_email}],
        },
        "content": {
            "subject": subject,
            "html": html_content,
        },
    }
    try:
        poller = client.begin_send(email_message)
        result = poller.result()
        while result["status"] == "Running":
            time.sleep(5)
            result = poller.result()
        return result
    except Exception as e:
        print("Exception while sending email : ", e)
        return jsonCommonStatus("Internal server error", 500, False)


def send_uic(recipient_name: str, uic: str, user_email: str):
    client = EmailClient.from_connection_string(function_app.client.get_secret("CONNECTIONSTRING").value)
    html_content = (
        html_content
    ) = f"""
        <!DOCTYPE html>
        <html xmlns="http://www.w3.org/1999/xhtml" lang="en">
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
            <title>HelloAlfred</title>

            <style>
            body {{
                margin: 0;
                padding: 0;
                font-family: Arial, sans-serif;
                font-size: 16px;
                color: #000000;
                background-color: #f6f6f6;
            }}

            .container {{
                width: 800px;
                margin: 0 auto;
            }}

            .container-inner {{
                width: 700px;
                margin: 0 auto;
                border: 1px solid #f6f6f6;
                background: url("https://storageaccountforpublic.blob.core.windows.net/publiccontainer/alfredemailtemplate/watermark.png")
                no-repeat center center #ffffff;
                background-size: 54%;
            }}

            .row {{
                content: "";
                display: table;
                clear: both;
                width: 100%;
            }}

            .col-lft {{
                width: calc(40% - 20px);
                float: left;
                padding-left: 20px;
            }}

            .col-rgt {{
                width: calc(60% - 20px);
                float: left;
                padding-right: 20px;
            }}

            .text-right {{
                text-align: right;
            }}

            .text-center {{
                text-align: center;
            }}

            .content-inner {{
                padding: 0 50px;
            }}

            p {{
                margin: 0px;
                margin-bottom: 10px;
                line-height: 1.5;
            }}

            h1 {{
                font-size: 32px;
                line-height: 1.16;
                font-weight: 700;
                margin: 0;
                color: #000000;
            }}

            h2 {{
                font-size: 23px;
                line-height: normal;
                color: #000000;
            }}

            h4 {{
                font-size: 16px;
                line-height: normal;
                color: #000000;
            }}

            h6 {{
                font-size: 16px;
                font-weight: 600;
            }}
            .bluetext {{
                color: #04c1d6;
                font-weight: 800;
            }}

            .footer {{
                padding: 15px 0;
                font-size: 13px;
                background-color: #04c1d6;
                color: #ffffff;
            }}

            .social span {{
                margin-right: 15px;
                display: inline-flex;
                align-items: center;
            }}

            .social span:last-child {{
                margin-right: 0;
            }}

            .social span img{{
                padding-right: 5px;
            }}

            a {{
                color: #696c73;
                text-decoration: none;
            }}

            a:hover {{
                color: #000000;
            }}
            </style>
        </head>
        <body>
            <div class="container">
            <div class="container-inner">
                <div style="padding: 50px">
                <img
                    src="https://storageaccountforpublic.blob.core.windows.net/publiccontainer/alfredemailtemplate/alfredlogo.svg"
                    alt=""
                    width="120"
                />
                </div>
                <div class="content-inner">
                <div style="margin-bottom: 50px">
                    <h1>Your Unique Identification Code (UIC)</h1>
                </div>
                <h4>Dear { recipient_name },</h4>
                <p>We hope this message finds you well.</p>
                <p>
                    We are writing to inform you that your Unique ldentification Code
                    (UIC) has been successfully generated. Please find your UIC below:
                </p>
                <h1 style="margin-top: 50px; margin-bottom: 30px; font-size: 36px">
                    Your UIC: <strong class="bluetext">{ uic }</strong>
                </h1>
                <p style="margin-bottom: 30px">
                    This code is unique to you and should be kept confidential. Do not
                    share your UIC with anyone else to ensure your account's security.
                    If you have any questions or require further assistance, please do
                    not hesitate to reach out to our support team at (
                    support@helloalfred.ai ).
                </p>
                <p>Thank you for your attention.</p>
                <h6 style="margin-top: 60px; margin-bottom: 10px">Best regards</h6>
                <p style="margin-bottom: 80px">Alfred Inc.</p>
                </div>
                <div class="row footer social">
                <div class="col-lft">
                    <span
                    ><img
                        src="https://storageaccountforpublic.blob.core.windows.net/publiccontainer/alfredemailtemplate/website.png"
                        alt=""
                        height="15"
                    />https://dev.helloalfred.ai</span
                    >
                </div>
                <div class="col-rgt text-right">
                    <span
                    ><img
                        src="https://storageaccountforpublic.blob.core.windows.net/publiccontainer/alfredemailtemplate/phone.png"
                        alt=""
                        height="15"
                    />+1 971-335-2875</span
                    >
                    <span
                    ><img
                        src="https://storageaccountforpublic.blob.core.windows.net/publiccontainer/alfredemailtemplate/email.png"
                        alt=""
                        height="15"
                    />support@helloalfred.ai</span
                    >
                </div>
                </div>
            </div>
            </div>
        </body>
        </html>
    """
    email_message = {
        "senderAddress": function_app.client.get_secret("SENDEREMAILADD").value,
        "recipients": {
            "to": [{"address": function_app.client.get_secret("SUPPORTEMAILADDRES").value}],
            "cc": [{"address": user_email}],
        },
        "content": {
            "subject": "Your Unique Identification Code (UIC) For HelloAlfred.ai",
            "html": html_content,
        },
    }
    try:
        poller = client.begin_send(email_message)
        result = poller.result()
        while result["status"] == "Running":
            time.sleep(5)
            result = poller.result()
        return result
    except Exception as e:
        print("Exception while sending email : ", e)
        return jsonCommonStatus("Internal server error", 500, False)


def generate_uic_code():
    lowercase = random.choice(string.ascii_lowercase)
    uppercase = random.choice(string.ascii_uppercase)
    digit = random.choice(string.digits)
    special_character = random.choice(string.punctuation)

    remaining_length = 2
    remaining_characters = [lowercase, uppercase, digit, special_character]
    all_characters = string.ascii_letters + string.digits + string.punctuation
    remaining_characters += random.choices(all_characters, k=remaining_length)

    random.shuffle(remaining_characters)

    unique_string = "".join(remaining_characters)

    return unique_string


def generate_temp_password():
    generate_user_id = patient_id_generator()
    timestamp = pd.Timestamp("now")
    hashed_password = hashlib.sha256(
        f"{generate_user_id}{timestamp}".encode()
    ).hexdigest()
    dynamic_password = hashed_password[:8]
    tp, main_ = Encode_password(dynamic_password)
    salt, password = main_[0], main_[1]
    return salt, password, dynamic_password
