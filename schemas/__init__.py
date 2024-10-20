from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    Boolean,
    VARBINARY,
    Date,
    JSON,
    Text,
    Float,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, Any
from sqlalchemy.orm import relationship
import re
from datetime import date

# Define SQLAlchemy model
Base = declarative_base()


class HealthRecord(Base):
    __tablename__ = "health_details"
    health_id = Column(Integer, primary_key=True, autoincrement=True)
    patient_id = Column(String(30))
    weight = Column(String(30))
    height = Column(String(30))
    bloodp = Column(String(30))
    pulse = Column(String(30))
    ctimestamp = Column(DateTime)
    tdate = Column(Date)


class Symptom(Base):
    __tablename__ = "symptoms"
    symptoms_id = Column(Integer, primary_key=True, autoincrement=True)
    patient_id = Column(String(30))
    tdate = Column(Date)
    infirmity = Column(JSON)
    nsynacpe = Column(JSON)
    tirednessafterwards = Column(JSON)
    breathnessda = Column(JSON)
    breathnessea = Column(JSON)
    dizziness = Column(JSON)
    col_swet = Column(JSON)
    chest_pain = Column(JSON)
    pressurechest = Column(JSON)
    worry = Column(JSON)
    weakness = Column(JSON)
    ctimestamp = Column(DateTime)
    health_id = Column(Integer)
    p_tiredness = Column(JSON)
    syncope = Column(JSON)


class UserData(Base):
    __tablename__ = "user_data"
    patient_id = Column(String(50), primary_key=True)
    password = Column(String(50))
    salt = Column(VARBINARY(100))


class DoctorCreds(Base):
    __tablename__ = "doctorcredentials"
    cred_id = Column(Integer, autoincrement=True, primary_key=True)
    doctor_details_id = Column(
        String(60), ForeignKey("doctor_details.doctor_details_id", ondelete="CASCADE")
    )
    password = Column(String(100))
    salt = Column(VARBINARY(100))
    doctor_details = relationship("doctorDetails")


class PatientDetails(Base):
    __tablename__ = "patient_details"
    patient_id = Column(String(50), primary_key=True)
    username = Column(String(50))
    email = Column(String(50), unique=True)
    dob = Column(DateTime, nullable=True)
    gender = Column(String(2))
    mobile = Column(String(10), unique=True)
    rtype = Column(String(20))
    education = Column(String(50))
    ssn = Column(String(20), unique=True)
    insuranceurl = Column(String(100))
    activestat = Column(Boolean, default=False, nullable=False)
    weight = Column(String(50))
    height = Column(String(50))
    feet = Column(String(50))
    inch = Column(String(50))
    age = Column(String(50))
    history_progress = Column(JSON)
    nationality = Column(String(50))
    bloodtype = Column(String(15))
    subscription = Column(String(50))
    insurance_provider = Column(String(50))
    insurance_policy_no = Column(String(100))
    updated_date = Column(DateTime)
    user_status = Column(Integer, default=0)
    remark = Column(Text)
    updated_by = Column(String(100), default=None)
    created_date = Column(Date)
    role_id = Column(Integer, ForeignKey("role.role_id"), default=3)


class history_question(Base):
    __tablename__ = "question_table"
    question_key = Column(String(50), primary_key=True, nullable=False)
    ans_category = Column(Text)
    description = Column(Text)
    main_type = Column(String(50))
    type_ = Column(String(50))
    yes = Column(String(50))
    no = Column(String(50))
    options = Column(JSON)


class CreationUserschema(BaseModel):
    email: str
    dob: str
    gender: str
    mobile: Optional[str] = None
    rtype: Optional[str] = None
    education: Optional[str] = None
    ssn: Optional[str] = None
    insuranceurl: Optional[str] = None
    password: str
    username: str
    nationality: Optional[str] = None


class Commonresponse(BaseModel):
    statuscode: int
    status: bool
    message: str


class Commonresponsedata(BaseModel):
    statuscode: int
    status: bool
    message: str
    data: dict


class ChatRequest(BaseModel):
    alfred: str
    user: str
    questionno: int


class ChatResponse(BaseModel):
    status_code: str
    message: str
    data: dict


class Message(BaseModel):
    # patient_id: str
    message: str


class introstate(Base):
    __tablename__ = "introstatus"
    patient_id = Column(
        String(50),
        ForeignKey("user_data.patient_id", ondelete="CASCADE"),
        primary_key=True,
    )
    progress = Column(JSON)
    cdate = Column(Date)


class preferanceSchema(Base):
    __tablename__ = "question_preference"
    preference_id = Column(Integer, primary_key=True, autoincrement=True)
    message = Column(Text)
    patient_id = Column(
        String(50), ForeignKey("patient_details.patient_id", ondelete="CASCADE")
    )
    preference = Column(Boolean)


class preferanceSchemaAdmin(Base):
    __tablename__ = "question_preference_admin"
    preference_id = Column(Integer, primary_key=True, autoincrement=True)
    message = Column(Text)
    user_id = Column(String(50), ForeignKey("admin.user_id", ondelete="CASCADE"))
    preference = Column(Boolean)


class request_preferanceSchema(BaseModel):
    message: str = Field(
        min_length=2, description="Message should have at least 2 characters"
    )
    preference: bool
    patient_id: Optional[str] = None


class JsonCommonStatus(BaseModel):
    statuscode: int
    status: bool
    message: str
    data: Optional[any] = None

    class Config:
        arbitrary_types_allowed = True

    def custom_dict(self):
        return {
            key: value for key, value in self.model_dump().items() if value is not None
        }


class JsonCommonStatus_without_data(BaseModel):
    statuscode: int
    status: bool
    message: str


class update_profile(BaseModel):
    email: Optional[str] = None
    dob: Optional[str] = None
    gender: Optional[str] = None
    mobile: Optional[str] = None
    rtype: Optional[str] = None
    education: Optional[str] = None
    ssn: Optional[str] = None
    insuranceurl: Optional[str] = None
    username: Optional[str] = None
    feet: Optional[str] = None
    inch: Optional[str] = None
    height: Optional[str] = None
    age: Optional[str] = None
    nationality: Optional[str] = None
    bloodtype: Optional[str] = None
    weight: Optional[str] = None

    class Config:
        from_attributes = True


class loginschema(BaseModel):
    username: str
    password: str
    session_id: str


class healthdatailsschema(BaseModel):
    weight: Optional[str] = None
    height: Optional[str] = None
    tdate: Optional[str] = None
    pulse: str
    bloodp: str


class symptoms_data(BaseModel):
    severity: str
    frequency: str
    quality_of_life: str


class addsymptomsschema(BaseModel):
    infirmity: Optional[symptoms_data] = None
    nsynacpe: Optional[symptoms_data] = None
    tirednessafterwards: Optional[symptoms_data] = None
    breathnessda: Optional[symptoms_data] = None
    breathnessea: Optional[symptoms_data] = None
    dizziness: Optional[symptoms_data] = None
    col_swet: Optional[symptoms_data] = None
    chest_pain: Optional[symptoms_data] = None
    pressurechest: Optional[symptoms_data] = None
    worry: Optional[symptoms_data] = None
    weakness: Optional[symptoms_data] = None
    syncope: Optional[symptoms_data] = None
    p_tiredness: Optional[symptoms_data] = None


class healthdetailsui(BaseModel):
    health_hub: Optional[int] = None
    expert_monitoring: Optional[int] = None
    list_your_symptoms: Optional[int] = None
    lifestyle_goals: Optional[int] = None
    optimal_risk_managemment: Optional[int] = None


class socialauth(BaseModel):
    email: str
    username: str
    session_id: str


class history_chatbot_answers(Base):
    __tablename__ = "history_chatbot_answers"
    answer_id = Column(Integer, autoincrement=True, primary_key=True)
    patient_id = Column(
        String(50), ForeignKey("patient_details.patient_id", ondelete="CASCADE")
    )
    question_id = Column(Text)
    answer = Column(Text)
    ctimestamp = Column(DateTime)


class history_answer_schemas(BaseModel):
    question_id: str = Field(min_length=2)
    answer: str = Field(min_length=1)


class history_command(BaseModel):
    question: str = Field(min_length=1)
    comment: str = Field(min_length=1)


class generate_otp(BaseModel):
    email: Optional[EmailStr] = Field(
        None, description="The email address to send the OTP to"
    )
    mobile: Optional[str] = None
    username: Optional[str] = None


class forgetpwd(BaseModel):
    email: EmailStr = Field(..., description="The email address to reset password")
    password: str = Field(min_length=8)


class verify_otp(BaseModel):
    email: EmailStr = Field(..., description="The email address used to verifiy")
    otp: str = Field(min_length=4)


class chat_bot_iteration(BaseModel):
    question: str
    user_message: str
    question_key: str
    main_type: str
    ans_categ: str


class history_schema(BaseModel):
    id: str
    message: str


class profile_keys(BaseModel):
    history_chat: Optional[bool] = False
    history_trans: Optional[bool] = False
    profile: Optional[bool] = False


class changePwd(BaseModel):
    old_password: str
    new_password: str


class ProfileCompletionRequest(BaseModel):
    history_chat: Optional[bool] = False
    history_trans: Optional[bool] = False
    behavioural_chat: Optional[bool] = False
    profile: Optional[bool] = False


class history_bypass(Base):
    __tablename__ = "history_chat_bypass"
    bypass_id = Column(Integer, primary_key=True)
    patient_id = Column(String(50))
    question_key = Column(Text)
    count = Column(Integer)
    answer = Column(JSON)


class healthDetailsDateRange(BaseModel):
    start_date: Optional[str] = None
    end_date: Optional[str] = None


class doctorCredentials(Base):
    __tablename__ = "doctorCredentials"
    cred_id = Column(Integer, primary_key=True, autoincrement=True)
    doctor_details_id = Column(
        String(60), ForeignKey("doctor_details.doctor_details_id", ondelete="CASCADE")
    )
    password = Column(String(100))
    salt = Column(VARBINARY(100))
    doctor_details = relationship("doctorDetails")


class doctorDetails(Base):
    __tablename__ = "doctor_details"
    dd_id = Column(Integer, primary_key=True, autoincrement=True)
    doctor_details_id = Column(String(60), unique=True)
    fullName = Column(String(50))
    email = Column(String(80), unique=True, nullable=False)
    mobile = Column(String(15), unique=True, nullable=False)
    highest_grade = Column(String(60))
    state_of_practice = Column(String(80))
    national_provider_id = Column(String(80))
    medical_license_number = Column(String(80))
    country = Column(String(50))
    state = Column(String(50))
    name_of_hospital = Column(String(50))
    referral_code = Column(String(60))
    role_id = Column(Integer, ForeignKey("role.role_id"), default=2)
    # Relationship between role table
    role = relationship("Role")
    city = Column(String(100))


class Role(Base):
    __tablename__ = "role"
    role_id = Column(Integer, primary_key=True)
    role_name = Column(String(50), nullable=False)


class reqCreateDoctorSchemas(BaseModel):
    username: str
    email: EmailStr
    mobile: str
    highest_grade: str
    state_of_practice: str
    national_provider_id: str
    medical_license_number: str
    country: str
    state: str
    name_of_hospital: str
    referral_code: Optional[str] = "NA"
    password: str
    city: str

    @validator("password")
    def validate_password(cls, v):
        regex_pattern = (
            r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
        )
        if not re.match(regex_pattern, v):
            raise ValueError(
                "Password must contain at least one uppercase letter, one lowercase letter, one digit, one special character, and be at least 8 characters long."
            )

        return v

    class Config:
        from_attributes = True


class EmailToken(Base):
    __tablename__ = "email_token"
    token_id = Column(Integer, autoincrement=True, primary_key=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    token = Column(String(50), nullable=False)
    patient_id = Column(
        String(50), ForeignKey("patient_details.patient_id", ondelete="CASCADE")
    )


class getAssetName(BaseModel):
    filename: str


class APILog(Base):
    __tablename__ = "api_logs"
    log_id = Column(Integer, primary_key=True, index=True)
    user_identifier = Column(String)
    request_url = Column(String, index=True)
    method = Column(String, index=True)
    client_ip = Column(String, index=True)
    status_code = Column(Integer)
    entry_time = Column(DateTime)
    exit_time = Column(DateTime)
    duration = Column(Float)


class HealthHubContent(Base):
    __tablename__ = "healt_hub_content"
    rec_id = Column(Integer, primary_key=True, autoincrement=True)
    week = Column(Integer, unique=True, nullable=False)
    week_title = Column(String(300))
    week_desc = Column(Text)
    content = Column(JSON)

    __table_args__ = (UniqueConstraint("week", name="uq_week"),)


class EmailSchema(BaseModel):
    name: str
    subject: str
    user_email: EmailStr
    message: str


class ExpertMonitoring(Base):
    __tablename__ = "patient_symp"
    tdate = Column(Date)
    patient_id = Column(String(50))
    weight = Column(String(30))
    height = Column(String(30))
    bloodp = Column(String(30))
    pulse = Column(String(30))
    ctimestamp = Column(DateTime)
    vitals = Column(String(15))
    symp_id = Column(Integer, autoincrement=True, primary_key=True)


class HealthHubProgress(Base):
    __tablename__ = "health_hub_progress"
    progress_id = Column(Integer, primary_key=True, autoincrement=True)
    patient_id = Column(
        String(50), ForeignKey("patient_details.patient_id", ondelete="CASCADE")
    )
    week_data = Column(JSON)
    patient = relationship("PatientDetails")


class UpdateHealthHubStatus(BaseModel):
    skip_week: Optional[int] = None
    update_complete_week: Optional[int] = None


class EmailWithPdf(BaseModel):
    email: EmailStr


class AdminUser(BaseModel):
    name: str
    email: EmailStr
    mobile: str
    designation: str
    expiry_date: date
    Unique_identification_code: str
    nationality: str
    super_admin_email: str

    @validator("Unique_identification_code")
    def validate_unique_identification_code(cls, v):
        if len(v) != 6:
            raise ValueError(
                "UIC should consist of 6 characters. Please enter a valid code"
            )
        return v


class UpdateAdminUser(BaseModel):
    user_id: str
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    mobile: Optional[str] = None
    designation: Optional[str] = None
    expiry_date: Optional[date] = None
    nationality: Optional[str] = None
    Unique_identification_code: str


class UpdateAdminDetails(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    mobile: Optional[str] = None
    designation: Optional[str] = None
    nationality: Optional[str] = None


class Admin(Base):
    __tablename__ = "admin"
    admin_id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(50), nullable=False)
    mobile = Column(String(50), nullable=False)
    designation = Column(String(50), nullable=False)
    assigned_date = Column(DateTime, nullable=True)
    expiry_date = Column(DateTime, nullable=True)
    assigned_by = Column(String(50), nullable=False)
    user_id = Column(String(100), nullable=False, unique=True)
    role_id = Column(Integer, ForeignKey("role.role_id"), default=1)
    name = Column(String(100), nullable=False)
    Unique_identification_code = Column(String(50), default=None)
    credentials = relationship("AdminCreds", backref="admin", uselist=False)
    nationality = Column(String(50), default=None)
    active_state = Column(Boolean, default=1)


class AdminCreds(Base):
    __tablename__ = "admin_creds"

    admin_cred_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        String(100),
        ForeignKey("admin.user_id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    password = Column(String(100), nullable=False)
    salt = Column(VARBINARY(100), nullable=False)
    pwdchanged = Column(Boolean, default=0)
    tempwddate = Column(DateTime, nullable=True)


class SuperAdminUser(BaseModel):
    name: str
    email: EmailStr
    mobile: str
    designation: str
    expiry_date: Optional[date] = None
    Unique_identification_code: str
    role_id: int
    password: str
    nationality: str


class ChangeAdminPassword(BaseModel):
    temporary_password: str
    new_password: str


class ChangeUserStatus(BaseModel):
    patient_id: str
    status: int
    remark: Optional[str] = None


class Uic_generator(BaseModel):
    user_name: str
    user_email: str
    user_phn: str
    user_desg: str


class UIC_Creds(Base):
    __tablename__ = "superadmin_uic_creds"

    temp_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False, unique=True)
    phone_number = Column(String(15), nullable=False, unique=True)
    designation = Column(String(50), nullable=False)
    UIC = Column(String(50), nullable=False, unique=True)
    salt = Column(String(64), nullable=False)


class EducationHistory(Base):
    __tablename__ = "patient_records"

    record_id = Column(Integer, primary_key=True, autoincrement=True)
    patient_id = Column(String(50), nullable=True)
    record_details = Column(JSON, nullable=True)
    cdate = Column(Date, nullable=False)
    session_id = Column(String(50), nullable=True)


class QuestionPreferenceComment(Base):
    __tablename__ = "question_preference_comment"

    comment_id = Column(Integer, primary_key=True, autoincrement=True)
    patient_id = Column(String(50), nullable=True)
    message = Column(Text, nullable=True)
    comment = Column(Text, nullable=True)
    ctimestap = Column(DateTime, nullable=False)


class QuestionPreferenceCommentAdmin(Base):
    __tablename__ = "question_preference_comment_admin"

    comment_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), nullable=True)
    message = Column(Text, nullable=True)
    comment = Column(Text, nullable=True)
    ctimestamp = Column(DateTime, nullable=False)


class EducationHistory_admin(Base):
    __tablename__ = "education_bot_conversation_dump_admin"

    record_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), nullable=True)
    conversation_history = Column(JSON, nullable=True)
    cdate = Column(Date, nullable=False)
    session_id = Column(String(50), nullable=True)
    reference = Column(JSON, nullable=False)


class WeekDetails(Base):
    __tablename__ = "week_details"

    week_id = Column(Integer, primary_key=True, autoincrement=True)
    week = Column(Integer)
    week_title = Column(Text, nullable=False)
    week_objective = Column(Text)
    week_activity = Column(Text)
    week_desc = Column(Text)
    week_explanation = Column(Text)
    content = Column(JSON)
