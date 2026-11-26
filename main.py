import os

from dotenv import load_dotenv

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from database import engine, Base, get_db
from models import User
from security import hash_password, verify_password


# Environment Configuration
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise ValueError("SECRET_KEY is missing from .env")


# Database Configuration
Base.metadata.create_all(bind=engine)


# FastAPI Application
app = FastAPI(title="StudentPortal")


# Session Configuration
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=False
)


# Static Files
app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


# Templates
templates = Jinja2Templates(directory="templates")


# HOME
@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={"request": request}
    )


# REGISTER PAGE
@app.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"request": request}
    )


# REGISTER
@app.post("/register")
async def register(
    request: Request,
    db: Session = Depends(get_db)
):
    form = await request.form()

    name = str(form.get("name", "")).strip()
    email = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))

    if not name or not email or not password:
        error = "All fields are required."

    elif "@" not in email or "." not in email.split("@")[-1]:
        error = "Please enter a valid email address."

    elif len(password) < 8:
        error = "Password must contain at least 8 characters."

    else:
        existing_user = db.query(User).filter(
            User.email == email
        ).first()

        if existing_user:
            error = "This email address is already registered."
        else:
            new_user = User(
                name=name,
                email=email,
                password_hash=hash_password(password),
                role="student"
            )

            db.add(new_user)
            db.commit()

            return RedirectResponse(
                url="/login",
                status_code=303
            )

    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={
            "request": request,
            "error": error
        },
        status_code=400
    )


# LOGIN PAGE
@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"request": request}
    )


# LOGIN
@app.post("/login")
async def login(
    request: Request,
    db: Session = Depends(get_db)
):
    form = await request.form()

    email = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))

    user = db.query(User).filter(
        User.email == email
    ).first()

    if not user or not verify_password(
        password,
        user.password_hash
    ):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "request": request,
                "error": "Invalid email or password."
            },
            status_code=401
        )

    request.session.clear()
    request.session["user_id"] = user.id

    return RedirectResponse(
        url="/dashboard",
        status_code=303
    )


# DASHBOARD
@app.get("/dashboard")
def dashboard(
    request: Request,
    db: Session = Depends(get_db)
):
    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", status_code=303)

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "user": user
        }
    )


# ADMIN
@app.get("/admin")
def admin_page(
    request: Request,
    db: Session = Depends(get_db)
):
    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", status_code=303)

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Access denied. Admin permission required."
        )

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "request": request,
            "user": user
        }
    )


# LOGOUT
@app.get("/logout")
def logout(request: Request):
    request.session.clear()

    return RedirectResponse(
        url="/",
        status_code=303
    )