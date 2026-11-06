from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from services import (
    AuthenticationFactory,
    ForbiddenRuleError,
    UnauthorizedError,
)

app = FastAPI(title="Lift ERP")

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")
