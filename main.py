from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


app = FastAPI()


app.mount("/static",StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

def format_currency(value: float) -> str:
    return f"R$ {value:,.2f}".replace(",", "v").replace(".", ",").replace("v", ".")
templates.env.globals["format_currency"] = format_currency

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    context = {
        "request": request,
        "title": "Página inicial",
        "users": [
            { "id": 1, "name": "janja", "rule": "Admin" },
            { "id": 1, "name": "Luis inacio", "rule": "Dev"},
        ],
    }
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context=context
    )
