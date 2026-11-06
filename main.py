from fastapi import FastAPI


app = FastAPI()


@app.get("/")
def read_root():
    return {"hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id:int, q:int | None = None):
    return {"item": item_id, "q": q}

