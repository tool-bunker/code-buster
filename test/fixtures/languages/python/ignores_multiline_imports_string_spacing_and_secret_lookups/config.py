from app.errors import (
    InvalidUsage,
    UnauthorizedRequest,
)


Model = db.Model
if TYPE_CHECKING:
    from app.models import Household
mcp_enabled = os.getenv("ENABLED", "False").lower() == "true"
database = URL.create(
    username=get_secret("DB_USER"),
    password=get_secret("DB_PASSWORD"),
)
text = open(
    "data.txt", "r", encoding="utf-8"
)
binary = open("image.bin", "wb")
image = Image.open("image.png")
