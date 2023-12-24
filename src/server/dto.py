import dataclasses
from src.db.models import ListOfTasks as dbListOfTasks


@dataclasses.dataclass
class User:
    id: int
