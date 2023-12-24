from typing import Optional, List
from sqlalchemy import String, Boolean, ForeignKey
import sqlalchemy.orm as orm


class Base(orm.DeclarativeBase):
    pass


class Task(Base):
    __tablename__ = "task"
    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    list_id: orm.Mapped[int] = orm.mapped_column(ForeignKey("task_list.id"))
    name: orm.Mapped[str] = orm.mapped_column(String(30))
    description: orm.Mapped[Optional[str]]
    is_done: orm.Mapped[Optional[bool]] = orm.mapped_column(Boolean)

    def __repr__(self) -> str:
        return f"Task(id={self.id!r}, name={self.name!r}, description={self.description!r}, done={self.is_done!r})"


class ListOfTasks(Base):
    __tablename__ = "task_list"
    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    name: orm.Mapped[str] = orm.mapped_column(String(30))
    tasks: orm.Mapped[Optional[List["Task"]]] = orm.relationship()
    user_id: orm.Mapped[int] = orm.mapped_column(ForeignKey("user.id"))


class User(Base):
    __tablename__ = "user"
    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    nickname: orm.Mapped[str] = orm.mapped_column(String(30), unique=True)
    password: orm.Mapped[str] = orm.mapped_column(String(100))
    is_admin: orm.Mapped[bool] = orm.mapped_column(Boolean, default=False)
    list_of_tasks: orm.Mapped[Optional[List["ListOfTasks"]]] = orm.relationship()
